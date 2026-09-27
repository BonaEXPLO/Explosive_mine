// internal/p2p/peer.go
package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"explosive/internal/address"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"log"
	"math/rand"
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PeerID is a string identifier for a peer (could be hex/base58).
type PeerID string

// Peer represents a remote peer connection, its outgoing queue, lifecycle, and blockchain state.
type Peer struct {
	// targetPeerID is the permanent remote identity known before
	// establishing a transport session.
	//
	// It is used by relay transport, which routes by PeerID rather
	// than by IP address or TCP port.
	targetPeerID PeerID

	id   PeerID
	addr string

	// reconnectAddr is the durable network locator used to create
	// a new session after the current TCP session disappears.
	//
	// addr may contain a temporary TCP source port for inbound
	// connections. reconnectAddr must never depend on that ephemeral
	// session port.
	reconnectAddr string

	// underlying network connection (may be nil until connected)
	conn net.Conn

	// back reference to owning node (same package)
	node *Node

	// outgoing send queue (encoded envelopes)
	sendQ chan []byte

	// cancellation and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// metadata protected by mu
	mu        sync.RWMutex
	connected bool
	lastSeen  time.Time

	// ---- PING / PONG LIVENESS ----
	//
	// These fields describe the current network session only.
	// They are NOT part of peer reputation.
	//
	// A peer can remain offline for days/weeks/months without punishment.
	pingMu       sync.Mutex
	pendingPings map[int64]time.Time
	lastPong     time.Time
	pingSequence uint64

	// anti-abuse / scoring
	score    int
	banUntil time.Time
	errCount int

	// blockchain info
	LatestHeight uint64

	// Verified identity after handshake (V3)
	verifiedMinerID string // Verified miner address (empty if not verified)
	verifiedPubKey  []byte // Verified Ed25519 public key
	verifiedMiner   bool   // True if peer proved knowledge of sacred words via V3 signature

	// ---- HANDSHAKE STATE (FIX CRITICAL BUGS) ----
	handshakeDone bool          // true once handshake fully validated
	handshakeOnce sync.Once     // guarantees single handshake execution
	handshakeCh   chan struct{} // closed when handshake completes

	// ---- NAT CANDIDATE EXCHANGE ----
	//
	// Remote NAT candidates are public network locators.
	// They are never treated as peer identity.
	//
	// Candidate exchange is performed only after the authenticated
	// EXPLOSIVE handshake has completed.
	candidateExchangeOnce sync.Once
	candidateExchangeMu   sync.RWMutex
	remoteNATCandidates   []NATCandidate
	seenCandidateNonces   map[uint64]time.Time

	nat4Mu         sync.Mutex
	seenNAT4Nonces map[uint64]time.Time
}

func init() {
	// seed math/rand for jitter
	rand.Seed(time.Now().UnixNano())
}

func NewPeer(id PeerID, addr string, node *Node) *Peer {
	ctx, cancel := context.WithCancel(context.Background())

	qsize := 64
	if node != nil && node.config.SendQueueSize > 0 {
		qsize = node.config.SendQueueSize
	}

	// The network address is only a temporary locator.
	// A peer's permanent identity is established only after
	// the EXPLOSIVE handshake verifies the remote wallet identity.
	return &Peer{
		id:                  id,
		addr:                addr,
		reconnectAddr:       addr,
		node:                node,
		sendQ:               make(chan []byte, qsize),
		ctx:                 ctx,
		cancel:              cancel,
		handshakeCh:         make(chan struct{}),
		pendingPings:        make(map[int64]time.Time),
		seenCandidateNonces: make(map[uint64]time.Time),
	}
}

// ID returns the peer identifier.
func (p *Peer) ID() PeerID { return p.id }

// Addr returns the remote address string.
func (p *Peer) Addr() string { return p.addr }

// IsConnected reports whether connection is active.
func (p *Peer) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected && p.conn != nil
}

// IsBanned reports whether peer is currently banned.
func (p *Peer) IsBanned() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return time.Now().Before(p.banUntil)
}

// Penalize adjusts score and optionally bans the peer for banDur.
func (p *Peer) Penalize(delta int, banDur time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldScore := p.score
	p.score -= delta
	p.errCount++

	if banDur > 0 {
		p.banUntil = time.Now().Add(banDur)
	}

	// Récupère le fichier + ligne de l'appelant
	pc, file, line, ok := runtime.Caller(1)

	caller := "unknown"
	funcName := "unknown"

	if ok {
		caller = file + ":" + strconv.Itoa(line)

		if fn := runtime.FuncForPC(pc); fn != nil {
			funcName = fn.Name()
		}
	}

	log.Printf(
		"[PENALIZE] peer=%s delta=%d score=%d->%d errCount=%d ban=%v caller=%s func=%s\nSTACK:\n%s",
		p.addr,
		delta,
		oldScore,
		p.score,
		p.errCount,
		banDur,
		caller,
		funcName,
		debug.Stack(),
	)
}

func (p *Peer) backoffDial(ctx context.Context) (net.Conn, error) {
	if p == nil {
		return nil, errors.New("nil peer")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Mobile networks may remain unavailable for days, weeks,
	// or months. Reconnection therefore has no artificial maximum
	// number of attempts and no fixed maximum backoff period.
	//
	// Offline time is never treated as peer misbehavior.
	const baseBackoff = 5 * time.Second

	var attempt uint64

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Respect the configured TCP dial timeout.
		dialTimeout := 10 * time.Second

		if p.node != nil && p.node.config.DialTimeout > 0 {
			dialTimeout = p.node.config.DialTimeout
		}

		d := net.Dialer{
			Timeout: dialTimeout,
		}

		conn, err := d.DialContext(
			ctx,
			"tcp",
			p.addr,
		)

		if err == nil {
			return conn, nil
		}

		attempt++

		// ==========================================================
		// EXPONENTIAL BACKOFF
		// ==========================================================
		//
		// The retry interval grows until 24 hours.
		// There is NO limit on the number of retries.
		//
		// 5s -> 10s -> 20s -> 40s -> ... -> 24h -> 24h -> ...
		//
		// The 24-hour value is only a retry interval.
		// It is NOT an offline or identity expiration limit.

		backoff := baseBackoff

		for i := uint64(1); i < attempt; i++ {
			if backoff >= 24*time.Hour {
				backoff = 24 * time.Hour
				break
			}

			backoff *= 2

			if backoff >= 24*time.Hour {
				backoff = 24 * time.Hour
				break
			}
		}

		// ==========================================================
		// RANDOM JITTER
		// ==========================================================
		//
		// Prevents many mobile peers from reconnecting at exactly
		// the same moment after a common network outage.

		jitterRange := backoff / 4
		var jitter time.Duration

		if jitterRange > 0 {
			jitter = time.Duration(
				rand.Int63n(int64(jitterRange)),
			)
		}

		delay := backoff + jitter

		log.Printf(
			"[p2p] mobile reconnect attempt #%d to %s failed: %v; retry in %s",
			attempt,
			p.addr,
			err,
			delay,
		)

		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			continue

		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			return nil, ctx.Err()
		}
	}
}

func (p *Peer) Connect() error {
	if p == nil {
		return errors.New("nil peer")
	}

	// ------------------------------------------------------------------
	// SESSION CHECK
	// ------------------------------------------------------------------

	p.mu.Lock()

	if p.connected && p.conn != nil {
		p.mu.Unlock()
		return nil
	}

	// Do not call IsBanned() here because it acquires p.mu again.
	if time.Now().Before(p.banUntil) {
		ban := p.banUntil
		p.mu.Unlock()

		return fmt.Errorf(
			"peer %s is banned until %s",
			p.addr,
			ban.String(),
		)
	}

	ctx := p.ctx

	p.mu.Unlock()

	// ------------------------------------------------------------------
	// NODE VALIDATION
	// ------------------------------------------------------------------

	if p.node == nil {
		return errors.New("missing node")
	}

	if p.node.tlsConfig == nil {
		return errors.New("missing TLS configuration")
	}

	if ctx == nil {
		return errors.New("peer context is missing")
	}

	// A cancelled Peer represents an expired network session.
	// A new session must use a new Peer object.
	select {
	case <-ctx.Done():
		return errors.New("peer session already closed")
	default:
	}

	// ------------------------------------------------------------------
	// DIAL CONFIGURATION
	// ------------------------------------------------------------------

	dialTimeout := 10 * time.Second

	if p.node.config.DialTimeout > 0 {
		dialTimeout = p.node.config.DialTimeout
	}

	// ------------------------------------------------------------------
	// TCP + TLS
	// ------------------------------------------------------------------
	//
	// This is a temporary network session.
	//
	// Mobile networks may disappear at any moment:
	//
	// Wi-Fi -> 4G
	// 4G -> 5G
	// phone sleep
	// router restart
	// IP change
	// phone powered off
	//
	// None of these events are identity violations.
	// The session simply ends and a future Peer reconnects.
	// ------------------------------------------------------------------

	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config:    p.node.tlsConfig,
	}

	relayTransport := false
	conn, err := tlsDialer.DialContext(
		ctx,
		"tcp",
		p.addr,
	)
	if err != nil {
		// If this session was cancelled, this is normal session
		// lifecycle behavior and does not require diagnostics.
		select {
		case <-ctx.Done():
			return errors.New("peer session cancelled during TLS dial")
		default:
		}

		log.Printf("[p2p] ❌ TLS connection FAILED to %s: %v", p.addr, err)

		// Keep the direct TCP diagnostic. This confirms whether the
		// failure is specifically at the TLS layer.
		tcpDialer := &net.Dialer{Timeout: dialTimeout}
		tcpConn, tcpErr := tcpDialer.DialContext(
			ctx,
			"tcp",
			p.addr,
		)

		if tcpErr != nil {
			log.Printf(
				"[p2p] ❌ TCP connection FAILED to %s: %v",
				p.addr,
				tcpErr,
			)
		} else {
			log.Printf(
				"[p2p] ✅ TCP connection SUCCESSFUL to %s — TLS is the failing layer",
				p.addr,
			)
			_ = tcpConn.Close()
		}

		// Relay fallback is available only when the permanent remote
		// PeerID is already known. IP address alone is never enough
		// to select a relay destination.
		if p.targetPeerID != "" {
			relayConn, relayErr := p.node.connectRelayPeer(
				ctx,
				p.targetPeerID,
			)

			if relayErr == nil {
				conn = relayConn
				relayTransport = true

				log.Printf(
					"[p2p] 🔄 Direct TLS failed; relay fallback established to peer %s",
					p.targetPeerID,
				)
			} else {
				log.Printf(
					"[p2p] ❌ Relay fallback FAILED to peer %s: %v",
					p.targetPeerID,
					relayErr,
				)
				return fmt.Errorf(
					"TLS dial failed to %s: %w",
					p.addr,
					err,
				)
			}
		} else {
			return fmt.Errorf(
				"TLS dial failed to %s: %w",
				p.addr,
				err,
			)
		}
	}

	// ------------------------------------------------------------------
	// SESSION VALIDATION AFTER TLS
	// ------------------------------------------------------------------

	p.mu.Lock()

	// The session may have been cancelled while TLS was completing.
	select {
	case <-ctx.Done():
		p.mu.Unlock()
		_ = conn.Close()

		return errors.New(
			"peer session cancelled before TLS connection was installed",
		)

	default:
	}

	// Never install a second connection into the same Peer session.
	if p.connected && p.conn != nil {
		p.mu.Unlock()
		_ = conn.Close()

		return nil
	}

	p.conn = conn
	p.connected = true
	p.lastSeen = time.Now()

	p.mu.Unlock()

	// ------------------------------------------------------------------
	// ------------------------------------------------------------------
	// TRANSPORT INFORMATION
	// ------------------------------------------------------------------

	if relayTransport {
		log.Printf(
			"[p2p] 🔄 Relay transport established to %s",
			p.targetPeerID,
		)
	} else if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()

		log.Printf(
			"[p2p] 🔒 Secure TLS connection established to %s (TLS %d.%d, cipher=%s)",
			p.addr,
			state.Version>>8,
			state.Version&0xff,
			tls.CipherSuiteName(state.CipherSuite),
		)
	} else {
		log.Printf(
			"[p2p] 🔒 Secure TLS connection established to %s",
			p.addr,
		)
	}

	// ------------------------------------------------------------------
	// START SESSION IO
	// ------------------------------------------------------------------

	p.wg.Add(2)

	go p.readLoop()
	go p.writeLoop()

	// ------------------------------------------------------------------
	// SEND HANDSHAKE
	// ------------------------------------------------------------------
	//
	// The handshake is intentionally asynchronous.
	//
	// TLS establishes the encrypted transport first.
	// EXPLOSIVE HANDSHAKE then authenticates the wallet identity
	// and, when applicable, the miner identity.
	//
	// Wallet password, BIP39 words, sacred words and private keys
	// never cross this connection.
	// ------------------------------------------------------------------

	go func() {
		delay := time.Duration(
			100+rand.Intn(501),
		) * time.Millisecond

		log.Printf(
			"[p2p] ⏳ Preparing outbound handshake to %s (delay=%v)",
			p.addr,
			delay,
		)

		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-p.ctx.Done():
			return

		case <-timer.C:
		}

		// The connection may have disappeared while the handshake
		// delay was running.
		if !p.IsConnected() {
			log.Printf(
				"[p2p] ⛔ Session disappeared before handshake to %s",
				p.addr,
			)
			return
		}

		log.Printf(
			"[p2p] 🚀 Sending handshake to %s",
			p.addr,
		)

		if err := p.sendHandshake(); err != nil {
			log.Printf(
				"[p2p] ❌ Handshake failed to %s: %v",
				p.addr,
				err,
			)

			// Handshake failure closes this temporary session.
			// The reconnect system may create a completely new Peer
			// session later.
			p.Close()
			return
		}

		log.Printf(
			"[p2p] ✅ Handshake queued for %s",
			p.addr,
		)
	}()

	return nil
}

// sendHandshake sends the local node's handshake message to the peer.
// Enhanced to use the improved Envelope with Nonce and proper canonical signing.
// Signs the message only if a valid V3 miner identity is available and required.

func (p *Peer) sendHandshake() error {
	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("missing node reference")
	}

	// ------------------------------------------------------------------
	// READ LOCAL WALLET PUBLIC IDENTITY
	// ------------------------------------------------------------------
	//
	// The wallet identity is the primary public identity of every
	// EXPLOSIVE P2P participant.
	//
	// The wallet public key is transmitted.
	// The wallet private key is never transmitted or stored in the P2P node.
	//
	// A wallet may belong to an investor who is not a miner.
	// Therefore the local ledger must never be used to select an identity.
	// ------------------------------------------------------------------

	p.node.walletIdentityMu.RLock()

	walletAddress := strings.TrimSpace(p.node.walletAddress)

	walletPublicKey := make([]byte, len(p.node.walletPublicKey))
	copy(walletPublicKey, p.node.walletPublicKey)

	p.node.walletIdentityMu.RUnlock()

	if walletAddress == "" {
		return errors.New("local wallet identity is not configured")
	}

	if !address.IsValidEXPLOAddress(walletAddress) {
		return errors.New("local wallet address is invalid")
	}

	if len(walletPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid local wallet public key size: got %d, want %d",
			len(walletPublicKey),
			ed25519.PublicKeySize,
		)
	}

	// ------------------------------------------------------------------
	// READ EXPLICIT MINER PUBLIC IDENTITY
	// ------------------------------------------------------------------
	//
	// Miner identity is completely separate from wallet identity.
	//
	// MinerID normally equals WalletAddress, but MinerPublicKey is a
	// different Ed25519 public key derived from the miner credentials.
	//
	// The P2P node only receives the public miner key and a signing
	// callback. Sacred words and miner private keys never enter the
	// handshake.
	// ------------------------------------------------------------------

	p.node.minerIdentityMu.RLock()

	minerID := strings.TrimSpace(p.node.minerID)

	minerPublicKey := make([]byte, len(p.node.minerPublicKey))
	copy(minerPublicKey, p.node.minerPublicKey)

	p.node.minerIdentityMu.RUnlock()

	isMiner := minerID != ""

	if isMiner {
		// MinerID must be the wallet address that owns the mining identity.
		if !strings.EqualFold(minerID, walletAddress) {
			return fmt.Errorf(
				"miner identity mismatch: miner_id=%s wallet_address=%s",
				minerID,
				walletAddress,
			)
		}

		if !address.IsValidEXPLOAddress(minerID) {
			return errors.New("local miner ID is invalid")
		}

		if len(minerPublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf(
				"invalid local miner public key size: got %d, want %d",
				len(minerPublicKey),
				ed25519.PublicKeySize,
			)
		}
	} else {
		// Observer/investor nodes must not advertise a miner identity.
		minerID = ""
		minerPublicKey = nil
	}

	// ------------------------------------------------------------------
	// BUILD HANDSHAKE PAYLOAD
	// ------------------------------------------------------------------

	h := HandshakePayload{
		WalletAddress: walletAddress,
		PeerID:        string(p.node.id),
		ListenAddr:    p.node.listenAddr,
		Version:       p.node.userAgent,
		Network:       p.node.networkID,
		IsMiner:       isMiner,
		MinerID:       minerID,

		// Advertise the highest block height currently known by this node.
		// This is public synchronization metadata only.
		ChainHeight: p.node.Ledger.GetLatestBlockHeight(),
	}

	if strings.TrimSpace(h.PeerID) == "" {
		return errors.New("local peer ID is empty")
	}

	if !strings.EqualFold(h.PeerID, h.WalletAddress) {
		return fmt.Errorf(
			"local peer identity mismatch: peer_id=%s wallet_address=%s",
			h.PeerID,
			h.WalletAddress,
		)
	}

	if strings.TrimSpace(h.Network) == "" {
		return errors.New("local network ID is empty")
	}

	if strings.TrimSpace(h.Network) == "" {
		return errors.New("local network ID is empty")
	}

	// ------------------------------------------------------------------
	// CREATE ENVELOPE
	// ------------------------------------------------------------------

	env, err := NewEnvelopeFromPayload(
		p.node.ProtocolVersion(),
		MsgTypeHandshake,
		h,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create handshake envelope: %w",
			err,
		)
	}

	// ------------------------------------------------------------------
	// ATTACH WALLET PUBLIC KEY
	// ------------------------------------------------------------------
	//
	// Envelope.PubKey always means WALLET public key.
	//
	// It must never be replaced by the miner public key.
	// ------------------------------------------------------------------

	env.PubKey = walletPublicKey

	// ------------------------------------------------------------------
	// CREATE WALLET CANONICAL SIGNING DATA
	// ------------------------------------------------------------------
	//
	// This MUST exactly match VerifyEnvelopeSignature().
	//
	// The signature covers:
	//
	//   Version
	//   Type
	//   Payload
	//   Timestamp
	//   Nonce
	//
	// The wallet address is inside Payload and is therefore authenticated.
	// ------------------------------------------------------------------

	walletCanon := struct {
		V     uint16      `cbor:"v"`
		T     MessageType `cbor:"t"`
		P     []byte      `cbor:"p,omitempty"`
		Ts    int64       `cbor:"ts"`
		Nonce uint64      `cbor:"nonce"`
	}{
		V:     env.Version,
		T:     env.Type,
		P:     env.Payload,
		Ts:    env.Timestamp,
		Nonce: env.Nonce,
	}

	walletMessage, err := cbor.Marshal(walletCanon)
	if err != nil {
		return fmt.Errorf(
			"failed to marshal canonical wallet handshake data: %w",
			err,
		)
	}

	// ------------------------------------------------------------------
	// SIGN WITH WALLET
	// ------------------------------------------------------------------
	//
	// The P2P node never receives the wallet private key.
	// The wallet layer performs the actual signing through the configured
	// signer callback.
	// ------------------------------------------------------------------

	signature, err := p.node.signWalletData(walletMessage)
	if err != nil {
		return fmt.Errorf(
			"failed to sign wallet handshake: %w",
			err,
		)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf(
			"invalid wallet handshake signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	env.Signature = signature

	// ------------------------------------------------------------------
	// ADD MINER PROOF WHEN THIS NODE IS A MINER
	// ------------------------------------------------------------------
	//
	// Wallet authentication and miner authentication are deliberately
	// separate.
	//
	// Wallet:
	//     Envelope.PubKey
	//     Envelope.Signature
	//
	// Miner:
	//     MinerInfo.PubKey
	//     MinerInfo.Signature
	//
	// The miner proof binds:
	//
	//     Network
	//     WalletAddress
	//     MinerID
	//     PeerID
	//     MinerPublicKey
	//     Timestamp
	//     Nonce
	//
	// Sacred words are NEVER transmitted.
	// ------------------------------------------------------------------

	if isMiner {
		proofPayload, err := BuildMinerP2PProof(
			p.node.networkID,
			walletAddress,
			minerID,
			string(p.node.id),
			minerPublicKey,
			env.Timestamp,
			env.Nonce,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to build miner P2P proof: %w",
				err,
			)
		}

		// Read the configured miner signer.
		//
		// The signer is a callback only. The P2P node does not receive
		// or store the miner private key or sacred words.
		p.node.minerSignerMu.RLock()
		minerSigner := p.node.minerSigner
		p.node.minerSignerMu.RUnlock()

		if minerSigner == nil {
			return errors.New(
				"miner P2P signer is not configured",
			)
		}

		minerSignature, err := minerSigner(proofPayload)
		if err != nil {
			return fmt.Errorf(
				"failed to sign miner P2P proof: %w",
				err,
			)
		}

		if len(minerSignature) != ed25519.SignatureSize {
			return fmt.Errorf(
				"invalid miner P2P signature size: got %d, want %d",
				len(minerSignature),
				ed25519.SignatureSize,
			)
		}

		env.MinerInfo = &MinerInfo{
			MinerID:   minerID,
			Timestamp: env.Timestamp,
			PubKey:    append([]byte(nil), minerPublicKey...),
			Signature: append([]byte(nil), minerSignature...),
		}
	}

	// ------------------------------------------------------------------
	// FINAL SECURITY CHECK

	// ------------------------------------------------------------------

	if isMiner {
		if env.MinerInfo == nil {
			return errors.New(
				"miner handshake missing MinerInfo",
			)
		}

		if env.MinerInfo.MinerID != minerID {
			return errors.New(
				"miner handshake identity mismatch",
			)
		}

		if !bytes.Equal(env.MinerInfo.PubKey, minerPublicKey) {
			return errors.New(
				"miner handshake public key mismatch",
			)
		}
	} else {
		if env.MinerInfo != nil {
			return errors.New(
				"observer handshake must not contain MinerInfo",
			)
		}

		if h.MinerID != "" {
			return errors.New(
				"observer handshake must not contain MinerID",
			)
		}
	}

	// ------------------------------------------------------------------
	// SEND HANDSHAKE
	// ------------------------------------------------------------------
	//
	// SendEnvelope() deliberately does not re-sign HANDSHAKE messages.
	// The wallet signature and optional miner proof created above are the
	// final authenticated handshake data.
	// ------------------------------------------------------------------

	log.Printf(
		"[p2p] 🤝 sending handshake: wallet=%s peer=%s miner=%v miner_id=%s",
		walletAddress,
		p.node.id,
		isMiner,
		minerID,
	)

	err = p.SendEnvelope(env)
	if err != nil {
		return fmt.Errorf(
			"failed to send handshake: %w",
			err,
		)
	}

	return nil
}

// finalizeHandshake is called when a valid remote handshake message is received.
// It ensures the bidirectional handshake is marked as complete only once and logs
// the success with detailed, symbolic information for easy debugging and monitoring.
//
// This method is critical for confirming that a full mutual authentication has occurred:
// - The local node has sent its handshake.
// - The remote peer has responded with a valid handshake payload.
// - Optional V3 miner identity verification has been performed if provided.
//
// The handshake is considered fully successful only at this point, allowing subsequent
// message exchange (blocks, transactions, metrics, etc.).

func (p *Peer) finalizeHandshake(remoteMinerID string) {

	p.handshakeOnce.Do(func() {

		p.mu.Lock()

		// Keep the PeerID established by the handshake.
		// Only use remoteMinerID as a fallback for legacy callers.
		if p.id == "" && remoteMinerID != "" {
			p.id = PeerID(remoteMinerID)
		}

		peerID := p.id
		p.handshakeDone = true

		verified := p.verifiedMiner
		minerID := p.verifiedMinerID

		p.mu.Unlock()

		if peerID == "" {
			log.Printf(
				"[p2p] ❌ Handshake finalized without a PeerID from %s",
				p.addr,
			)
		} else if p.node != nil {
			p.node.addPeer(p)
		}

		log.Printf(
			"[p2p] 🤝 BIDIRECTIONAL HANDSHAKE SUCCESSFUL with %s (peer=%s, miner=%s)",
			p.addr,
			peerID,
			minerID,
		)

		if verified {
			log.Printf(
				"[p2p] ✅ Verified conscious miner connected: %s",
				minerID,
			)
		}

		select {
		case <-p.handshakeCh:
		default:
			close(p.handshakeCh)
		}
	})
}

// Close gracefully shuts down the current peer session.
// A Peer represents one connection session and must never be reused
// after it has been closed. The context cancellation stops the I/O
// workers, while closing the connection unblocks network operations.
//
// Close intentionally does not close sendQ and does not wait on wg.
// This prevents send-on-closed-channel races and avoids a deadlock when
// Close is called from readLoop or writeLoop through disconnect handling.
func (p *Peer) Close() {
	if p == nil {
		return
	}

	p.mu.Lock()

	// Capture the current session resources while holding the mutex.
	cancel := p.cancel
	conn := p.conn

	// Mark the session as disconnected immediately.
	p.connected = false
	p.conn = nil

	p.mu.Unlock()

	// Cancel all peer workers.
	if cancel != nil {
		cancel()
	}

	// Close the network connection.
	// This also unblocks any pending Read or Write operation.
	if conn != nil {
		_ = conn.Close()
	}
}

// getConn returns the underlying connection under read lock.
func (p *Peer) getConn() net.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.conn
}
