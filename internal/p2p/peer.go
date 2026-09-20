// internal/p2p/peer.go
package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"explosive/internal/address"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"explosive/internal/ledger"
	"github.com/fxamacker/cbor/v2"
)

// PeerID is a string identifier for a peer (could be hex/base58).
type PeerID string

// Peer represents a remote peer connection, its outgoing queue, lifecycle, and blockchain state.
type Peer struct {
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
		id:            id,
		addr:          addr,
		reconnectAddr: addr,
		node:          node,
		sendQ:         make(chan []byte, qsize),
		ctx:           ctx,
		cancel:        cancel,
		handshakeCh:   make(chan struct{}),
		pendingPings:  make(map[int64]time.Time),
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

		log.Printf(
			"[p2p] ❌ TLS connection FAILED to %s: %v",
			p.addr,
			err,
		)

		// Diagnostic TCP probe only.
		// Failure here is network/session failure, not peer misbehavior.
		tcpDialer := &net.Dialer{
			Timeout: dialTimeout,
		}

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

		return fmt.Errorf(
			"TLS dial failed to %s: %w",
			p.addr,
			err,
		)
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
	// TLS INFORMATION
	// ------------------------------------------------------------------

	if tlsConn, ok := conn.(*tls.Conn); ok {
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

// SendEnvelope serializes and enqueues an envelope for sending.
//
// Signing policy:
//  1. HANDSHAKE is already signed explicitly by sendHandshake().
//  2. If a wallet signer is configured, regular messages are signed with
//     the authenticated wallet identity.
//  3. If no wallet signer is configured, the legacy miner signing path is
//     preserved temporarily for miner-only nodes.
//  4. Critical messages can never be sent unsigned.
//
// The P2P layer never receives or stores wallet private keys.
func (p *Peer) SendEnvelope(e *Envelope) error {

	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("missing node reference")
	}

	if e == nil {
		return errors.New("nil envelope")
	}

	// ================================================================
	// SIGNING
	// ================================================================
	//
	// The handshake is signed explicitly by sendHandshake().
	//
	// Every other signed P2P message uses the authenticated wallet
	// identity. The wallet public key is stored in Envelope.PubKey and
	// the corresponding wallet signature is stored in Envelope.Signature.
	//
	// Miner authentication is separate and is carried only through
	// MinerInfo when explicitly required by the protocol.
	//
	// The P2P package never accesses miner sacred words or derives
	// miner private keys.
	// ================================================================

	if p.node.config.RequireSignedMessages &&
		e.Type != MsgTypeHandshake {

		signed := false

		// ------------------------------------------------------------
		// WALLET PUBLIC IDENTITY
		// ------------------------------------------------------------

		p.node.walletIdentityMu.RLock()

		walletAddress := p.node.walletAddress
		walletPublicKey := append(
			[]byte(nil),
			p.node.walletPublicKey...,
		)

		p.node.walletIdentityMu.RUnlock()

		// ------------------------------------------------------------
		// WALLET SIGNER
		// ------------------------------------------------------------

		p.node.walletSignerMu.RLock()
		walletSignerConfigured := p.node.walletSigner != nil
		p.node.walletSignerMu.RUnlock()

		if walletSignerConfigured &&
			walletAddress != "" &&
			address.IsValidEXPLOAddress(walletAddress) &&
			len(walletPublicKey) == ed25519.PublicKeySize {

			canon := struct {
				V     uint16      `cbor:"v"`
				T     MessageType `cbor:"t"`
				P     []byte      `cbor:"p,omitempty"`
				Ts    int64       `cbor:"ts"`
				Nonce uint64      `cbor:"nonce"`
			}{
				V:     e.Version,
				T:     e.Type,
				P:     e.Payload,
				Ts:    e.Timestamp,
				Nonce: e.Nonce,
			}

			msg, err := cbor.Marshal(canon)
			if err != nil {
				return fmt.Errorf(
					"failed to marshal canonical wallet signing data: %w",
					err,
				)
			}

			signature, err := p.node.signWalletData(msg)
			if err != nil {
				return fmt.Errorf(
					"failed to sign message with wallet: %w",
					err,
				)
			}

			if len(signature) != ed25519.SignatureSize {
				return fmt.Errorf(
					"invalid wallet signature size: got %d, want %d",
					len(signature),
					ed25519.SignatureSize,
				)
			}

			e.Signature = append([]byte(nil), signature...)
			e.PubKey = append([]byte(nil), walletPublicKey...)

			signed = true

			log.Printf(
				"[p2p] 🔐 message signed with wallet identity: type=%s wallet=%s",
				e.Type,
				walletAddress,
			)
		}

		// ------------------------------------------------------------
		// NO LEGACY MINER FALLBACK
		// ------------------------------------------------------------
		//
		// A P2P node must never enumerate local miners, read sacred
		// words, derive miner private keys, or silently select miners[0].
		//
		// Miner authentication is handled separately by the explicit
		// MinerInfo proof mechanism.
		// ------------------------------------------------------------

		if !signed {

			critical :=
				e.Type == MsgTypeTx ||
					e.Type == MsgTypeBlock ||
					e.Type == MsgTypeInv ||
					e.Type == MsgTypeMetrics

			if critical {
				return fmt.Errorf(
					"critical message %s cannot be sent without a valid wallet identity",
					e.Type,
				)
			}

			return fmt.Errorf(
				"message %s cannot be sent without a valid wallet identity",
				e.Type,
			)
		}
	}

	// ================================================================
	// ENCODE
	// ================================================================

	b, err := EncodeEnvelope(e)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	max := p.node.config.MaxMsgSize
	if max <= 0 {
		max = 4 * 1024 * 1024
	}

	if len(b) > max {
		return fmt.Errorf(
			"message too large: %d > %d",
			len(b),
			max,
		)
	}

	select {
	case <-p.ctx.Done():
		return errors.New("peer closed")
	default:
	}

	// ================================================================
	// TRANSACTION QUEUE
	// ================================================================

	if e.Type == MsgTypeTx {

		select {
		case p.sendQ <- b:
			return nil

		default:
			p.Penalize(1, 0)
			return errors.New("TX queue full")
		}
	}

	// ================================================================
	// CRITICAL QUEUE
	// ================================================================

	critical :=
		e.Type == MsgTypeHandshake ||
			e.Type == MsgTypeBlock ||
			e.Type == MsgTypeInv

	if critical {

		timeout := 500 * time.Millisecond

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-p.ctx.Done():
			return errors.New("peer closed")

		case p.sendQ <- b:
			return nil

		case <-timer.C:

			log.Printf(
				"[p2p] timeout sending critical %s to %s",
				e.Type,
				p.addr,
			)

			return errors.New("critical send timeout")
		}
	}

	// ================================================================
	// NORMAL QUEUE
	// ================================================================

	select {
	case p.sendQ <- b:
		return nil

	default:

		log.Printf(
			"[p2p] peer %s: outbound queue full, dropping %s",
			p.addr,
			e.Type,
		)

		return errors.New("send queue full")
	}
}

func (p *Peer) signEnvelope(
	env *Envelope,
	priv ed25519.PrivateKey,
	miner *ledger.Miner,
) error {

	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("missing node reference")
	}

	if env == nil {
		return errors.New("nil envelope")
	}

	// The P2P envelope identity is the wallet identity.
	// Miner identity is separate and must never replace Wallet.PubKey.
	//
	// Keep the legacy parameters in the function signature for
	// compatibility with existing callers, but never use them to
	// construct the P2P envelope identity.

	p.node.walletIdentityMu.RLock()

	walletAddress := p.node.walletAddress
	walletPublicKey := append(
		[]byte(nil),
		p.node.walletPublicKey...,
	)

	p.node.walletIdentityMu.RUnlock()

	if walletAddress == "" {
		return errors.New("wallet identity is not configured")
	}

	if !address.IsValidEXPLOAddress(walletAddress) {
		return errors.New("invalid wallet address")
	}

	if len(walletPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid wallet public key size: got %d, want %d",
			len(walletPublicKey),
			ed25519.PublicKeySize,
		)
	}

	p.node.walletSignerMu.RLock()
	walletSignerConfigured := p.node.walletSigner != nil
	p.node.walletSignerMu.RUnlock()

	if !walletSignerConfigured {
		return errors.New("wallet signer is not configured")
	}

	canon := struct {
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

	msg, err := cbor.Marshal(canon)
	if err != nil {
		return fmt.Errorf(
			"failed to marshal canonical data for signing: %w",
			err,
		)
	}

	signature, err := p.node.signWalletData(msg)
	if err != nil {
		return fmt.Errorf(
			"failed to sign envelope with wallet: %w",
			err,
		)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf(
			"invalid wallet signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	env.Signature = append([]byte(nil), signature...)
	env.PubKey = walletPublicKey

	return nil
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

// writeLoop consumes sendQ and writes framed messages to the connection.
// Writes are batched and flushed periodically to increase throughput.
func (p *Peer) writeLoop() {
	defer p.wg.Done()

	conn := p.getConn()
	if conn == nil {
		log.Printf("[p2p] writeLoop aborted: nil connection for %s", p.addr)
		return
	}

	w := bufio.NewWriterSize(conn, 64*1024)

	flushTicker := time.NewTicker(100 * time.Millisecond)
	defer flushTicker.Stop()

	var pending [][]byte
	var pendingBytes int

	flush := func() error {

		if len(pending) == 0 {
			return nil
		}

		log.Printf("[p2p] writeLoop flushing %d message(s) (%d bytes) to %s",
			len(pending), pendingBytes, p.addr)

		if c, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			writeTimeout := 2 * time.Minute

			if p.node != nil && p.node.config.ConnWriteTimeout > 0 {
				writeTimeout = p.node.config.ConnWriteTimeout
			}

			_ = c.SetWriteDeadline(
				time.Now().Add(writeTimeout),
			)
		}

		for i, b := range pending {

			log.Printf("[p2p] writing frame #%d (%d bytes) to %s",
				i+1, len(b), p.addr)

			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))

			log.Printf("[p2p] writing frame header to %s", p.addr)

			if _, err := w.Write(lenBuf[:]); err != nil {
				log.Printf("[p2p] write header failed to %s: %v", p.addr, err)
				return err
			}

			log.Printf("[p2p] writing frame payload (%d bytes) to %s",
				len(b), p.addr)

			if _, err := w.Write(b); err != nil {
				log.Printf("[p2p] write payload failed to %s: %v", p.addr, err)
				return err
			}
		}

		log.Printf("[p2p] flushing buffered data to %s", p.addr)

		if err := w.Flush(); err != nil {
			log.Printf("[p2p] flush failed to %s: %v", p.addr, err)
			return err
		}

		log.Printf("[p2p] ✅ flush completed to %s", p.addr)

		pending = pending[:0]
		pendingBytes = 0

		return nil
	}

	for {
		select {

		case <-p.ctx.Done():
			log.Printf("[p2p] writeLoop stopping for %s", p.addr)
			_ = flush()
			return

		case b, ok := <-p.sendQ:

			if !ok {
				log.Printf("[p2p] sendQ closed for %s", p.addr)
				_ = flush()
				return
			}

			log.Printf("[p2p] writeLoop received %d bytes for %s",
				len(b), p.addr)

			if p.IsBanned() {
				log.Printf("[p2p] peer %s is banned, dropping outbound message", p.addr)
				continue
			}

			pending = append(pending, b)
			pendingBytes += len(b)

			log.Printf("[p2p] pending=%d message(s), %d bytes for %s",
				len(pending), pendingBytes, p.addr)

			if pendingBytes >= 64*1024 || len(pending) >= 128 {

				log.Printf("[p2p] forcing flush due to buffer threshold for %s", p.addr)

				if err := flush(); err != nil {
					log.Printf("peer %s write flush error: %v", p.addr, err)
					if p.node != nil {
						p.node.handlePeerDisconnect(p)
					}
					return
				}
			}

		case <-flushTicker.C:

			if pendingBytes == 0 {
				continue
			}

			log.Printf("[p2p] periodic flush for %s", p.addr)

			if err := flush(); err != nil {
				log.Printf("peer %s periodic flush error: %v", p.addr, err)
				if p.node != nil {
					p.node.handlePeerDisconnect(p)
				}
				return
			}
		}
	}
}

func (p *Peer) readLoop() {
	defer p.wg.Done()

	conn := p.getConn()
	if conn == nil {
		return
	}

	// The read deadline protects the current network session.
	// A timeout is NOT a reputation violation.
	readTimeout := 5 * time.Minute
	if p.node != nil && p.node.config.ConnReadTimeout > 0 {
		readTimeout = p.node.config.ConnReadTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

	r := bufio.NewReaderSize(conn, 64*1024)

	seenNonces := make(map[uint64]time.Time)
	lastCleanup := time.Now()

	criticalMessages := map[MessageType]bool{
		MsgTypeHandshake: true,
		MsgTypeTx:        true,
		MsgTypeBlock:     true,
		MsgTypeInv:       true,
		MsgTypeMetrics:   true,
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// ==========================================================
		// READ FRAME SIZE
		// ==========================================================

		var lenBuf [4]byte

		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {

			// Network interruption, timeout, EOF or closed socket
			// are session events, NOT reputation violations.
			if errors.Is(err, os.ErrDeadlineExceeded) ||
				errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, io.ErrUnexpectedEOF) {

				log.Printf(
					"[p2p] network session ended with %s: %v",
					p.addr,
					err,
				)
			} else {
				log.Printf(
					"[p2p] read header error from %s: %v",
					p.addr,
					err,
				)
			}

			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}

			return
		}

		msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))

		maxSize := 4 * 1024 * 1024
		if p.node != nil && p.node.config.MaxMsgSize > 0 {
			maxSize = p.node.config.MaxMsgSize
		}

		if msgLen <= 0 || msgLen > maxSize {

			log.Printf(
				"[p2p] invalid message length %d from %s",
				msgLen,
				p.addr,
			)

			p.Penalize(20, 0)

			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}

			return
		}

		// ==========================================================
		// READ PAYLOAD
		// ==========================================================

		payload := make([]byte, msgLen)

		if _, err := io.ReadFull(r, payload); err != nil {

			// Again: network loss is not malicious behaviour.
			if errors.Is(err, os.ErrDeadlineExceeded) ||
				errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) ||
				errors.Is(err, io.ErrUnexpectedEOF) {

				log.Printf(
					"[p2p] network session ended while reading payload from %s: %v",
					p.addr,
					err,
				)
			} else {
				log.Printf(
					"[p2p] read payload error from %s: %v",
					p.addr,
					err,
				)
			}

			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}

			return
		}

		// Renew deadline after each successful read.
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

		// ==========================================================
		// DECODE
		// ==========================================================

		env, err := DecodeEnvelope(payload)
		if err != nil {

			log.Printf(
				"[p2p] decode error from %s: %v",
				p.addr,
				err,
			)

			p.Penalize(3, 0)
			continue
		}

		log.Printf(
			"[p2p] 📨 received envelope type=%s size=%d from %s (handshakeDone=%v)",
			env.Type,
			len(payload),
			p.addr,
			p.handshakeDone,
		)

		if err := ValidateEnvelope(env); err != nil {

			log.Printf(
				"[p2p] invalid envelope from %s: %v",
				p.addr,
				err,
			)

			p.Penalize(10, 0)
			continue
		}

		// ==========================================================
		// HANDSHAKE GATE
		//
		// node3.go remains the single source of truth for:
		// - handshake authentication
		// - wallet identity verification
		// - miner identity verification
		// - peer registration
		// ==========================================================

		// ==========================================================
		// SIGNATURE VALIDATION
		// ==========================================================

		if criticalMessages[env.Type] {

			if len(env.PubKey) != ed25519.PublicKeySize ||
				len(env.Signature) != ed25519.SignatureSize {

				log.Printf(
					"[p2p] 🚫 missing or invalid cryptographic identity from %s (type=%s, pubkey=%d, signature=%d)",
					p.addr,
					env.Type,
					len(env.PubKey),
					len(env.Signature),
				)

				p.Penalize(40, 4*time.Hour)
				continue
			}

			ok, err := VerifyEnvelopeSignature(env)
			if err != nil || !ok {

				log.Printf(
					"[p2p] 🚫 invalid signature from %s (type=%s): %v",
					p.addr,
					env.Type,
					err,
				)

				p.Penalize(40, 4*time.Hour)
				continue
			}

			log.Printf(
				"[p2p] ✅ cryptographic wallet signature verified from %s (type=%s)",
				p.addr,
				env.Type,
			)
		}

		// ==========================================================
		// REPLAY PROTECTION
		// ==========================================================

		if env.Nonce != 0 {

			now := time.Now()

			if now.Sub(lastCleanup) > 5*time.Minute {

				for nonce, ts := range seenNonces {
					if now.Sub(ts) > 10*time.Minute {
						delete(seenNonces, nonce)
					}
				}

				lastCleanup = now
			}

			if _, exists := seenNonces[env.Nonce]; exists {

				log.Printf(
					"[p2p] 🚫 replayed nonce from %s: %d",
					p.addr,
					env.Nonce,
				)

				p.Penalize(50, 24*time.Hour)
				continue
			}

			seenNonces[env.Nonce] = now
		}

		// ==========================================================
		// BLOCK VALIDATION
		//
		// Pre-dispatch DailyPoW verification.
		// ==========================================================

		if env.Type == MsgTypeBlock {

			var blk ledger.Block

			if err := cbor.Unmarshal(env.Payload, &blk); err != nil {

				log.Printf(
					"[p2p] invalid block payload from %s: %v",
					p.addr,
					err,
				)

				p.Penalize(20, 1*time.Hour)
				continue
			}

			if blk.Header.DailyPoW == nil {

				log.Printf(
					"[p2p] block without DailyPoW from %s",
					p.addr,
				)

				p.Penalize(40, 24*time.Hour)
				continue
			}

			if !ledger.VerifyDailyPoW(
				blk.Header.MinerAddress,
				*blk.Header.DailyPoW,
				blk.Header.PrevHash,
			) {

				log.Printf(
					"[p2p] invalid DailyPoW from %s",
					p.addr,
				)

				p.Penalize(60, 48*time.Hour)
				continue
			}
		}

		// ==========================================================
		// ACTIVITY UPDATE
		// ==========================================================

		p.mu.Lock()
		p.lastSeen = time.Now()
		p.mu.Unlock()

		// ==========================================================
		// DISPATCH
		//
		// All messages, including HANDSHAKE, are dispatched through
		// the node handler.
		// ==========================================================

		if p.node != nil {
			p.node.handleIncomingEnvelope(p, env)
		}
	}
}

// isLocalAddr returns true if the advertised address is not publicly routable.
// Prevents replacing a reachable public address with 0.0.0.0, localhost, etc.
func isLocalAddr(addr string) bool {

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}

	switch strings.ToLower(host) {

	case "",
		"0.0.0.0",
		"::",
		"::1",
		"127.0.0.1",
		"localhost":
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// RequestBlocksSince asks the peer for blocks starting from a specific height.
func (p *Peer) RequestBlocksSince(height uint64) ([]*ledger.Block, error) {
	// TODO: implement actual P2P request (RPC / gRPC / HTTP)
	return nil, fmt.Errorf("RequestBlocksSince not implemented")
}

// requestBlocksRange sends a block-range request without waiting
// for the blockchain data.
//
// The corresponding BLOCKSRESPONSE is delivered asynchronously
// through the node message handler.
//
// The synchronization engine uses this function to advance from
// one block segment to the next.
func (p *Peer) requestBlocksRange(from, to uint64) error {
	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("no node reference")
	}

	if from > to {
		return errors.New("invalid block range")
	}

	// Never request more than 50 blocks in one message.
	if to-from+1 > 50 {
		to = from + 49
	}

	payload := GetBlocksRangePayload{
		From: from,
		To:   to,
	}

	env, err := NewEnvelopeFromPayload(
		p.node.ProtocolVersion(),
		MsgTypeGetBlocksRange,
		payload,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create block range request: %w",
			err,
		)
	}

	if err := p.SendEnvelope(env); err != nil {
		return fmt.Errorf(
			"failed to send block range request: %w",
			err,
		)
	}

	log.Printf(
		"[p2p] 📤 GETBLOCKSRANGE %d-%d sent to %s",
		from,
		to,
		p.addr,
	)

	return nil
}

func (p *Peer) IsVerifiedMiner() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.verifiedMiner
}

func (p *Peer) getTLSIdentity() (string, bool) {

	conn := p.getConn()

	if conn == nil {
		return "", false
	}

	tlsConn, ok := conn.(*tls.Conn)

	if !ok {
		return "", false
	}

	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return "", false
	}

	cert := state.PeerCertificates[0]

	return cert.Subject.CommonName, true
}

// nextPingNonce generates a unique nonce for the current peer session.
func (p *Peer) nextPingNonce() int64 {
	if p == nil {
		return 0
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	p.pingSequence++

	// Combine the current timestamp with a per-peer sequence.
	// This avoids relying on wall-clock uniqueness alone.
	now := time.Now().UnixNano()

	nonce := now ^ int64(p.pingSequence)

	if nonce == 0 {
		nonce = int64(p.pingSequence)
	}

	return nonce
}

// registerPing records an outbound PING awaiting its PONG.
func (p *Peer) registerPing(nonce int64) {
	if p == nil || nonce == 0 {
		return
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	if p.pendingPings == nil {
		p.pendingPings = make(map[int64]time.Time)
	}

	p.pendingPings[nonce] = time.Now()

	// Keep the pending table bounded.
	// A missing PONG is a session issue, never a reputation violation.
	if len(p.pendingPings) > 64 {
		cutoff := time.Now().Add(-10 * time.Minute)

		for pendingNonce, sentAt := range p.pendingPings {
			if sentAt.Before(cutoff) {
				delete(p.pendingPings, pendingNonce)
			}
		}

		// Hard safety bound in case the clock behaves unexpectedly.
		for len(p.pendingPings) > 64 {
			for pendingNonce := range p.pendingPings {
				delete(p.pendingPings, pendingNonce)
				break
			}
		}
	}
}

// receivePong validates a PONG against an outstanding PING.
//
// The returned duration is the measured round-trip time.
// A false result means that the nonce was not issued by this session.
func (p *Peer) receivePong(nonce int64) (time.Duration, bool) {
	if p == nil || nonce == 0 {
		return 0, false
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	sentAt, ok := p.pendingPings[nonce]
	if !ok {
		return 0, false
	}

	delete(p.pendingPings, nonce)

	rtt := time.Since(sentAt)

	if rtt < 0 {
		rtt = 0
	}

	p.lastPong = time.Now()

	return rtt, true
}

// LastPong returns the last successful PONG time for the current session.
func (p *Peer) LastPong() time.Time {
	if p == nil {
		return time.Time{}
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	return p.lastPong
}

// PendingPingCount returns the number of PINGs currently awaiting PONG.
func (p *Peer) PendingPingCount() int {
	if p == nil {
		return 0
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	return len(p.pendingPings)
}
