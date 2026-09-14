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
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
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

// NewPeer constructs a Peer object (not connected).
// It reads queue sizing from node.config.SendQueueSize.
func NewPeer(id PeerID, addr string, node *Node) *Peer {
	ctx, cancel := context.WithCancel(context.Background())
	qsize := 64
	if node != nil && node.config.SendQueueSize > 0 {
		qsize = node.config.SendQueueSize
	}
	return &Peer{
		id:          id,
		addr:        addr,
		node:        node,
		sendQ:       make(chan []byte, qsize),
		ctx:         ctx,
		cancel:      cancel,
		handshakeCh: make(chan struct{}),
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

// backoffDial tries to dial with exponential backoff + jitter using the peer context.
func (p *Peer) backoffDial(ctx context.Context) (net.Conn, error) {
	base := time.Second
	max := 30 * time.Second
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		// respect provided DialTimeout from node config if present
		dialTimeout := time.Second * 10
		if p.node != nil && p.node.config.DialTimeout > 0 {
			dialTimeout = p.node.config.DialTimeout
		}
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", p.addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// compute backoff + jitter
		sleep := base * (1 << uint(attempt))
		if sleep > max {
			sleep = max
		}
		jitter := time.Duration(rand.Int63n(int64(250 * time.Millisecond)))
		select {
		case <-time.After(sleep + jitter):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// Connect dials the peer (if not already connected) and starts IO loops.
// It uses Node.config.DialTimeout for dial timeout.
// Subsequent calls when already connected are no-op.
//
// The connection is now established over TLS using the node's pre-generated
// deterministic or fallback self-signed certificate.
//
// The handshake is fully asynchronous and bidirectional: the function returns
// success immediately after establishing the encrypted TLS connection.
// Handshake completion occurs when the remote peer's MsgTypeHandshake message is received.

func (p *Peer) Connect() error {
	// ------------------------------------------------------------------
	// FAST CHECK
	// ------------------------------------------------------------------

	p.mu.Lock()

	if p.connected && p.conn != nil {
		p.mu.Unlock()
		return nil
	}

	// IMPORTANT:
	// Do NOT call IsBanned() here because it would try to acquire
	// the same RWMutex and can deadlock.
	if time.Now().Before(p.banUntil) {
		ban := p.banUntil
		p.mu.Unlock()
		return fmt.Errorf("peer %s is banned until %s", p.addr, ban.String())
	}

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

	dialTimeout := 10 * time.Second
	if p.node.config.DialTimeout > 0 {
		dialTimeout = p.node.config.DialTimeout
	}

	// ------------------------------------------------------------------
	// TLS CONNECTION
	// ------------------------------------------------------------------

	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		p.addr,
		p.node.tlsConfig,
	)
	if err != nil {
		log.Printf(
			"[p2p] ❌ TLS connection FAILED to %s: %v",
			p.addr,
			err,
		)

		// Also test plain TCP separately so we can distinguish
		// network connectivity from TLS negotiation failure.
		tcpDialer := &net.Dialer{
			Timeout: dialTimeout,
		}

		tcpConn, tcpErr := tcpDialer.Dial("tcp", p.addr)
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

		return fmt.Errorf("TLS dial failed to %s: %w", p.addr, err)
	}

	state := conn.ConnectionState()

	log.Printf(
		"[p2p] 🔒 Secure TLS connection established to %s (TLS %d.%d, cipher=%s)",
		p.addr,
		state.Version>>8,
		state.Version&0xff,
		tls.CipherSuiteName(state.CipherSuite),
	)

	// ------------------------------------------------------------------
	// STORE CONNECTION
	// ------------------------------------------------------------------

	p.mu.Lock()
	p.conn = conn
	p.connected = true
	p.lastSeen = time.Now()
	p.mu.Unlock()

	// ------------------------------------------------------------------
	// START IO
	// ------------------------------------------------------------------

	p.wg.Add(2)

	go p.readLoop()
	go p.writeLoop()

	// ------------------------------------------------------------------
	// SEND HANDSHAKE
	// ------------------------------------------------------------------

	go func() {
		delay := time.Duration(100+rand.Intn(501)) * time.Millisecond

		log.Printf(
			"[p2p] ⏳ Preparing outbound handshake to %s (delay=%v)",
			p.addr,
			delay,
		)

		time.Sleep(delay)

		log.Printf("[p2p] 🚀 Sending handshake to %s", p.addr)

		if err := p.sendHandshake(); err != nil {
			log.Printf("[p2p] ❌ Handshake failed to %s: %v", p.addr, err)
			p.Close()
			return
		}

		log.Printf("[p2p] ✅ Handshake queued for %s", p.addr)
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
	// The wallet identity configured in Node is authoritative.
	//
	// NEVER use ListAllMiners()[0] here.
	//
	// A wallet can be an investor without being a miner.
	// Therefore the local ledger must never decide which identity
	// this P2P connection represents.
	//
	// Only public wallet information is read here.
	// Private keys, passwords, BIP39 words and sacred words never
	// enter the handshake payload.
	// ------------------------------------------------------------------

	p.node.walletIdentityMu.RLock()

	walletAddress := p.node.walletAddress

	walletPublicKey := make([]byte, len(p.node.walletPublicKey))
	copy(walletPublicKey, p.node.walletPublicKey)

	p.node.walletIdentityMu.RUnlock()

	walletAddress = strings.TrimSpace(walletAddress)

	if walletAddress == "" {
		return errors.New("local wallet identity is not configured")
	}

	if len(walletPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid local wallet public key size: got %d, want %d",
			len(walletPublicKey),
			ed25519.PublicKeySize,
		)
	}

	// ------------------------------------------------------------------
	// DETERMINE NODE ROLE
	// ------------------------------------------------------------------
	//
	// The wallet node is an investor/observer by default.
	//
	// Miner identity must be explicitly configured by the miner startup
	// path. It must never be inferred from an arbitrary local miner.
	// ------------------------------------------------------------------

	isMiner := false
	minerID := ""

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
	}

	env, err := NewEnvelopeFromPayload(
		p.node.ProtocolVersion(),
		MsgTypeHandshake,
		h,
	)
	if err != nil {
		return fmt.Errorf("failed to create handshake envelope: %w", err)
	}

	// ------------------------------------------------------------------
	// ATTACH WALLET PUBLIC KEY
	// ------------------------------------------------------------------
	//
	// The public key is safe to transmit.
	//
	// It allows the remote node to associate the claimed wallet address
	// with its public cryptographic identity.
	//
	// The private key is never stored in Node and never transmitted.
	// ------------------------------------------------------------------

	env.PubKey = walletPublicKey

	// ------------------------------------------------------------------
	// CREATE THE EXACT CANONICAL DATA USED BY VerifyEnvelopeSignature
	// ------------------------------------------------------------------
	//
	// IMPORTANT:
	// The public key and signature themselves are NOT included in the
	// signed canonical data.
	//
	// The signature authenticates:
	//
	//   Version
	//   Type
	//   Payload
	//   Timestamp
	//   Nonce
	//
	// WalletAddress is inside Payload, therefore it is authenticated
	// by the signature.
	// ------------------------------------------------------------------

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
			"failed to marshal canonical handshake data: %w",
			err,
		)
	}

	// ------------------------------------------------------------------
	// SIGN WITH THE LOCAL WALLET
	// ------------------------------------------------------------------
	//
	// The P2P node does NOT receive the private key.
	//
	// Node.signWalletData() delegates the operation to the wallet layer.
	//
	// Only the resulting Ed25519 signature is placed into the envelope.
	// ------------------------------------------------------------------

	signature, err := p.node.signWalletData(msg)
	if err != nil {
		return fmt.Errorf(
			"failed to sign wallet handshake: %w",
			err,
		)
	}

	env.Signature = signature

	// ------------------------------------------------------------------
	// SEND SIGNED HANDSHAKE
	// ------------------------------------------------------------------

	return p.SendEnvelope(env)
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

		p.id = PeerID(remoteMinerID)
		p.handshakeDone = true

		verified := p.verifiedMiner
		minerID := p.verifiedMinerID

		p.mu.Unlock()

		if p.node != nil {
			p.node.addPeer(p)
		}

		log.Printf(
			"[p2p] 🤝 BIDIRECTIONAL HANDSHAKE SUCCESSFUL with %s (miner=%s)",
			p.addr,
			remoteMinerID,
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
	// Every other signed message prefers the authenticated wallet
	// signer. This is important because an investor wallet is a valid
	// P2P participant even when no miner exists in the local ledger.
	//
	// Private keys never enter the P2P package.
	// ================================================================

	if p.node.config.RequireSignedMessages &&
		e.Type != MsgTypeHandshake {

		signed := false

		// --------------------------------------------------------
		// 1. PREFER WALLET SIGNER
		// --------------------------------------------------------

		p.node.walletIdentityMu.RLock()

		walletPublicKey := make([]byte, len(p.node.walletPublicKey))
		copy(walletPublicKey, p.node.walletPublicKey)

		walletAddress := p.node.walletAddress

		p.node.walletIdentityMu.RUnlock()

		p.node.walletSignerMu.RLock()
		walletSignerConfigured := p.node.walletSigner != nil
		p.node.walletSignerMu.RUnlock()

		if walletSignerConfigured &&
			walletAddress != "" &&
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

			e.Signature = signature
			e.PubKey = walletPublicKey

			signed = true

			log.Printf(
				"[p2p] 🔐 message signed with wallet identity: type=%s wallet=%s",
				e.Type,
				walletAddress,
			)
		}

		// --------------------------------------------------------
		// 2. LEGACY MINER FALLBACK
		// --------------------------------------------------------
		//
		// This preserves the existing miner path temporarily.
		//
		// It is intentionally used ONLY when no wallet signer is
		// configured. It must never override an authenticated
		// wallet signer.
		// --------------------------------------------------------

		if !signed &&
			p.node.Ledger != nil {

			miners, err := p.node.Ledger.ListAllMiners()

			if err == nil && len(miners) > 0 {

				miner := &miners[0]

				if ledger.EnsureMinerSignature(miner) == nil {

					priv, _, err := ledger.DeriveMinerKey(
						miner.ID,
						miner.ConsciousnessFingerprint,
					)

					if err == nil {

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

						if err == nil {

							e.Signature = ed25519.Sign(
								priv,
								msg,
							)

							e.PubKey = miner.PubKey

							if e.Type == MsgTypeTx ||
								e.Type == MsgTypeBlock ||
								e.Type == MsgTypeAnnounceMiner ||
								e.Type == MsgTypeMetrics {

								if e.MinerInfo == nil {

									e.MinerInfo = &MinerInfo{
										MinerID:   miner.ID,
										Timestamp: e.Timestamp,
										PubKey:    miner.PubKey,
									}
								}
							}

							signed = true

							log.Printf(
								"[p2p] 🔐 message signed with legacy miner identity: type=%s miner=%s",
								e.Type,
								miner.ID,
							)
						}
					}
				}
			}
		}

		// --------------------------------------------------------
		// 3. CRITICAL MESSAGE CANNOT LEAVE UNSIGNED
		// --------------------------------------------------------

		critical :=
			e.Type == MsgTypeHandshake ||
				e.Type == MsgTypeTx ||
				e.Type == MsgTypeBlock ||
				e.Type == MsgTypeInv ||
				e.Type == MsgTypeMetrics

		if critical && !signed {

			return fmt.Errorf(
				"critical message %s cannot be sent without a valid cryptographic identity",
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

// signEnvelope signs an envelope using the miner's deterministic Ed25519 private key.
// Includes Version, Type, Payload, Timestamp, and Nonce in the signed data.
// Used for both handshake and regular messages.
func (p *Peer) signEnvelope(env *Envelope, priv ed25519.PrivateKey, miner *ledger.Miner) error {
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
		return fmt.Errorf("failed to marshal canonical data for signing: %w", err)
	}

	env.Signature = ed25519.Sign(priv, msg)
	env.PubKey = miner.PubKey
	return nil
}

// Close gracefully shuts down peer: cancels context, closes conn and waits loops.
func (p *Peer) Close() {
	p.mu.Lock()

	// idempotent guard
	if !p.connected {
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		return
	}

	p.connected = false

	// signal goroutines
	if p.cancel != nil {
		p.cancel()
	}

	// close socket once
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}

	// close sendQ to unblock writeLoop
	if p.sendQ != nil {
		close(p.sendQ)
		p.sendQ = nil
	}

	p.mu.Unlock()

	// wait loops to exit
	p.wg.Wait()
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
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
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

// readLoop continuously reads framed messages from the peer and dispatches them to handlers.
// The handshake is purely bidirectional: it is considered complete as soon as
// the remote peer's MsgTypeHandshake message is received.

func (p *Peer) readLoop() {
	defer p.wg.Done()

	conn := p.getConn()
	if conn == nil {
		return
	}

	// Use full readTimeout for initial deadline.
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
			if !errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) {
				log.Printf("[p2p] read header error from %s: %v", p.addr, err)
				p.Penalize(1, 0)
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
			log.Printf("[p2p] invalid message length %d from %s", msgLen, p.addr)
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
			if !errors.Is(err, io.EOF) &&
				!errors.Is(err, net.ErrClosed) {
				log.Printf("[p2p] read payload error from %s: %v", p.addr, err)
				p.Penalize(1, 0)
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
			log.Printf("[p2p] decode error from %s: %v", p.addr, err)
			p.Penalize(3, 0)
			continue
		}

		log.Printf("[p2p] 📨 received envelope type=%s size=%d from %s (handshakeDone=%v)",
			env.Type, len(payload), p.addr, p.handshakeDone)

		if err := ValidateEnvelope(env); err != nil {
			log.Printf("[p2p] invalid envelope from %s: %v", p.addr, err)
			// Do not ban — may be version mismatch or clock skew.
			p.Penalize(10, 0)
			continue
		}

		// ==========================================================
		// HANDSHAKE GATE
		// FIX: removed — the MsgTypeHandshake handler in node3.go
		// manages handshake ordering via handshakeOnce and handshakeDone.
		// Blocking all messages before handshake here caused the seed
		// to drop the mobile handshake silently when REQUEST_PEERS
		// arrived first in the old pipeline.
		// The node3.go handler is the single source of truth for handshake.
		// ==========================================================

		// ==========================================================
		// SIGNATURE VALIDATION
		// ==========================================================

		if criticalMessages[env.Type] {

			// Critical P2P messages MUST be cryptographically signed.
			// Missing signatures are never accepted for critical messages.
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
				"[p2p] ✅ cryptographic signature verified from %s (type=%s)",
				p.addr,
				env.Type,
			)
		}

		// ==========================================================
		// MINER INFO SPOOF PROTECTION
		// ==========================================================

		if env.MinerInfo != nil {
			if len(env.PubKey) == ed25519.PublicKeySize {
				if !bytes.Equal(env.PubKey, env.MinerInfo.PubKey) {
					log.Printf("[p2p] MinerInfo spoof attempt from %s", p.addr)
					p.Penalize(50, 24*time.Hour)
					continue
				}
			}
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
				p.Penalize(50, 24*time.Hour)
				continue
			}

			seenNonces[env.Nonce] = now
		}

		// ==========================================================
		// BLOCK VALIDATION (pre-dispatch PoW check)
		// ==========================================================

		if env.Type == MsgTypeBlock {
			var blk ledger.Block
			if err := cbor.Unmarshal(env.Payload, &blk); err != nil {
				p.Penalize(20, 1*time.Hour)
				continue
			}

			if blk.Header.DailyPoW == nil {
				p.Penalize(40, 24*time.Hour)
				continue
			}

			if !ledger.VerifyDailyPoW(
				blk.Header.MinerAddress,
				*blk.Header.DailyPoW,
				blk.Header.PrevHash,
			) {
				log.Printf("[p2p] invalid DailyPoW from %s", p.addr)
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
		// DISPATCH — all messages including HANDSHAKE go through here.
		// The MsgTypeHandshake handler in node3.go handles the full
		// handshake lifecycle: network check, on-chain verification,
		// V3 miner auth, addPeer, and close(handshakeCh).
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

// RequestBlocksRange sends a request to the remote peer for a range of blocks
// from height 'from' to 'to' (inclusive).
//
// This is a fire-and-forget operation: the function only sends the request
// envelope and returns immediately. The actual blocks are delivered asynchronously
// via the node's MsgTypeBlocksResponse handler, which processes the response
// and adds the received blocks to the local ledger.
//
// This design keeps the P2P layer non-blocking and mobile-friendly while
// allowing concurrent requests to multiple peers during ledger synchronization.
//
// Returns:
//   - nil, nil on successful enqueue of the request
//   - an error if envelope creation or sending fails
//
// RequestBlocksRange sends a GetBlocksRange request to the peer.
// Now returns ([]*ledger.Block, error) to allow synchronous use during sync,
// but remains non-blocking at network level. Response handled via node handler.
// RequestBlocksRange sends a GetBlocksRange request to the peer.
// Currently fire-and-forget (response handled asynchronously).
// Returns nil blocks to reflect current design.
func (p *Peer) RequestBlocksRange(from, to uint64) ([]*ledger.Block, error) {
	if p.node == nil {
		return nil, errors.New("no node reference")
	}

	payload := GetBlocksRangePayload{From: from, To: to}
	env, err := NewEnvelopeFromPayload(p.node.ProtocolVersion(), MsgTypeGetBlocksRange, payload)
	if err != nil {
		return nil, err
	}

	if err := p.SendEnvelope(env); err != nil {
		return nil, err
	}

	// Response arrives via node handler (MsgTypeBlocksResponse)
	return nil, nil
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
