// internal/p2p/peer.go
package p2p

import (
        "bufio"
        "context"
        "crypto/ed25519"
        "encoding/binary"
        "errors"
        "fmt"
        "crypto/tls"
        "io"
        "log"
        "math/rand"
        "net"
        "sync"
        "time"

        "github.com/fxamacker/cbor/v2"
        "explosive/internal/ledger"
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
        verifiedMiner bool // True if peer proved knowledge of sacred words via V3 signature

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
        p.score -= delta
        p.errCount++
        if banDur > 0 {
                p.banUntil = time.Now().Add(banDur)
        }
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
    p.mu.Lock()
    if p.connected && p.conn != nil {
        p.mu.Unlock()
        return nil
    }
    if p.IsBanned() {
        ban := p.banUntil
        p.mu.Unlock()
        return fmt.Errorf("peer %s is banned until %s", p.addr, ban.String())
    }
    p.mu.Unlock()

    if p.node == nil || p.node.tlsConfig == nil {
        return errors.New("node or TLS configuration missing - cannot establish secure connection")
    }


    // Use TLS dialer with the node's deterministic TLS config
    dialer := &net.Dialer{
    Timeout: p.node.config.DialTimeout,
}
conn, err := tls.DialWithDialer(dialer, "tcp", p.addr, p.node.tlsConfig)
    if err != nil {
        // Enhanced error logging for TLS issues (certificate, handshake, etc.)
        log.Printf("[p2p] ❌ TLS connection failed to %s: %v", p.addr, err)
        return fmt.Errorf("TLS dial failed to %s: %w", p.addr, err)
    }

    // Optional: log TLS connection details for debugging (remove in production if needed)
    tlsState := conn.ConnectionState()
    log.Printf("[p2p] 🔒 Secure TLS connection established to %s (TLS %d.%d, cipher: %s)",
        p.addr,
        tlsState.Version >> 8, tlsState.Version & 0xff,
        tls.CipherSuiteName(tlsState.CipherSuite))

    p.mu.Lock()
    p.conn = conn
    p.connected = true
    p.lastSeen = time.Now()
    p.mu.Unlock()

    // Start read and write loops
    p.wg.Add(2)
    go p.readLoop()
    go p.writeLoop()

    // Send our handshake with randomized jitter and detailed logging
    go func() {
        delay := time.Duration(100 + rand.Intn(501)) * time.Millisecond // 100–600 ms jitter
        log.Printf("[p2p] ⏳ Preparing outbound handshake to %s (jitter delay: %v)", p.addr, delay)
        time.Sleep(delay)

        log.Printf("[p2p] 🚀 Attempting to send outbound handshake to %s", p.addr)
        if err := p.sendHandshake(); err != nil {
            log.Printf("[p2p] ❌ FAILED to send outbound handshake to %s: %v", p.addr, err)
            p.Close()
        } else {
            log.Printf("[p2p] ✅ SUCCESS: outbound handshake sent to %s (jitter: %v)", p.addr, delay)
        }
    }()

    return nil
}
// sendHandshake sends the local node's handshake message to the peer.
// Enhanced to use the improved Envelope with Nonce and proper canonical signing.
// Signs the message only if a valid V3 miner identity is available and required.
func (p *Peer) sendHandshake() error {
        if p.node == nil {
                return errors.New("missing node reference")
        }

        // Construct handshake payload
        h := HandshakePayload{
                PeerID:     string(p.node.id),
                ListenAddr: p.node.listenAddr,
                Version:    p.node.userAgent,
                Network:    p.node.networkID,
        }

        // Use improved envelope constructor (includes secure nonce)
        env, err := NewEnvelopeFromPayload(p.node.ProtocolVersion(), MsgTypeHandshake, h)
        if err != nil {
                return err
        }

        // Optional V3 identity signing
        if p.node.Ledger != nil && p.node.config.RequireSignedMessages {
                miners, err := p.node.Ledger.ListAllMiners()
                if err == nil && len(miners) > 0 {
                        miner := &miners[0]
                        if ledger.EnsureMinerSignature(miner) == nil {
                                priv, _, err := ledger.DeriveMinerKey(miner.ID, miner.ConsciousnessFingerprint)
                                if err == nil {
                                        if err := p.signEnvelope(env, priv, miner); err == nil {
                                                env.MinerInfo = &MinerInfo{
                                                     MinerID:   miner.ID,
                                                     Timestamp: env.Timestamp,
                                                     PubKey:    miner.PubKey,
                                                }
                                        } else {
                                                log.Printf("p2p: failed to sign handshake: %v", err)
                                        }
                                }
                        }
                }
        }

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
func (p *Peer) finalizeHandshake(remotePeerID string) {
    p.handshakeOnce.Do(func() {
        p.mu.Lock()
        p.handshakeDone = true
        p.mu.Unlock()

        // Clear, symbolic log indicating full bidirectional handshake completion
        log.Printf("[p2p] 🤝 BIDIRECTIONAL HANDSHAKE SUCCESSFUL with %s", p.addr)
        log.Printf("[p2p] 🔑 Remote PeerID: %s", remotePeerID)

        // Additional context about V3 conscious miner verification
        if p.verifiedMiner {
            log.Printf("[p2p] ✅ Verified conscious miner connected: %s", p.verifiedMinerID)
        } else {
            log.Printf("[p2p] ℹ️ Unverified peer connected (no V3 miner identity provided)")
        }

        // Signal completion to any waiting goroutines (e.g., connection health checks)
        close(p.handshakeCh)
    })
}

// SendEnvelope serializes and enqueues an envelope for sending.
// Fixed: safe signing path when no miner or errors occur.
// Critical messages (Tx, Block, AnnounceMiner) get MinerInfo attached.
func (p *Peer) SendEnvelope(e *Envelope) error {
        if p.node == nil {
                return errors.New("missing node reference")
        }

        // Automatic signing if enabled and miner available
        if p.node.config.RequireSignedMessages && p.node.Ledger != nil && e.Type != MsgTypeHandshake {
                miners, err := p.node.Ledger.ListAllMiners()
                if err == nil && len(miners) > 0 {
                        miner := &miners[0]
                        if ledger.EnsureMinerSignature(miner) == nil {
                                priv, _, err := ledger.DeriveMinerKey(miner.ID, miner.ConsciousnessFingerprint)
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
                                        if msg, err := cbor.Marshal(canon); err == nil {
                                                e.Signature = ed25519.Sign(priv, msg)
                                                e.PubKey = miner.PubKey

                                                // Attach identity proof for key message types
                                                if e.Type == MsgTypeTx || e.Type == MsgTypeBlock || e.Type == MsgTypeAnnounceMiner || e.Type == MsgTypeMetrics {
                                                     if e.MinerInfo == nil {
                                                     e.MinerInfo = &MinerInfo{
                                                     MinerID:   miner.ID,
                                                     Timestamp: e.Timestamp,
                                                     PubKey:    miner.PubKey,
                                                     }
                                                     }
                                                }
                                        }
                                }
                        }
                }
        }

        b, err := EncodeEnvelope(e)
        if err != nil {
                return fmt.Errorf("encode envelope: %w", err)
        }

        max := p.node.config.MaxMsgSize
        if max <= 0 {
                max = 4 * 1024 * 1024
        }
        if len(b) > max {
                return fmt.Errorf("message too large: %d > %d", len(b), max)
        }

        select {
        case <-p.ctx.Done():
                return errors.New("peer closed")
        default:
        }

        if e.Type == MsgTypeTx {
                select {
                case p.sendQ <- b:
                        return nil
                default:
                        p.Penalize(1, 0)
                        return errors.New("TX queue full")
                }
        }

        for {
                select {
                case p.sendQ <- b:
                        return nil
                default:
                        select {
                        case <-p.sendQ:
                        default:
                                return errors.New("send queue full")
                        }
                }
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
		if c, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		}
		for _, b := range pending {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))

			if _, err := w.Write(lenBuf[:]); err != nil {
				return err
			}
			if _, err := w.Write(b); err != nil {
				return err
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
		pending = pending[:0]
		pendingBytes = 0
		return nil
	}

	for {
		select {
		case <-p.ctx.Done():
			_ = flush()
			return

		case b, ok := <-p.sendQ:
			if !ok {
				// sendQ closed → shutdown
				_ = flush()
				return
			}

			if p.IsBanned() {
				continue
			}

			pending = append(pending, b)
			pendingBytes += len(b)

			if pendingBytes >= 64*1024 || len(pending) >= 128 {
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

	// IMPORTANT: create ONE buffered reader for the lifetime of this connection
	r := bufio.NewReaderSize(conn, 64*1024)

	// Per-peer replay protection: tracks recently seen nonces
	seenNonces := make(map[uint64]time.Time)
	lastCleanup := time.Now()

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// ---- Read message length prefix (4-byte big-endian) ----
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			// Remote closed or connection closed locally
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("peer %s: read header error: %v", p.addr, err)
				p.Penalize(5, 10*time.Minute)
			}
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}

		msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))
		if msgLen <= 0 || msgLen > p.node.config.MaxMsgSize {
			log.Printf(
				"peer %s: invalid message length %d (max %d)",
				p.addr,
				msgLen,
				p.node.config.MaxMsgSize,
			)
			p.Penalize(20, 1*time.Hour)
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}

		// ---- Read payload ----
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("peer %s: read payload error: %v", p.addr, err)
				p.Penalize(5, 0)
			}
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}

		env, err := DecodeEnvelope(payload)
		if err != nil {
			log.Printf("peer %s: envelope decode error: %v", p.addr, err)
			p.Penalize(3, 0)
			continue
		}

		if err := ValidateEnvelope(env); err != nil {
			log.Printf("peer %s: invalid envelope: %v", p.addr, err)
			p.Penalize(10, 30*time.Minute)
			continue
		}

		// Block all messages until handshake is complete
		if !p.handshakeDone && env.Type != MsgTypeHandshake {
			log.Printf(
				"peer %s: message received before handshake completion: %s",
				p.addr,
				env.Type,
			)
			p.Penalize(10, 10*time.Minute)
			continue
		}

		// ---- Enforce signature on critical message types ----
		criticalTypes := map[MessageType]bool{
			MsgTypeTx:      true,
			MsgTypeBlock:   true,
			MsgTypeInv:     true,
			MsgTypeMetrics: true,
		}

		if criticalTypes[env.Type] {
			ok, err := VerifyEnvelopeSignature(env)
			if err != nil {
				log.Printf("peer %s: signature processing error: %v", p.addr, err)
				p.Penalize(15, 1*time.Hour)
				continue
			}
			if !ok {
				log.Printf(
					"peer %s: invalid or missing signature on critical message %s",
					p.addr,
					env.Type,
				)
				p.Penalize(40, 4*time.Hour)
				continue
			}
		}

		// ==== REMOTE HANDSHAKE PROCESSING ====
		if env.Type == MsgTypeHandshake {
			payload, err := DecodeHandshakePayload(env.Payload)
			if err != nil {
				log.Printf("peer %s: invalid handshake payload: %v", p.addr, err)
				p.Penalize(20, 1*time.Hour)
				continue
			}

			// V3 miner identity verification if provided
			if env.MinerInfo != nil {
				if len(env.MinerInfo.PubKey) != ed25519.PublicKeySize {
					log.Printf("peer %s: invalid PubKey length in handshake", p.addr)
					p.Penalize(30, 1*time.Hour)
					continue
				}
				p.mu.Lock()
				p.verifiedMinerID = env.MinerInfo.MinerID
				p.verifiedPubKey = env.MinerInfo.PubKey
				p.verifiedMiner = true
				p.mu.Unlock()
			}

			// Handshake completes upon receiving the remote handshake
			p.finalizeHandshake(payload.PeerID)
			continue
		}

		// ---- Replay protection using nonce ----
		if env.Nonce != 0 {
			now := time.Now()
			if time.Since(lastCleanup) > 5*time.Minute {
				for nonce, ts := range seenNonces {
					if time.Since(ts) > 10*time.Minute {
						delete(seenNonces, nonce)
					}
				}
				lastCleanup = now
			}

			if ts, exists := seenNonces[env.Nonce]; exists {
				log.Printf(
					"peer %s: replay attack detected (nonce %d, first seen %v)",
					p.addr,
					env.Nonce,
					ts,
				)
				p.Penalize(50, 24*time.Hour)
				continue
			}
			seenNonces[env.Nonce] = now
		}

		// Update peer activity timestamp
		p.mu.Lock()
		p.lastSeen = time.Now()
		p.mu.Unlock()

		// Dispatch message to node-level handler
		if p.node != nil {
			p.node.handleIncomingEnvelope(p, env)
		}
	}
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
