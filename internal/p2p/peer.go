// internal/p2p/peer.go
// Patched version — Assistant improvements applied.
// NOTE_FOR_AUDIT: This file has received the following concrete improvements so they are
// not unintentionally duplicated in other files:
//  - Adaptive flush interval (configurable) to reduce mobile wakeups.
//  - Read/Write deadlines on socket operations (ConnReadTimeout, ConnWriteTimeout).
//  - Exponential backoff with jitter for dialing (backoffDial).
//  - Max message size check on SendEnvelope to avoid OOM attacks.
//  - Reduced default send queue size (64) for mobile-friendly memory usage.
//  - Simple anti-abuse fields (score, banUntil, errCount) and helpers.
//  - Drain + graceful shutdown improvements in Close().
//  - Config-driven tuning points expected on NodeConfig: DialTimeout, ConnReadTimeout,
//    ConnWriteTimeout, FlushInterval, MaxMsgSize, SendQueueSize.
//  - Defensive nil-node checks; minimal behavioural changes to existing handshake.

package p2p

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"
        "explosive/internal/ledger"
)

func init() {
	// seed math/rand for jitter
	rand.Seed(time.Now().UnixNano())
}

// PeerID is a string identifier for a peer (could be hex/base58).
type PeerID string

// Peer represents a remote peer connection, its outgoing queue and lifecycle.
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
}

// NewPeer constructs a Peer object (not connected).
// It reads queue sizing from node.config.SendQueueSize.
func NewPeer(id PeerID, addr string, node *Node) *Peer {
	ctx, cancel := context.WithCancel(context.Background())
	qsize := 64 // mobile-friendly default
	if node != nil && node.config.SendQueueSize > 0 {
		qsize = node.config.SendQueueSize
	}
	return &Peer{
		id:     id,
		addr:   addr,
		node:   node,
		sendQ:  make(chan []byte, qsize),
		ctx:    ctx,
		cancel: cancel,
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
func (p *Peer) Connect() error {
	// quick check
	p.mu.RLock()
	if p.connected && p.conn != nil {
		p.mu.RUnlock()
		return nil
	}
	p.mu.RUnlock()

	// check ban
	if p.IsBanned() {
		return fmt.Errorf("peer %s is banned until %s", p.addr, p.banUntil.String())
	}

	// use context with cancel so backoffDial can observe cancellation
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()

	// try dialing with backoff
	conn, err := p.backoffDial(ctx)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.conn = conn
	p.connected = true
	p.lastSeen = time.Now()
	p.mu.Unlock()

	// start read/write loops
	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()

	// send handshake synchronously; if fails, close and return error
	if err := p.sendHandshake(); err != nil {
		p.Close()
		return err
	}

	return nil
}

// sendHandshake sends the local node's handshake to the peer.
// NOTE: Transport-level identity proofs / signature of handshake should be
// implemented at the transport or node layer. Keep handshake compact here.
func (p *Peer) sendHandshake() error {
	if p.node == nil {
		return errors.New("missing node reference")
	}
	// Use Node's internal fields (id, listenAddr, userAgent, networkID)
	h := HandshakePayload{
		PeerID:     string(p.node.id),
		ListenAddr: p.node.listenAddr,
		Version:    p.node.userAgent,
		Network:    p.node.networkID,
	}
	env, err := NewEnvelopeFromPayload(p.node.protocolVersion, MsgTypeHandshake, h)
	if err != nil {
		return err
	}
	return p.SendEnvelope(env)
}

// SendEnvelope serializes the envelope and enqueues it for sending.
// Non-blocking: when send queue is full we drop-oldest then enqueue.
func (p *Peer) SendEnvelope(e *Envelope) error {
	if p.node == nil {
		return errors.New("missing node reference")
	}
	b, err := EncodeEnvelope(e)
	if err != nil {
		return err
	}
	// enforce max message size
	max := p.node.config.MaxMsgSize
	if max <= 0 {
		max = 4 * 1024 * 1024 // sane default 4MB
	}
	if len(b) > max {
		return fmt.Errorf("message too large %d > %d", len(b), max)
	}

	// If peer closed
	select {
	case <-p.ctx.Done():
		return errors.New("peer closed")
	default:
	}

	// attempt to enqueue
	select {
	case p.sendQ <- b:
		return nil
	default:
		// try drop oldest to free slot
		select {
		case <-p.sendQ:
			// freed one slot
			select {
			case p.sendQ <- b:
				return nil
			default:
				return errors.New("send queue busy after drop")
			}
		default:
			return errors.New("send queue full")
		}
	}
}

// Close gracefully shuts down peer: cancels context, closes conn and waits loops.
func (p *Peer) Close() {
	p.mu.Lock()
	// idempotent check
	if !p.connected && p.conn == nil {
		// still cancel context to wake any waiters
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.connected = false
	p.conn = nil
	p.mu.Unlock()

	// wait loops to finish
	p.wg.Wait()

	// drain sendQ to avoid goroutine leaks on re-use
cleanup:
	for {
		select {
		case <-p.sendQ:
			// continue draining
		default:
			break cleanup
		}
	}
}

// getConn returns the underlying connection under read lock.
func (p *Peer) getConn() net.Conn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.conn
}

// readLoop reads framed messages from the peer and dispatches them to node handlers.
// Frame format: 4-byte big-endian length followed by CBOR payload.
func (p *Peer) readLoop() {
	defer p.wg.Done()
	conn := p.getConn()
	if conn == nil {
		return
	}
	r := bufio.NewReader(conn)

	for {
		// stop if requested
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// apply read deadline if configured
		if c, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			rd := 60 * time.Second
			if p.node != nil && p.node.config.ConnReadTimeout > 0 {
				rd = p.node.config.ConnReadTimeout
			}
			_ = c.SetReadDeadline(time.Now().Add(rd))
		}

		// read 4-byte length prefix
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err != io.EOF {
				log.Printf("peer %s read header error: %v", p.addr, err)
			}
			// notify node for cleanup
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}
		msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))

		// validate size
		max := 4 * 1024 * 1024
		if p.node != nil && p.node.config.MaxMsgSize > 0 {
			max = p.node.config.MaxMsgSize
		}
		if msgLen <= 0 || msgLen > max {
			log.Printf("peer %s invalid msgLen %d (max %d)", p.addr, msgLen, max)
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}

		// read payload
		payload := make([]byte, msgLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			log.Printf("peer %s read payload error: %v", p.addr, err)
			if p.node != nil {
				p.node.handlePeerDisconnect(p)
			}
			return
		}

		// decode envelope
		env, err := DecodeEnvelope(payload)
		if err != nil {
			// decode errors are not fatal by themselves
			log.Printf("peer %s decode error: %v", p.addr, err)
			continue
		}
		// basic validation
		if err := ValidateEnvelope(env); err != nil {
			log.Printf("peer %s invalid envelope: %v", p.addr, err)
			continue
		}

		// update last seen
		p.mu.Lock()
		p.lastSeen = time.Now()
		p.mu.Unlock()

		// dispatch to node (non-blocking). node.handleIncomingEnvelope will enqueue/buffer.
		if p.node != nil {
			p.node.handleIncomingEnvelope(p, env)
		}
	}
}

// writeLoop consumes sendQ and writes framed messages to the connection.
// Writes are batched and flushed periodically to increase throughput.
func (p *Peer) writeLoop() {
	defer p.wg.Done()
	conn := p.getConn()
	if conn == nil {
		return
	}
	// buffered writer with a reasonable size
	w := bufio.NewWriterSize(conn, 64*1024)
	// adaptive flush interval (configurable)
	flushInterval := 100 * time.Millisecond
	if p.node != nil && p.node.config.FlushInterval > 0 {
		flushInterval = p.node.config.FlushInterval
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	var pending [][]byte
	var pendingBytes int

	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		// ensure write deadline
		if c, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			wd := 30 * time.Second
			if p.node != nil && p.node.config.ConnWriteTimeout > 0 {
				wd = p.node.config.ConnWriteTimeout
			}
			_ = c.SetWriteDeadline(time.Now().Add(wd))
		}
		for _, b := range pending {
			ln := uint32(len(b))
			lenBuf := []byte{byte(ln >> 24), byte(ln >> 16), byte(ln >> 8), byte(ln)}
			if _, err := w.Write(lenBuf); err != nil {
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

	// protect against unbounded memory: cap batch size
	maxBatchBytes := 64 * 1024
	if p.node != nil {
		nodeMax := p.node.config.SendQueueSize * 1024
		if nodeMax > maxBatchBytes {
			maxBatchBytes = int(math.Min(float64(nodeMax), 512*1024))
		}
	}

	for {
		select {
		case <-p.ctx.Done():
			// flush then exit
			_ = flush()
			return
		case b := <-p.sendQ:
			// if peer got banned while waiting, drop messages
			if p.IsBanned() {
				// discard message silently
				continue
			}
			pending = append(pending, b)
			pendingBytes += len(b)
			// urgent flush if size limit reached
			urgentThreshold := maxBatchBytes
			if urgentThreshold <= 0 {
				urgentThreshold = 64 * 1024
			}
			if pendingBytes >= urgentThreshold || len(pending) >= 128 {
				if err := flush(); err != nil {
					log.Printf("peer %s write flush error: %v", p.addr, err)
					if p.node != nil {
						p.node.handlePeerDisconnect(p)
					}
					return
				}
			}
		case <-flushTicker.C:
			// do a periodic flush but skip when nothing to write
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

// RequestBlocksSince asks the peer for blocks starting from a specific height.
func (p *Peer) RequestBlocksSince(height uint64) ([]*ledger.Block, error) {
    // TODO: implement actual P2P request (RPC / gRPC / HTTP)
    return nil, fmt.Errorf("RequestBlocksSince not implemented")
}
