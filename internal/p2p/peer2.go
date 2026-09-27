package p2p

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"explosive/internal/ledger"
)

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
