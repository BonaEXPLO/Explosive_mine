package p2p

import (
	"crypto/rand"
	"log"
	"math/big"
	"sync"
	"time"

	"explosive/internal/ledger"
	"github.com/fxamacker/cbor/v2"
)

/* -------------------------------------------------------------------------
   GLOBAL BROADCAST WORKER POOL (anti goroutine explosion)
--------------------------------------------------------------------------- */

var broadcastQueue = make(chan func(), 2048)
var broadcastOnce sync.Once

func startBroadcastWorkers() {
	broadcastOnce.Do(func() {
		workers := 8 // mobile-friendly

		for i := 0; i < workers; i++ {
			go func() {
				for job := range broadcastQueue {
					job()
				}
			}()
		}
	})
}

/* -------------------------------------------------------------------------
   SECURE RANDOM SHUFFLE
--------------------------------------------------------------------------- */

func secureShuffle(peers []*Peer) {
	for i := len(peers) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}

		j := int(jBig.Int64())
		peers[i], peers[j] = peers[j], peers[i]
	}
}

/* -------------------------------------------------------------------------
   BROADCAST
--------------------------------------------------------------------------- */

func (n *Node) Broadcast(e *Envelope) {
	if e == nil {
		return
	}

	startBroadcastWorkers()

	max := n.config.MaxBroadcastFanout
	if max <= 0 {
		return
	}

	for i := range n.peerShards {
		sh := &n.peerShards[i]

		sh.mu.RLock()

		peers := make([]*Peer, 0, len(sh.peers))

		for _, p := range sh.peers {
			if p != nil && p.IsConnected() && !p.IsBanned() {
				peers = append(peers, p)
			}
		}

		sh.mu.RUnlock()

		if len(peers) == 0 {
			continue
		}

		secureShuffle(peers)

		sent := 0

		for _, p := range peers {
			if sent >= max {
				break
			}

			peer := p

			select {
			case broadcastQueue <- func() {
				if err := peer.SendEnvelope(e); err != nil {
					log.Printf(
						"[p2p] ⚠️ broadcast send failed to %s: %v",
						peer.addr,
						err,
					)
				}
			}:
			default:
				log.Printf(
					"[p2p] ⚠️ broadcast queue full, dropping message",
				)
			}

			sent++
		}
	}
}

/* -------------------------------------------------------------------------
   INCOMING ENVELOPE PIPELINE

   IMPORTANT:
   HANDSHAKE IS NOT SPECIAL-CASED HERE.

   All envelopes, including HANDSHAKE, enter the normal inbound pipeline.
   The authoritative HANDSHAKE handler is registered in node3.go.

   The only dispatcher is processIncoming() in node.go.
--------------------------------------------------------------------------- */

func (n *Node) handleIncomingEnvelope(p *Peer, e *Envelope) {
	if e == nil || p == nil {
		return
	}

	now := time.Now()

	// ------------------------------------------------------------------
	// RATE LIMIT
	// ------------------------------------------------------------------

	lastAny, _ := n.peerLastMsg.LoadOrStore(p.id, now)
	last := lastAny.(time.Time)

	scoreAny, _ := n.peerSpamScore.LoadOrStore(p.id, 0)
	score := scoreAny.(int)

	if now.Sub(last) < 10*time.Millisecond {
		score++

		if score > 50 {
			n.peerSpamScore.Store(p.id, score)
			p.Penalize(50, time.Hour)
			return
		}
	} else if score > 0 {
		score--
	}

	n.peerLastMsg.Store(p.id, now)
	n.peerSpamScore.Store(p.id, score)

	// ------------------------------------------------------------------
	// GLOBAL REPLAY PROTECTION
	// ------------------------------------------------------------------

	if e.Nonce != 0 {
		n.seenNoncesMutex.Lock()

		if time.Since(n.lastNonceCleanup) > 5*time.Minute {
			n.seenNonces.Range(func(key, value interface{}) bool {
				if time.Since(value.(time.Time)) > 10*time.Minute {
					n.seenNonces.Delete(key)
				}

				return true
			})

			n.lastNonceCleanup = now
		}

		if ts, loaded := n.seenNonces.LoadOrStore(e.Nonce, now); loaded {
			n.seenNoncesMutex.Unlock()

			log.Printf(
				"p2p: replay attack detected nonce=%d seen at %v",
				e.Nonce,
				ts,
			)

			p.Penalize(70, 48*time.Hour)
			return
		}

		n.seenNoncesMutex.Unlock()
	}

	// ------------------------------------------------------------------
	// BLOCK VALIDATION
	// ------------------------------------------------------------------

	if e.Type == MsgTypeBlock {
		var blk ledger.Block

		if err := cbor.Unmarshal(e.Payload, &blk); err != nil {
			log.Printf(
				"p2p: invalid block payload: %v",
				err,
			)

			p.Penalize(20, time.Hour)
			return
		}

		var prevHash string

		if blk.Header.Height > 0 {
			if prev, err := n.Ledger.GetBlockByHeight(
				blk.Header.Height - 1,
			); err == nil && prev != nil {
				prevHash = prev.BlockHash
			}
		}

		if blk.Header.DailyPoW != nil {
			if !ledger.VerifyDailyPoW(
				blk.Header.MinerAddress,
				*blk.Header.DailyPoW,
				prevHash,
			) {
				log.Printf(
					"p2p: invalid DailyPoW height=%d miner=%s",
					blk.Header.Height,
					blk.Header.MinerAddress,
				)

				p.Penalize(60, 3*time.Hour)
				return
			}
		}
	}

	// ------------------------------------------------------------------
	// QUEUE
	// ------------------------------------------------------------------

	msg := &incomingMsg{
		peer: p,
		env:  e,
	}

	select {
	case n.inboundCh <- msg:

	default:
		select {
		case <-n.inboundCh:
			n.inboundCh <- msg

		default:
			log.Printf(
				"[p2p] ⚠️ inbound channel full, dropping message",
			)
		}
	}
}

/* -------------------------------------------------------------------------
   HANDLER REGISTRATION

   processIncoming() in node.go is the single message dispatcher.
--------------------------------------------------------------------------- */

func (n *Node) RegisterHandler(
	mt MessageType,
	fn func(*Peer, *Envelope),
) {
	n.handlerMux.Lock()
	n.handlers[mt] = fn
	n.handlerMux.Unlock()
}

/* -------------------------------------------------------------------------
   PEER LIST
--------------------------------------------------------------------------- */

func (n *Node) ListPeers() map[PeerID]string {
	out := map[PeerID]string{}

	for i := range n.peerShards {
		sh := &n.peerShards[i]

		sh.mu.RLock()

		for id, p := range sh.peers {
			out[id] = p.addr
		}

		sh.mu.RUnlock()
	}

	return out
}

// -------------------------------------------------------------------------
// PEER DISCONNECT
// -------------------------------------------------------------------------

func (n *Node) handlePeerDisconnect(p *Peer) {
	if p == nil {
		return
	}

	// Capture the session identity and address before modifying
	// the peer state or removing the session from the node.
	p.mu.RLock()
	peerID := p.id
	peerAddr := p.addr
	p.mu.RUnlock()

	// Stop the current session.
	//
	// Close() is intentionally non-blocking: this function may be
	// called from readLoop() or writeLoop(), so waiting for the
	// WaitGroup here could deadlock the current worker.
	p.Close()

	// Remove this exact session from its shard.
	if peerID != "" {
		sh := n.shard(peerID)

		sh.mu.Lock()

		if existing, ok := sh.peers[peerID]; ok && existing == p {
			delete(sh.peers, peerID)
		}

		sh.mu.Unlock()
	}

	// Remove this exact session from the global active-peer list.
	n.PeersMutex.Lock()

	for i := 0; i < len(n.Peers); {
		if n.Peers[i] == p {
			n.Peers = append(
				n.Peers[:i],
				n.Peers[i+1:]...,
			)
			continue
		}

		i++
	}

	n.PeersMutex.Unlock()

	log.Printf(
		"[p2p] peer session disconnected: id=%s addr=%s",
		peerID,
		peerAddr,
	)
}

func (n *Node) watchdogLoop() {
	defer n.wg.Done()

	// Mobile heartbeat interval.
	//
	// This is a session-liveness mechanism only.
	// Missing PONGs never modify peer reputation.
	const pingInterval = 1 * time.Minute

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:

			// ------------------------------------------------------------------
			// 1. SEND MOBILE HEARTBEATS
			// ------------------------------------------------------------------
			//
			// A heartbeat is sent only to an active authenticated session.
			//
			// The permanent peer identity is not affected by heartbeat state.
			// A peer may disappear from the network for an unlimited period.

			for i := range n.peerShards {
				sh := &n.peerShards[i]

				sh.mu.RLock()

				peers := make([]*Peer, 0, len(sh.peers))

				for _, p := range sh.peers {
					if p == nil {
						continue
					}

					p.mu.RLock()

					connected := p.connected && p.conn != nil
					handshakeDone := p.handshakeDone
					peerID := p.id
					peerAddr := p.addr

					p.mu.RUnlock()

					if !connected || !handshakeDone || peerID == "" {
						continue
					}

					peers = append(peers, p)

					log.Printf(
						"[p2p] 💓 scheduling mobile heartbeat to %s (%s)",
						peerID,
						peerAddr,
					)
				}

				sh.mu.RUnlock()

				for _, p := range peers {
					if p == nil {
						continue
					}

					// The session may have disappeared after the shard
					// lock was released.
					if !p.IsConnected() {
						continue
					}

					nonce := p.nextPingNonce()

					if nonce == 0 {
						continue
					}

					p.registerPing(nonce)

					ping := PingPayload{
						Nonce: nonce,
					}

					env, err := NewEnvelopeFromPayload(
						n.protocolVersion,
						MsgTypePing,
						ping,
					)

					if err != nil {
						log.Printf(
							"[p2p] ⚠️ failed to create PING for %s: %v",
							p.Addr(),
							err,
						)
						continue
					}

					if err := p.SendEnvelope(env); err != nil {
						// Sending failure is a network-session event.
						// It is NOT a reputation violation.
						log.Printf(
							"[p2p] ⚠️ PING send failed to %s: %v",
							p.Addr(),
							err,
						)
						continue
					}

					log.Printf(
						"[p2p] 💓 PING sent to %s nonce=%d",
						p.Addr(),
						nonce,
					)
				}
			}

			// ------------------------------------------------------------------
			// 2. PEER CAPACITY MANAGEMENT
			// ------------------------------------------------------------------
			//
			// Capacity management is a resource constraint.
			// It is never a reputation decision.
			//
			// Disconnected sessions are removed first.
			// Connected sessions are considered only when the node is
			// actually above MaxPeers.

			maxPeers := n.config.MaxPeers

			if maxPeers > 0 {
				for n.PeerCount() > maxPeers {

					var victim *Peer
					var disconnectedVictim *Peer

					var oldest time.Time
					var oldestDisconnected time.Time

					now := time.Now()

					oldest = now
					oldestDisconnected = now

					for i := range n.peerShards {
						sh := &n.peerShards[i]

						sh.mu.RLock()

						for _, p := range sh.peers {
							if p == nil {
								continue
							}

							p.mu.RLock()

							connected := p.connected && p.conn != nil
							lastSeen := p.lastSeen

							p.mu.RUnlock()

							if !connected {
								if disconnectedVictim == nil ||
									lastSeen.Before(oldestDisconnected) {

									oldestDisconnected = lastSeen
									disconnectedVictim = p
								}

								continue
							}

							if victim == nil ||
								lastSeen.Before(oldest) {

								oldest = lastSeen
								victim = p
							}
						}

						sh.mu.RUnlock()
					}

					if disconnectedVictim != nil {
						log.Printf(
							"[p2p] capacity cleanup: removing disconnected session id=%s addr=%s",
							disconnectedVictim.ID(),
							disconnectedVictim.Addr(),
						)

						// Capacity cleanup is not punishment.
						n.handlePeerDisconnect(disconnectedVictim)
						continue
					}

					if victim != nil {
						log.Printf(
							"[p2p] capacity cleanup: removing connected session id=%s addr=%s",
							victim.ID(),
							victim.Addr(),
						)

						// Capacity eviction is NOT a reputation penalty.
						// The permanent peer identity remains valid.
						n.handlePeerDisconnect(victim)
						continue
					}

					break
				}
			}

			// ------------------------------------------------------------------
			// 3. NO INACTIVITY PENALTY
			// ------------------------------------------------------------------
			//
			// IMPORTANT:
			//
			// We intentionally do NOT:
			//
			//   - inspect lastSeen and punish old timestamps
			//   - punish missing PONGs
			//   - ban silent peers
			//   - delete permanent peer identity because of inactivity
			//
			// TCP/readLoop handles the current session.
			// PeerReconnectLoop creates a new session when connectivity
			// becomes available again.
			//
			// Offline duration is therefore irrelevant to reputation.

			// ------------------------------------------------------------------
			// 4. BLOCKCHAIN SYNCHRONIZATION
			// ------------------------------------------------------------------
			//
			// Blockchain synchronization remains completely independent
			// from heartbeat/liveness.
			//
			// It is handled by:
			//
			//   SyncLedgerFromBestPeer()
			//   startLightSyncCycles()
			//   GETBLOCKSRANGE
			//   BLOCKSRESPONSE
		}
	}
}

/* -------------------------------------------------------------------------
   BLOCK INVENTORY BROADCAST
--------------------------------------------------------------------------- */

// BroadcastBlockInv announces a new block via lightweight inventory.
// Peers request the full block only if needed.
func (n *Node) BroadcastBlockInv(
	blockHash []byte,
	kind string,
) {
	if len(blockHash) == 0 {
		return
	}

	if kind != InvKindBlockFull &&
		kind != InvKindBlockHeader {
		return
	}

	hashes := [][]byte{blockHash}

	invEnv, err := NewInvMessage(
		kind,
		hashes,
	)

	if err != nil {
		log.Printf(
			"[p2p] failed to create INV: %v",
			err,
		)

		return
	}

	n.Broadcast(invEnv)

	log.Printf(
		"[p2p] 📢 INV (%s) %x",
		kind,
		blockHash[:8],
	)
}
