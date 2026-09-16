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

/* -------------------------------------------------------------------------
   WATCHDOG
--------------------------------------------------------------------------- */

func (n *Node) watchdogLoop() {
	defer n.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:
			now := time.Now()

			evictBefore := now.Add(
				-n.config.PeerEvictionTimeout,
			)

			// ----------------------------------------------------------
			// 1. EVICT INACTIVE PEERS
			// ----------------------------------------------------------

			for i := range n.peerShards {
				sh := &n.peerShards[i]

				var toEvict []*Peer

				sh.mu.Lock()

				for id, p := range sh.peers {
					p.mu.RLock()
					lastSeen := p.lastSeen
					p.mu.RUnlock()

					if lastSeen.IsZero() ||
						lastSeen.Before(evictBefore) {

						delete(sh.peers, id)

						log.Printf(
							"[p2p] evicted inactive peer id=%s addr=%s",
							id,
							p.addr,
						)

						toEvict = append(
							toEvict,
							p,
						)
					}
				}

				sh.mu.Unlock()

				// Do not acquire PeersMutex while holding sh.mu.
				if len(toEvict) > 0 {
					n.PeersMutex.Lock()

					for _, p := range toEvict {
						for j, peer := range n.Peers {
							if peer == p {
								n.Peers = append(
									n.Peers[:j],
									n.Peers[j+1:]...,
								)

								break
							}
						}
					}

					n.PeersMutex.Unlock()

					for _, p := range toEvict {
						go p.Close()
					}
				}
			}

			// ----------------------------------------------------------
			// 2. ENFORCE MAXIMUM PEER CAPACITY
			// ----------------------------------------------------------

			for n.PeerCount() > n.config.MaxPeers {
				var victim *Peer
				oldest := now

				for i := range n.peerShards {
					sh := &n.peerShards[i]

					sh.mu.RLock()

					for _, p := range sh.peers {
						p.mu.RLock()
						ls := p.lastSeen
						p.mu.RUnlock()

						if ls.Before(oldest) {
							oldest = ls
							victim = p
						}
					}

					sh.mu.RUnlock()
				}

				if victim != nil {
					log.Printf(
						"[p2p] capacity eviction of peer id=%s addr=%s",
						victim.id,
						victim.addr,
					)

					n.handlePeerDisconnect(victim)
				} else {
					break
				}
			}

			// ----------------------------------------------------------
			// 3. PERIODIC BLOCK SYNCHRONIZATION
			// ----------------------------------------------------------

			newBlocks, err := n.FetchBlocks()
			if err != nil {
				log.Printf(
					"[p2p] block fetch failed: %v",
					err,
				)

				continue
			}

			for _, blk := range newBlocks {
				// Verify block signature strictly according to V3 rules.
				valid, err := blk.VerifySignature()
				if err != nil {
					log.Printf(
						"[p2p] block %d signature verification error: %v",
						blk.Header.Height,
						err,
					)

					continue
				}

				// Reject unsigned/invalid blocks in strict mode.
				if !valid && n.config.RequireStrictBlockSig {
					log.Printf(
						"[p2p] rejecting unsigned/invalid block %d (strict mode)",
						blk.Header.Height,
					)

					continue
				}

				// Accept only one block per height.
				existing, err := n.Ledger.GetBlockByHeight(
					blk.Header.Height,
				)

				if err == nil && existing != nil {
					if existing.BlockHash != blk.BlockHash {
						log.Printf(
							"[p2p] ⚠️ fork detected at height %d",
							blk.Header.Height,
						)
					}

					continue
				}

				// Attempt to add block to ledger.
				if err := n.Ledger.AddBlock(blk); err != nil {
					log.Printf(
						"[p2p] failed to apply fetched block %d: %v",
						blk.Header.Height,
						err,
					)
				} else {
					log.Printf(
						"[p2p] successfully applied fetched block %d",
						blk.Header.Height,
					)

					// Relay block through lightweight inventory announcement.
					n.BroadcastBlockInv(
						[]byte(blk.BlockHash),
						InvKindBlockFull,
					)
				}
			}
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
