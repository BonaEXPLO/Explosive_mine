// internal/p2p/node4.go
package p2p

import (
	"context"
	"log"
	"math/rand"
	"strings"
	"time"
)

/*
	-------------------------------------------------------------------------
	  Deterministic port derivation helpers
	  - These helpers are intentionally non-invasive: they do not change Node
	    constructors or startup flow. Call ApplyDerivedListenAddrToNode(n, id, words)                               after restoring the miner identity to set the derived listen address.
	  - Default port range: [31000, 61000]

---------------------------------------------------------------------------
*/
const (
	defaultMinPort = 31000
	defaultMaxPort = 61000
)

// ProtocolVersion returns the node's protocol version.
func (n *Node) ProtocolVersion() uint16 {
	return n.protocolVersion
}

// normalizeAndJoinWords does light normalized join of 4 sacred words.
// It trims spaces and collapses internal whitespace, then joins with '-'.
func normalizeAndJoinWords(words []string) string {
	parts := make([]string, 0, len(words))
	for _, w := range words {
		s := strings.TrimSpace(w)
		// collapse internal runs of spaces to one space
		s = strings.Join(strings.Fields(s), " ")
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

func (n *Node) PeerReconnectLoop() {
	if n == nil {
		return
	}

	// Mobile peers may remain unreachable for days, weeks,
	// or months. Reconnection therefore has no maximum number
	// of attempts and no offline expiration.
	const (
		initialBackoff = 30 * time.Second
		maxBackoff     = 24 * time.Hour
		scanInterval   = 30 * time.Second
	)

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	// Reconnection state is maintained independently from peer identity.
	//
	// A peer address is only a locator.
	// The WalletAddress / PeerID remains the permanent identity.
	nextRetry := make(map[string]time.Time)
	attempts := make(map[string]uint64)

	// Prevent multiple replacement sessions from being created for
	// the same locator while a previous connection is still alive.
	inFlight := make(map[string]*Peer)

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:
		}

		now := time.Now()

		// ------------------------------------------------------------
		// CLEAN UP COMPLETED RECONNECTION SESSIONS
		// ------------------------------------------------------------

		for addr, peer := range inFlight {
			if peer == nil || !peer.IsConnected() {
				delete(inFlight, addr)
			}
		}

		// ------------------------------------------------------------
		// COLLECT DISCONNECTED PEER LOCATORS
		// ------------------------------------------------------------

		n.PeersMutex.RLock()

		addresses := make([]string, 0, len(n.Peers))

		for _, p := range n.Peers {
			if p == nil {
				continue
			}

			if p.IsConnected() {
				continue
			}

			addr := strings.TrimSpace(p.Addr())
			if addr == "" {
				continue
			}

			// Do not create another session while a replacement
			// session for this locator is already active.
			if _, exists := inFlight[addr]; exists {
				continue
			}

			// Respect the current retry schedule.
			if retryAt, exists := nextRetry[addr]; exists {
				if now.Before(retryAt) {
					continue
				}
			}

			addresses = append(addresses, addr)
		}

		n.PeersMutex.RUnlock()

		// ------------------------------------------------------------
		// START NEW MOBILE SESSIONS
		// ------------------------------------------------------------

		for _, addr := range addresses {
			addr := addr

			// Double-check the in-flight state because another
			// address may have been discovered more than once
			// during the same scan.
			if _, exists := inFlight[addr]; exists {
				continue
			}

			attempts[addr]++
			attempt := attempts[addr]

			// Exponential backoff:
			//
			// attempt 1 -> 30s
			// attempt 2 -> 1m
			// attempt 3 -> 2m
			// ...
			// eventually -> 24h
			backoff := initialBackoff

			for i := uint64(1); i < attempt; i++ {
				if backoff >= maxBackoff {
					backoff = maxBackoff
					break
				}

				backoff *= 2

				if backoff >= maxBackoff {
					backoff = maxBackoff
					break
				}
			}

			// Add up to 25% jitter.
			// This prevents a large mobile population from
			// reconnecting simultaneously.
			jitterRange := backoff / 4
			var jitter time.Duration

			if jitterRange > 0 {
				jitter = time.Duration(
					rand.Int63n(int64(jitterRange)),
				)
			}

			nextRetry[addr] = now.Add(backoff + jitter)

			// Create a completely new Peer session.
			//
			// The old Peer may have been disconnected for a long
			// time. It is never reused.
			peer := NewPeer("", addr, n)

			inFlight[addr] = peer

			log.Printf(
				"[p2p] 📱 mobile reconnect attempt #%d to %s",
				attempt,
				addr,
			)

			go func() {
				if err := peer.Connect(); err != nil {
					log.Printf(
						"[p2p] 📱 reconnect attempt #%d to %s failed: %v",
						attempt,
						addr,
						err,
					)

					// Network failure is not peer misbehavior.
					//
					// Do NOT call Penalize().
					peer.Close()
					return
				}

				log.Printf(
					"[p2p] 🔄 new P2P session established to %s; awaiting HANDSHAKE",
					addr,
				)

				// Keep this locator marked as in-flight while the
				// newly-created session is alive.
				//
				// Connect() starts the handshake asynchronously.
				// We therefore wait until the session actually ends.
				for {
					select {
					case <-n.ctx.Done():
						peer.Close()
						return

					case <-time.After(30 * time.Second):
						if !peer.IsConnected() {
							return
						}
					}
				}
			}()
		}
	}
}

// SendKnownPeers sends a list of known connected peers to the requesting peer.
func (n *Node) SendKnownPeers(p *Peer) {
	addrs := make([]string, 0, 32)

	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		for _, peer := range sh.peers {
			if peer.IsConnected() && peer != p && peer.addr != n.listenAddr {
				addrs = append(addrs, peer.addr)
			}
		}
		sh.mu.RUnlock()
	}

	if len(addrs) == 0 {
		return
	}

	env, _ := NewEnvelopeFromPayload(n.protocolVersion, MsgTypePeers, PeersPayload{Addrs: addrs})
	_ = p.SendEnvelope(env)
}

// SyncLedgerFromBestPeer starts one asynchronous ledger synchronization
// session using the connected peer that advertises the highest chain height.
//
// The synchronization protocol is:
//
//	GETBLOCKSRANGE -> BLOCKSRESPONSE -> AddBlock
//	                     |
//	                     +-> next GETBLOCKSRANGE
//
// Only one synchronization session may run at a time.
// BLOCKSRESPONSE is responsible for continuing the session asynchronously.
func (n *Node) SyncLedgerFromBestPeer(ctx context.Context) {
	if n == nil || n.Ledger == nil {
		log.Println("[p2p] ⚠️ Cannot synchronize: ledger not initialized")
		return
	}

	if ctx == nil {
		ctx = n.ctx
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// ------------------------------------------------------------
	// 1. Acquire the global synchronization session.
	// ------------------------------------------------------------

	n.syncMu.Lock()

	if n.syncRunning {
		activePeer := n.syncPeer
		var activeAddr string

		if activePeer != nil {
			activeAddr = activePeer.Addr()
		}

		n.syncMu.Unlock()

		log.Printf(
			"[p2p] ⏳ Ledger synchronization already running with %s",
			activeAddr,
		)

		return
	}

	n.syncRunning = true
	n.syncPeer = nil
	n.syncTarget = 0

	n.syncMu.Unlock()

	// ------------------------------------------------------------
	// 2. Cancel safely before selecting a peer.
	// ------------------------------------------------------------

	select {
	case <-ctx.Done():
		n.syncMu.Lock()
		n.syncRunning = false
		n.syncPeer = nil
		n.syncTarget = 0
		n.syncMu.Unlock()

		log.Println("[p2p] ⛔ Ledger synchronization cancelled")
		return

	default:
	}

	// ------------------------------------------------------------
	// 3. Snapshot the currently known peers.
	// ------------------------------------------------------------

	peers := n.AllPeers()

	var bestPeer *Peer
	var bestHeight uint64

	localHeight := n.Ledger.GetLatestBlockHeight()

	for _, p := range peers {
		if p == nil {
			continue
		}

		if !p.IsConnected() || p.IsBanned() {
			continue
		}

		p.mu.RLock()
		peerHeight := p.LatestHeight
		peerID := p.id
		p.mu.RUnlock()

		if peerID == "" {
			continue
		}

		if peerHeight <= localHeight {
			continue
		}

		if bestPeer == nil || peerHeight > bestHeight {
			bestPeer = p
			bestHeight = peerHeight
		}
	}

	// ------------------------------------------------------------
	// 4. No peer has a longer chain.
	// ------------------------------------------------------------

	if bestPeer == nil {
		n.syncMu.Lock()
		n.syncRunning = false
		n.syncPeer = nil
		n.syncTarget = 0
		n.syncMu.Unlock()

		log.Println(
			"[p2p] ⚠️ No suitable peer found for ledger synchronization",
		)

		return
	}

	// ------------------------------------------------------------
	// 5. Register the selected synchronization peer.
	// ------------------------------------------------------------

	n.syncMu.Lock()
	n.syncPeer = bestPeer
	n.syncTarget = bestHeight
	n.syncMu.Unlock()

	// ------------------------------------------------------------
	// 6. Calculate the first synchronization segment.
	// ------------------------------------------------------------

	from := localHeight + 1
	to := from + 49

	if to > bestHeight {
		to = bestHeight
	}

	log.Printf(
		"[p2p] ⏳ Starting ledger synchronization: local=%d target=%d peer=%s",
		localHeight,
		bestHeight,
		bestPeer.Addr(),
	)

	// ------------------------------------------------------------
	// 7. Send the first asynchronous block-range request.
	// ------------------------------------------------------------

	if err := bestPeer.requestBlocksRange(from, to); err != nil {
		n.syncMu.Lock()
		n.syncRunning = false
		n.syncPeer = nil
		n.syncTarget = 0
		n.syncMu.Unlock()

		log.Printf(
			"[p2p] ⚠️ Failed to start ledger synchronization with %s: %v",
			bestPeer.Addr(),
			err,
		)

		return
	}

	log.Printf(
		"[p2p] 📥 Initial sync request sent: blocks %d-%d from %s",
		from,
		to,
		bestPeer.Addr(),
	)
}

func (n *Node) StartSeedMode() {
	n.config.IsSeedNode = true
	log.Println("🌱 Seed mode enabled: responding with peer lists.")
}

func (n *Node) AllPeers() []*Peer {
	n.PeersMutex.RLock()
	defer n.PeersMutex.RUnlock()
	return append([]*Peer(nil), n.Peers...)
}

func (n *Node) IsLedgerComplete() bool {
	if n.PeerCount() == 0 || n.Ledger == nil {
		return false
	}

	n.PeersMutex.RLock()
	defer n.PeersMutex.RUnlock()

	highest := n.Ledger.GetLatestBlockHeight()
	for _, p := range n.Peers {
		p.mu.RLock()
		peerHeight := p.LatestHeight
		p.mu.RUnlock()
		if peerHeight > highest {
			return false
		}
	}
	return true
}
