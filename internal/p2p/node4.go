// internal/p2p/node4.go
package p2p

import (
	"context"
	"log"
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
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:
			// A Peer represents one connection session.
			// A closed session must never be reused for reconnection.
			n.PeersMutex.RLock()

			addresses := make([]string, 0, len(n.Peers))

			for _, p := range n.Peers {
				if p == nil {
					continue
				}

				if p.IsConnected() {
					continue
				}

				addr := strings.TrimSpace(p.addr)
				if addr == "" {
					continue
				}

				addresses = append(addresses, addr)
			}

			n.PeersMutex.RUnlock()

			// Create a completely new Peer session for every
			// disconnected peer address.
			for _, addr := range addresses {
				addr := addr

				go func() {
					peer := NewPeer("", addr, n)

					if err := peer.Connect(); err != nil {
						log.Printf(
							"[p2p] ⚠️ failed to reconnect to %s: %v",
							addr,
							err,
						)
						return
					}

					log.Printf(
						"[p2p] 🔄 new P2P session created for %s",
						addr,
					)
				}()
			}
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
