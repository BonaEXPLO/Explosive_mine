// internal/p2p/node4.go
package p2p
import (
        "context"
        "fmt"
        "log"
        "strings"
        "sync"
        "time"
        "explosive/internal/ledger"
)

/* -------------------------------------------------------------------------
   Deterministic port derivation helpers
   - These helpers are intentionally non-invasive: they do not change Node
     constructors or startup flow. Call ApplyDerivedListenAddrToNode(n, id, words)                               after restoring the miner identity to set the derived listen address.
   - Default port range: [31000, 61000]
--------------------------------------------------------------------------- */
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
            n.PeersMutex.RLock()
            peersCopy := append([]*Peer(nil), n.Peers...)
            n.PeersMutex.RUnlock()
            for _, p := range peersCopy {
                if !p.IsConnected() {
                    go func(peer *Peer) {
                        if err := peer.Connect(); err != nil {
                            log.Printf("⚠️ failed to reconnect to %s: %v", peer.addr, err)
                        } else {
                            log.Printf("🔄 reconnected to peer %s", peer.addr)
                        }
                    }(p)
                }
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

// SyncLedgerFromBestPeer synchronizes the local ledger with the peer
// having the highest known block height. Supports parallel fetching,
// retry with exponential backoff, ordered insertion, and graceful cancellation.

func (n *Node) SyncLedgerFromBestPeer(ctx context.Context) {
	// 0️⃣ Snapshot peers safely.
	n.PeersMutex.RLock()
	peersCopy := append([]*Peer(nil), n.Peers...)
	n.PeersMutex.RUnlock()

	if len(peersCopy) == 0 {
		log.Println("[p2p] ⚠️ No peers available for sync")
		return
	}

	// 1️⃣ Identify peer with highest block height.
	var bestPeer *Peer
	maxHeight := uint64(0)
	for _, p := range peersCopy {
		if !p.IsConnected() {
			continue
		}
		p.mu.RLock()
		height := p.LatestHeight
		p.mu.RUnlock()
		if height > maxHeight {
			maxHeight = height
			bestPeer = p
		}
	}

	if bestPeer == nil {
		log.Println("[p2p] ⚠️ No suitable peer found for sync")
		return
	}

	// 2️⃣ Current ledger height.
	nextHeight := n.Ledger.GetLatestBlockHeight() + 1
	if nextHeight > maxHeight {
		log.Println("[p2p] ✅ Ledger is already up-to-date")
		return
	}

	log.Printf("[p2p] ⏳ Syncing blocks from height %d to %d", nextHeight, maxHeight)

	// 3️⃣ Prepare segments.
	const segmentSize = 50
	const maxRetries = 3
	var segments [][2]uint64
	for s := nextHeight; s <= maxHeight; s += segmentSize {
		segEnd := s + segmentSize - 1
		if segEnd > maxHeight {
			segEnd = maxHeight
		}
		segments = append(segments, [2]uint64{s, segEnd})
	}

	// 4️⃣ Channels & concurrency.
	blockCh := make(chan *ledger.Block, segmentSize*len(segments))
	errCh := make(chan error, len(segments))
	concurrencyLimit := 5
	sem := make(chan struct{}, concurrencyLimit)

	// FIX Bug #7: use a dedicated WaitGroup for segment-level goroutines only.
	// Per-peer goroutines inside fetchSegment use a separate local WaitGroup,
	// preventing wg.Wait() from racing against wg.Add() calls made inside
	// already-running goroutines.
	var segWg sync.WaitGroup

	// 5️⃣ Fetch segment in parallel from multiple peers.
	fetchSegment := func(from, to uint64) {
		defer segWg.Done()

		attempt := 0
		for attempt < maxRetries {
			attempt++

			select {
			case <-ctx.Done():
				errCh <- fmt.Errorf("sync cancelled for segment %d-%d", from, to)
				return
			default:
			}

			type result struct {
				blocks []*ledger.Block
				err    error
			}

			connectedPeers := make([]*Peer, 0, len(peersCopy))
			for _, peer := range peersCopy {
				if peer.IsConnected() {
					connectedPeers = append(connectedPeers, peer)
				}
			}

			if len(connectedPeers) == 0 {
				errCh <- fmt.Errorf("no connected peers for segment %d-%d", from, to)
				return
			}

			resCh := make(chan result, len(connectedPeers))

			// FIX Bug #7: use a local WaitGroup for per-peer goroutines.
			// This is completely independent from segWg, so segWg.Wait()
			// cannot race against these Add() calls.
			var peerWg sync.WaitGroup

			for _, peer := range connectedPeers {
				peerWg.Add(1) // Safe: called before go, in the same goroutine.
				go func(p *Peer) {
					defer peerWg.Done()
					sem <- struct{}{}
					blks, err := p.RequestBlocksRange(from, to)
					<-sem
					resCh <- result{blocks: blks, err: err}
				}(peer)
			}

			// Close resCh once all peer fetches complete.
			go func() {
				peerWg.Wait()
				close(resCh)
			}()

			// Collect first successful result.
			var success bool
			for res := range resCh {
				if !success && res.err == nil && len(res.blocks) > 0 {
					for _, blk := range res.blocks {
						if blk != nil && blk.Header.Height > 0 {
							blockCh <- blk
						}
					}
					success = true
				}
			}

			if success {
				return
			}

			// Exponential backoff before retry.
			backoff := time.Duration(1<<attempt) * time.Second
			log.Printf("[p2p] ⚠️ Segment %d-%d failed on attempt %d, retrying in %s", from, to, attempt, backoff)

			select {
			case <-ctx.Done():
				errCh <- fmt.Errorf("sync cancelled for segment %d-%d during backoff", from, to)
				return
			case <-time.After(backoff):
			}
		}

		errCh <- fmt.Errorf("failed to sync segment %d-%d after %d attempts", from, to, maxRetries)
	}

	// 6️⃣ Launch all segment fetches.
	// FIX Bug #7: all segWg.Add(1) calls happen here, before any goroutine
	// starts, guaranteeing segWg.Wait() cannot run before all Add() calls.
	for _, seg := range segments {
		segWg.Add(1)
		go fetchSegment(seg[0], seg[1])
	}

	// 7️⃣ Close channels after all segment goroutines finish.
	go func() {
		segWg.Wait()
		close(blockCh)
		close(errCh)
	}()

	// 8️⃣ Ordered block insertion.
	buffer := make(map[uint64]*ledger.Block)
	for blk := range blockCh {
		h := blk.Header.Height
		buffer[h] = blk

		for {
			b, ok := buffer[nextHeight]
			if !ok {
				break
			}
			if err := n.Ledger.AddBlock(b); err != nil {
				log.Printf("[p2p] ⚠️ Failed to add block %d: %v", nextHeight, err)
			} else {
				log.Printf("[p2p] ✅ Block %d synced", nextHeight)
			}
			delete(buffer, nextHeight)
			nextHeight++
		}
	}

	// 9️⃣ Log remaining errors.
	for err := range errCh {
		log.Printf("[p2p] ⚠️ Sync error: %v", err)
	}

	log.Println("[p2p] ✅ Ledger synchronization completed successfully")
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
