// internal/p2p/node2.go
package p2p

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"explosive/internal/ledger"
)

// =============================================================================
// BOOTSTRAP & SEED NODES
// =============================================================================

// BootstrapPeers contains hard-coded seed nodes used only for initial discovery.
// Once the network has peers, it operates fully decentralized — true P2P resilience.
// These IPs can be changed or removed entirely in production.
var BootstrapPeers = []string{
	"51.21.180.138:8443", // Official Explosive seed (change or add more as needed)
}

// peerShard holds a subset of connected peers for lock sharding and high concurrency.
type peerShard struct {
	peers map[PeerID]*Peer
	mu    sync.RWMutex
}

// =============================================================================
// Bootstrap() — Mobile-first, non-blocking, fault-tolerant network bootstrap
// =============================================================================

// Bootstrap initializes peer discovery and light ledger sync in the background.
// - Connects to seed nodes asynchronously with timeout & backoff
// - Requests peer lists periodically
// - Performs LightSync cycles until ledger is complete
// - Auto-announces local unregistered miners
// - Never blocks mining or wallet operations
func (n *Node) Bootstrap() {
	log.Printf("[p2p] Starting bootstrap with %d seed peer(s)", len(BootstrapPeers))

	// Limit concurrent outbound connections to avoid overwhelming mobile devices.
	const maxConcurrent = 5
	sem := make(chan struct{}, maxConcurrent)

	for _, addr := range BootstrapPeers {
		go func(addr string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			p, err := n.tryConnect(addr, 4)
			if err != nil || p == nil {
				return
			}

			// FIX: wait for the bidirectional handshake to complete before
			// sending any messages. Sending REQUEST_PEERS before the handshake
			// causes the seed to receive it as the first message, which blocks
			// the handshake gate and prevents the connection from being established.
			go func(peer *Peer) {
				select {
				case <-peer.handshakeCh:
					// Handshake complete — now safe to request peers.
					env, _ := NewEnvelopeFromPayload(
						n.ProtocolVersion(),
						MsgTypeRequestPeers,
						struct{}{},
					)
					_ = peer.SendEnvelope(env)
					log.Printf("[p2p] bootstrap: peer list requested from %s", peer.addr)

				case <-time.After(10 * time.Second):
					log.Printf("[p2p] bootstrap: handshake timeout for %s", peer.addr)

				case <-n.ctx.Done():
					return
				}
			}(p)
		}(addr)
	}

	// Periodic peer discovery: ask all known peers for more peers.
	go func() {
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(12 * time.Second):
				n.requestPeersFromAll()
			}
		}
	}()

	// LightSync cycles — sync ledger from best available peer.
	go n.startLightSyncCycles()

	// Auto-register any local miners not yet known on-chain.
	go n.AutoRegisterLocalMiners()
}

// tryConnect attempts to establish a connection to a bootstrap peer address
// with exponential backoff.
// It performs a limited number of retries and never blocks mining or wallet operations.
func (n *Node) tryConnect(addr string, maxAttempts int) (*Peer, error) {
	// Start with a reasonable initial backoff suitable for mobile networks.
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Attempt to connect to the bootstrap peer.
		p, err := n.Connect(addr)
		if err == nil && p != nil {
			log.Printf(
				"[p2p] ✅ Successfully connected to bootstrap peer %s (attempt %d/%d)",
				addr,
				attempt,
				maxAttempts,
			)
			return p, nil
		}

		// Retry with exponential backoff and randomized jitter.
		if attempt < maxAttempts {
			jitter := time.Duration(rand.Intn(501)) * time.Millisecond
			sleepDuration := backoff + jitter

			// Keep retry information concise.
			log.Printf(
				"[p2p] bootstrap connection retry %d/%d in %.1fs",
				attempt,
				maxAttempts,
				sleepDuration.Seconds(),
			)

			timer := time.NewTimer(sleepDuration)

			select {
			case <-n.ctx.Done():
				timer.Stop()
				return nil, n.ctx.Err()

			case <-timer.C:
			}

			backoff *= 2
		}
	}

	// Return the error to the caller without printing another duplicate error.
	return nil, fmt.Errorf(
		"exhausted all %d connection attempts to bootstrap peer %s",
		maxAttempts,
		addr,
	)
}

// requestPeersFromAll sends a peer discovery request to all connected peers.
// FIX Bug #8: replaced sequential time.Sleep with per-peer goroutines to avoid
// blocking the caller for up to (peers * 300ms) on mobile networks.
func (n *Node) requestPeersFromAll() {
	peers := n.AllPeers()

	if len(peers) == 0 {
		return
	}

	for _, p := range peers {

		if !p.IsConnected() || p.IsBanned() {
			continue
		}

		peer := p

		go func() {

			// Wait until handshake is fully completed.
			select {

			case <-peer.handshakeCh:

			case <-time.After(5 * time.Second):
				log.Printf(
					"[p2p] requestPeers skipped (handshake timeout): %s",
					peer.addr,
				)
				return

			case <-n.ctx.Done():
				return
			}

			delay :=
				time.Duration(
					rand.Intn(301),
				) * time.Millisecond

			timer := time.NewTimer(delay)
			defer timer.Stop()

			select {

			case <-n.ctx.Done():
				return

			case <-timer.C:
			}

			env, err :=
				NewEnvelopeFromPayload(
					n.ProtocolVersion(),
					MsgTypeRequestPeers,
					struct{}{},
				)

			if err != nil {

				log.Printf(
					"[p2p] requestPeers envelope failed: %v",
					err,
				)

				return
			}

			if err :=
				peer.SendEnvelope(env); err != nil {

				log.Printf(
					"[p2p] requestPeers send failed to %s: %v",
					peer.addr,
					err,
				)
			}

		}()
	}
}

// AutoRegisterLocalMiners periodically announces unregistered local miners to the network.
// FIX Bug #9: ticker loop now listens on n.ctx.Done() to avoid goroutine leak on node shutdown.
func (n *Node) AutoRegisterLocalMiners() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:
			miners, err := n.Ledger.ListAllMiners()
			if err != nil || len(miners) == 0 {
				continue
			}

			const batchSize = 15
			sent := 0

			for _, m := range miners {
				if sent >= batchSize {
					break
				}

				// Skip if already registered on-chain.
				if onChain, _ := n.Ledger.HasMinerOnChain(m.ID); onChain {
					continue
				}

				// Avoid spamming: max 1 attempt per 12 minutes.
				if n.Ledger.HasRecentRegAttempt(m.ID, 12*60*1000) {
					continue
				}

				// Ensure V3 deterministic identity is ready.
				if err := ledger.EnsureMinerSignature(&m); err != nil {
					log.Printf(
						"[p2p] skipping miner %s announcement — V3 identity not ready: %v",
						m.ID,
						err,
					)
					continue
				}

				// Public announcement payload — includes Ed25519 PubKey as proof of identity.
				// Sacred words are never transmitted.
				payload := struct {
					MinerID        string `cbor:"miner_id"`
					PubKey         []byte `cbor:"pubkey"`
					FingerprintSHA string `cbor:"fingerprint_sha3"`
					Timestamp      int64  `cbor:"time"`
					SourceNode     string `cbor:"source"`
				}{
					MinerID:        m.ID,
					PubKey:         m.PubKey,
					FingerprintSHA: ledger.FingerprintHash(m.ConsciousnessFingerprint),
					Timestamp:      time.Now().UnixMilli(),
					SourceNode:     string(n.id),
				}

				env, err := NewEnvelopeFromPayload(
					n.ProtocolVersion(),
					MsgTypeAnnounceMiner,
					payload,
				)
				if err != nil {
					continue
				}

				// Attach MinerInfo for redundancy and faster verification by peers.
				env.MinerInfo = &MinerInfo{
					MinerID:   m.ID,
					Timestamp: env.Timestamp,
					PubKey:    m.PubKey,
				}

				// Randomized jitter (0-800ms) to avoid synchronized broadcast bursts.
				delay := time.Duration(rand.Intn(801)) * time.Millisecond

				select {
				case <-n.ctx.Done():
					return

				case <-time.After(delay):
				}

				n.BroadcastEnvelope(env)
				_ = n.Ledger.MarkRegistrationAttempt(m.ID)
				sent++

				// Announcement is intentionally silent.
				// The network operation still happens normally.
			}
		}
	}
}

// startLightSyncCycles runs up to 5 ledger sync attempts with increasing delays.
// FIX Bug #9: all sleeps now respect n.ctx.Done() to avoid goroutine leak on node shutdown.
func (n *Node) startLightSyncCycles() {
	const maxCycles = 5

	for cycle := 1; cycle <= maxCycles; cycle++ {
		// Check for shutdown before each cycle.
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		if n.PeerCount() == 0 {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(6 * time.Second):
			}
			continue
		}

		ctx, cancel := context.WithTimeout(n.ctx, 35*time.Second)
		n.SyncLedgerFromBestPeer(ctx)
		cancel()

		if n.IsLedgerComplete() {
			return
		}

		select {
		case <-n.ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
// =============================================================================
// SHARDING UTILITIES (internal)
// =============================================================================

// shard returns the correct shard for a given PeerID using consistent hashing.
func (n *Node) shard(pid PeerID) *peerShard {
	if len(pid) == 0 {
		return &n.peerShards[0]
	}
	h := int(pidHash(pid))
	return &n.peerShards[h%len(n.peerShards)]
}

// pidHash produces a stable 32-bit hash from a PeerID (SHA-256 truncated).
func pidHash(pid PeerID) int32 {
	sum := sha256.Sum256([]byte(pid))
	var h int32
	for i := 0; i < 4; i++ {
		h = (h << 8) | int32(sum[i])
	}
	if h < 0 {
		h = -h
	}
	return h
}

// ClearBootstrapPeers vide la liste des seeds.
// Appelé par le seed node lui-même pour éviter l'auto-connexion.
func ClearBootstrapPeers() {
    BootstrapPeers = []string{}
}
