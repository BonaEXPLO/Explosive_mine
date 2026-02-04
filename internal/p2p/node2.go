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

	// Limit concurrent outbound connections to avoid overwhelming mobile devices
	const maxConcurrent = 5
	sem := make(chan struct{}, maxConcurrent)

	for _, addr := range BootstrapPeers {
		go func(addr string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try up to 4 times with exponential backoff
			if p, err := n.tryConnect(addr, 4); err == nil && p != nil {
				// Immediately request known peers from this seed
				env, _ := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeRequestPeers, struct{}{})
				_ = p.SendEnvelope(env)
			}
		}(addr)
	}

	// Periodic peer discovery: ask all known peers for more peers
	go func() {
		for {
			n.requestPeersFromAll()
			time.Sleep(12 * time.Second)
		}
	}()

	// LightSync cycles — sync ledger from best available peer
	go n.startLightSyncCycles()

	// Auto-register any local miners not yet known on-chain
	go n.AutoRegisterLocalMiners()
}

// tryConnect attempts to establish a connection to a bootstrap peer address with exponential backoff.
// It performs a limited number of retries (maxAttempts) and logs detailed progress for network debugging,
// especially valuable on mobile devices with unstable connectivity.
// This function is called only once per bootstrap peer during initial discovery — no infinite loops.
// Enhanced with randomized jitter to avoid synchronized retries across nodes.
func (n *Node) tryConnect(addr string, maxAttempts int) (*Peer, error) {
	// Start with a reasonable initial backoff (2 seconds) suitable for mobile networks
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Attempt to connect to the bootstrap peer
		p, err := n.Connect(addr)
		if err == nil && p != nil {
			// SUCCESS: Connection established on this attempt
			log.Printf("[p2p] ✅ Successfully connected to bootstrap peer %s (attempt %d/%d)", addr, attempt, maxAttempts)
			return p, nil
		}

		// FAILURE: Log the failed attempt
		if attempt < maxAttempts {
			// Add randomized jitter (0-500ms) to prevent synchronized retries
			jitter := time.Duration(rand.Intn(501)) * time.Millisecond
			sleepDuration := backoff + jitter

			log.Printf("[p2p] ⚠️ Failed to connect to bootstrap peer %s (attempt %d/%d) — retrying in %.1f seconds...",
				addr, attempt, maxAttempts, sleepDuration.Seconds())
			time.Sleep(sleepDuration)
			backoff *= 2 // Exponential backoff for next attempt
		}
	}

	// FINAL FAILURE: All attempts exhausted
	finalErr := fmt.Errorf("exhausted all %d connection attempts to bootstrap peer %s", maxAttempts, addr)
	log.Printf("[p2p] ❌ %s", finalErr.Error())
	return nil, finalErr
}

// requestPeersFromAll sends a peer request to every currently connected peer.
// Enhanced with randomized jitter per peer and filtering of banned peers to reduce network noise.
func (n *Node) requestPeersFromAll() {
	peers := n.AllPeers()
	if len(peers) == 0 {
		return
	}
	env, _ := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeRequestPeers, struct{}{})
	for _, p := range peers {
		if !p.IsConnected() || p.IsBanned() {
			continue
		}
		// Add small randomized jitter (0-300ms) per request to avoid synchronized bursts
		delay := time.Duration(rand.Intn(301)) * time.Millisecond
		time.Sleep(delay)

		_ = p.SendEnvelope(env)
	}
}

// startLightSyncCycles runs up to 5 sync attempts with increasing delays.
func (n *Node) startLightSyncCycles() {
	const maxCycles = 5
	for cycle := 1; cycle <= maxCycles; cycle++ {
		if n.PeerCount() == 0 {
			time.Sleep(6 * time.Second)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		n.SyncLedgerFromBestPeer(ctx)
		cancel()

		if n.IsLedgerComplete() {
			return
		}
		time.Sleep(5 * time.Second)
	}
}

// =============================================================================
// AUTO-REGISTRATION OF LOCAL MINERS
// =============================================================================

// AutoRegisterLocalMiners announces unregistered local miners to the network.
// Updated for full V3 compatibility:
// - Announces deterministic Ed25519 PubKey (proof of consciousness fingerprint possession)
// - Envelope is signed using the miner's stateless Ed25519 key when possible
// - Rate-limited and privacy-preserving: no sacred words or private data ever transmitted
// Enhanced with per-announcement jitter and stricter batch spacing for mobile-friendly network behavior.
func (n *Node) AutoRegisterLocalMiners() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
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

			// Skip if already registered on-chain
			if onChain, _ := n.Ledger.HasMinerOnChain(m.ID); onChain {
				continue
			}

			// Avoid spamming: max 1 attempt per 12 minutes
			if n.Ledger.HasRecentRegAttempt(m.ID, 12*60*1000) {
				continue
			}

			// Ensure V3 deterministic identity is ready
			if err := ledger.EnsureMinerSignature(&m); err != nil {
				log.Printf("p2p: skipping miner %s announcement — V3 identity not ready: %v", m.ID, err)
				continue
			}

			// Public announcement payload — includes Ed25519 PubKey as strong proof
			payload := struct {
				MinerID        string `cbor:"miner_id"`
				PubKey         []byte `cbor:"pubkey"`                  // Ed25519 public key (deterministic)
				FingerprintSHA string `cbor:"fingerprint_sha3"`        // Optional: for legacy compatibility
				Timestamp      int64  `cbor:"time"`
				SourceNode     string `cbor:"source"`
			}{
				MinerID:        m.ID,
				PubKey:         m.PubKey,
				FingerprintSHA: ledger.FingerprintHash(m.ConsciousnessFingerprint),
				Timestamp:      time.Now().UnixMilli(),
				SourceNode:     string(n.id),
			}

			env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeAnnounceMiner, payload)
			if err != nil {
				continue
			}

			// Attach MinerInfo for redundancy and faster verification by peers
			env.MinerInfo = &MinerInfo{
				MinerID:   m.ID,
				Timestamp: env.Timestamp,
				PubKey:    m.PubKey,
			}

			// Small jitter (0-800ms) before broadcast to avoid synchronized bursts
			delay := time.Duration(rand.Intn(801)) * time.Millisecond
			time.Sleep(delay)

			// The envelope will be automatically signed in SendEnvelope/BroadcastEnvelope
			// if RequireSignedMessages is enabled and miner key is derivable
			n.BroadcastEnvelope(env)
			_ = n.Ledger.MarkRegistrationAttempt(m.ID)
			sent++

			log.Printf("p2p: announced unregistered miner %s with V3 Ed25519 identity (jitter delay=%v)", m.ID, delay)
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
