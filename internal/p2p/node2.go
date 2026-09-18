// internal/p2p/node2.go
package p2p

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	"explosive/internal/ledger"
)

// BootstrapPeers contains optional initial peers used only for network discovery.
// The network becomes fully decentralized after peers are connected.
// No external seed is hard-coded into the node.
var BootstrapPeers = []string{}

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

// AutoRegisterLocalMiners periodically announces the local miner identity
// when it is not yet registered on-chain.
//
// SCALABILITY DESIGN:
//
//   - Observer/investor nodes perform zero miner scans.
//   - Only the configured local MinerID is queried.
//   - The ledger lookup is a direct BadgerDB key lookup:
//     miner:<MinerID>
//   - No ListAllMiners() call is performed.
//   - No Argon2 miner-key derivation is performed by this loop.
//   - The P2P layer uses the already configured public miner identity
//     and secure miner signing callback.
//   - Sacred words and miner private keys never enter this function.
//
// This keeps the normal announcement path independent of the total
// number of miners registered by the network.
func (n *Node) AutoRegisterLocalMiners() {
	if n == nil || n.Ledger == nil || n.ctx == nil {
		return
	}

	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return

		case <-ticker.C:

			// =========================================================
			// 1. DETERMINE LOCAL NODE ROLE
			// =========================================================

			minerID, minerPubKey := n.getMinerIdentity()

			minerID = strings.TrimSpace(minerID)

			// Observer/investor nodes have no local MinerID.
			// They must never scan the miner database and must never
			// broadcast ANNOUNCE_MINER.
			if minerID == "" {
				continue
			}

			// The local miner public identity must be a valid
			// Ed25519 public key.
			if len(minerPubKey) != ed25519.PublicKeySize {
				log.Printf(
					"[p2p] skipping miner announcement: invalid local miner public key",
				)
				continue
			}

			// =========================================================
			// 2. DIRECT LOCAL MINER LOOKUP
			// =========================================================
			//
			// IMPORTANT:
			// This performs ONE BadgerDB key lookup:
			//
			//     miner:<MinerID>
			//
			// It does not enumerate the miner namespace.

			miner, err := n.Ledger.GetStoredMinerByID(minerID)
			if err != nil {
				if !errors.Is(err, badger.ErrKeyNotFound) {
					log.Printf(
						"[p2p] local miner lookup failed for %s: %v",
						minerID,
						err,
					)
				}
				continue
			}

			if miner == nil {
				continue
			}

			// =========================================================
			// 3. VERIFY LOCAL PUBLIC IDENTITY
			// =========================================================

			if !strings.EqualFold(
				strings.TrimSpace(miner.ID),
				minerID,
			) {
				log.Printf(
					"[p2p] refusing miner announcement: stored MinerID mismatch",
				)
				continue
			}

			if len(miner.PubKey) != ed25519.PublicKeySize {
				log.Printf(
					"[p2p] refusing miner announcement for %s: invalid stored public key",
					minerID,
				)
				continue
			}

			if !bytes.Equal(miner.PubKey, minerPubKey) {
				log.Printf(
					"[p2p] refusing miner announcement for %s: public key mismatch",
					minerID,
				)
				continue
			}

			// =========================================================
			// 4. CHECK ON-CHAIN REGISTRATION
			// =========================================================

			onChain, err := n.Ledger.HasMinerOnChain(minerID)
			if err != nil {
				log.Printf(
					"[p2p] failed to check on-chain status for miner %s: %v",
					minerID,
					err,
				)
				continue
			}

			if onChain {
				continue
			}

			// =========================================================
			// 5. REGISTRATION RATE LIMIT
			// =========================================================

			if n.Ledger.HasRecentRegAttempt(
				minerID,
				12*60*1000,
			) {
				continue
			}

			// =========================================================
			// 6. BUILD PUBLIC ANNOUNCEMENT
			// =========================================================
			//
			// Sacred words are never transmitted.
			//
			// The local P2P miner public key is already authenticated
			// by SetMinerIdentity().

			timestamp := time.Now().UnixMilli()

			payload := struct {
				MinerID        string `cbor:"miner_id"`
				PubKey         []byte `cbor:"pubkey"`
				FingerprintSHA string `cbor:"fingerprint_sha3"`
				Timestamp      int64  `cbor:"time"`
				SourceNode     string `cbor:"source"`
			}{
				MinerID: minerID,
				PubKey: append(
					[]byte(nil),
					minerPubKey...,
				),
				FingerprintSHA: ledger.FingerprintHash(
					miner.ConsciousnessFingerprint,
				),
				Timestamp:  timestamp,
				SourceNode: string(n.id),
			}

			env, err := NewEnvelopeFromPayload(
				n.ProtocolVersion(),
				MsgTypeAnnounceMiner,
				payload,
			)
			if err != nil {
				log.Printf(
					"[p2p] failed to create miner announcement for %s: %v",
					minerID,
					err,
				)
				continue
			}

			// =========================================================
			// 7. CREATE MINER P2P PROOF
			// =========================================================

			proofPayload, err := BuildMinerP2PProof(
				n.networkID,
				minerID,
				minerID,
				string(n.id),
				minerPubKey,
				env.Timestamp,
				env.Nonce,
			)
			if err != nil {
				log.Printf(
					"[p2p] failed to build miner P2P proof for %s: %v",
					minerID,
					err,
				)
				continue
			}

			// =========================================================
			// 8. SIGN WITHOUT EXPOSING PRIVATE MATERIAL
			// =========================================================

			minerSignature, err := n.signMinerData(proofPayload)
			if err != nil {
				log.Printf(
					"[p2p] failed to sign miner announcement for %s: %v",
					minerID,
					err,
				)
				continue
			}

			if len(minerSignature) != ed25519.SignatureSize {
				log.Printf(
					"[p2p] invalid miner signature size for %s: got %d, want %d",
					minerID,
					len(minerSignature),
					ed25519.SignatureSize,
				)
				continue
			}

			// =========================================================
			// 9. ATTACH MINER P2P PROOF
			// =========================================================

			env.MinerInfo = &MinerInfo{
				MinerID:   minerID,
				Timestamp: env.Timestamp,
				PubKey: append(
					[]byte(nil),
					minerPubKey...,
				),
				Signature: append(
					[]byte(nil),
					minerSignature...,
				),
			}

			// =========================================================
			// 10. SMALL RANDOMIZED JITTER
			// =========================================================
			//
			// Prevent synchronized announcement bursts without creating
			// one timer per miner or maintaining a large scheduling queue.

			delay := time.Duration(
				rand.Intn(801),
			) * time.Millisecond

			timer := time.NewTimer(delay)

			select {
			case <-n.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return

			case <-timer.C:
			}

			// =========================================================
			// 11. BROADCAST
			// =========================================================

			n.BroadcastEnvelope(env)

			_ = n.Ledger.MarkRegistrationAttempt(minerID)

			log.Printf(
				"[p2p] 📡 ANNOUNCE_MINER broadcast: miner=%s",
				minerID,
			)
		}
	}
}

// startLightSyncCycles performs a limited number of asynchronous
// ledger synchronization attempts.
//
// Synchronization itself is asynchronous:
//
//	SyncLedgerFromBestPeer()
//	        |
//	        v
//	  GETBLOCKSRANGE
//	        |
//	        v
//	  BLOCKSRESPONSE
//	        |
//	        v
//	     AddBlock()
//
// This function only starts and monitors synchronization sessions.
// It never cancels an active synchronization context prematurely.
func (n *Node) startLightSyncCycles() {
	const maxCycles = 5
	const syncMonitorInterval = 1 * time.Second
	const syncAttemptTimeout = 35 * time.Second

	for cycle := 1; cycle <= maxCycles; cycle++ {

		// ------------------------------------------------------------
		// 1. Check node shutdown.
		// ------------------------------------------------------------

		select {
		case <-n.ctx.Done():
			return
		default:
		}

		// ------------------------------------------------------------
		// 2. Wait for at least one connected peer.
		// ------------------------------------------------------------

		if n.PeerCount() == 0 {
			select {
			case <-n.ctx.Done():
				return

			case <-time.After(6 * time.Second):
			}

			continue
		}

		// ------------------------------------------------------------
		// 3. Start one asynchronous synchronization session.
		// ------------------------------------------------------------

		n.SyncLedgerFromBestPeer(n.ctx)

		// ------------------------------------------------------------
		// 4. Monitor the active synchronization session.
		//
		// We do NOT cancel n.ctx.
		// The node context belongs to the whole P2P node lifetime.
		//
		// The timeout here only limits how long this monitoring cycle
		// waits before allowing the next cycle to evaluate the state.
		// ------------------------------------------------------------

		deadline := time.NewTimer(syncAttemptTimeout)

	monitorLoop:
		for {
			select {

			case <-n.ctx.Done():
				if !deadline.Stop() {
					select {
					case <-deadline.C:
					default:
					}
				}
				return

			case <-deadline.C:
				break monitorLoop

			case <-time.After(syncMonitorInterval):
				n.syncMu.Lock()
				running := n.syncRunning
				n.syncMu.Unlock()

				if !running {
					break monitorLoop
				}

				if n.IsLedgerComplete() {
					break monitorLoop
				}
			}
		}

		// ------------------------------------------------------------
		// 5. Stop immediately if synchronization completed.
		// ------------------------------------------------------------

		if n.IsLedgerComplete() {
			log.Printf(
				"[p2p] 🎉 Initial ledger synchronization completed",
			)
			return
		}

		// ------------------------------------------------------------
		// 6. Give the network a short recovery interval before
		// attempting another synchronization cycle.
		// ------------------------------------------------------------

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
