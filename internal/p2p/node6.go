package p2p

import (
	"crypto/sha256"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"log"
        "crypto/ed25519"
        "strings"
	"net"
	"sync/atomic"
	"time"
)

/* =========================
   CONSTANTS
   ========================= */

const (
	maxPeersPerIP       = 3
	minReputationBan    = -20
	minReputationReject = -10

	reputationMax = 100
	reputationMin = -100

	tlsIdentityTTL = 2 * time.Minute
	nonceTTL       = 2 * time.Minute

	basePoWDifficulty = 18

	maxNonces           = 10000
	maxInactivityPenalty = 20
)

/* =========================
   POW HANDSHAKE
   ========================= */

type HandshakeChallenge struct {
	Nonce      string
	Difficulty int
}

// Generate PoW challenge (server-side)
func generateChallenge(difficulty int, networkID string) HandshakeChallenge {

    b := make([]byte, 16)
    _, _ = cryptorand.Read(b)

    nonce := hex.EncodeToString(b) + networkID

    return HandshakeChallenge{
        Nonce:      nonce,
        Difficulty: difficulty,
    }
}

// 🔥 PoW must bind nonce + identity (anti-replay + anti-share)
func verifyPoW(nonce string, peerID PeerID, difficulty int) bool {

    data := nonce + string(peerID)

    hash := sha256.Sum256([]byte(data))
    hashHex := hex.EncodeToString(hash[:])

    prefix := strings.Repeat("0", difficulty/4)

    return strings.HasPrefix(hashHex, prefix)
}

// Dynamic PoW difficulty based on network load
func (n *Node) currentPoWDifficulty() int {

    peers := n.PeerCount()

    switch {
    case peers > 100:
        return 6
    case peers > 50:
        return 5
    default:
        return 4
    }
}


/* =========================
   PEER REGISTRATION
   ========================= */

func (n *Node) registerPeer(p *Peer, realID PeerID) {

        if p == nil {
                return
        }

        if realID == "" {
                log.Printf("p2p: ❌ empty peer identity")
                p.Close()
                return
        }

        // ------------------------------------------------------------------
        // 1. Validate TLS-authenticated identity
        // ------------------------------------------------------------------

        val, ok := n.tlsPeerCache.Load(string(realID))

        if ok {
                if ts, ok := val.(time.Time); ok && time.Since(ts) <= tlsIdentityTTL {
                        n.tlsPeerCache.Delete(string(realID))
                }
        }

        // ------------------------------------------------------------------
        // 2. Reputation gate
        // ------------------------------------------------------------------

        if rep := n.getReputation(realID); rep < minReputationReject {

                log.Printf(
                        "p2p: 🚫 rejected low reputation %s (%d)",
                        realID,
                        rep,
                )

                p.Close()
                return
        }

        // ------------------------------------------------------------------
        // 3. Register peer regardless of ledger status.
        // Ledger verification only sets trust level.
        // ------------------------------------------------------------------

        verified := n.verifyPeerOnChain(realID)

        p.mu.Lock()
        p.id = realID
        p.lastSeen = time.Now()
        p.verifiedMiner = verified
        p.mu.Unlock()

        sh := n.shard(realID)

        sh.mu.Lock()
        sh.peers[realID] = p
        sh.mu.Unlock()

        n.peerLastSeen.Store(realID, time.Now())

        if _, exists := n.peerReputation.Load(realID); !exists {
                n.peerReputation.Store(realID, 0)
        }

        if verified {
                log.Printf("p2p: ✅ registered verified peer %s", realID)
        } else {
                log.Printf("p2p: ⚠ registered unverified peer %s", realID)
        }
}

/* =========================
   REPUTATION SYSTEM
   ========================= */

func (n *Node) adjustReputation(id PeerID, delta int) {

	val, _ := n.peerReputation.LoadOrStore(id, 0)
	old := val.(int)

	newScore := old + delta

	if newScore > reputationMax {
		newScore = reputationMax
	}
	if newScore < reputationMin {
		newScore = reputationMin
	}

	n.peerReputation.Store(id, newScore)
}

func (n *Node) getReputation(id PeerID) int {
	val, ok := n.peerReputation.Load(id)
	if !ok {
		return 0
	}
	return val.(int)
}

/* =========================
   SCORING SYSTEM
   ========================= */

func (n *Node) computePeerScore(id PeerID) int {

	base := n.getReputation(id)

	lastSeenVal, ok := n.peerLastSeen.Load(id)
	if !ok {
		return base
	}

	lastSeen := lastSeenVal.(time.Time)

	inactivity := int(time.Since(lastSeen).Minutes())
	if inactivity > maxInactivityPenalty {
		inactivity = maxInactivityPenalty
	}

	score := base - inactivity

	if score < reputationMin {
		score = reputationMin
	}

	return score
}

/* =========================
   NETWORK HELPERS
   ========================= */

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

/* =========================
   EVICTION
   ========================= */

func (n *Node) findWorstPeer() PeerID {

	worstScore := reputationMax
	var worstID PeerID

	for i := range n.peerShards {
		sh := &n.peerShards[i]

		sh.mu.RLock()
		for id := range sh.peers {

			score := n.computePeerScore(id)

			if score < worstScore {
				worstScore = score
				worstID = id
			}
		}
		sh.mu.RUnlock()
	}

	return worstID
}

func (n *Node) evictPeer(id PeerID) {

	sh := n.shard(id)

	sh.mu.Lock()
	p, ok := sh.peers[id]
	if ok {
		delete(sh.peers, id)
	}
	sh.mu.Unlock()

	if ok {
		ip := extractIP(p.addr)

		// decrement IP tracking safely
		n.peerIPMutex.Lock()
		n.peerIPCount[ip]--
		if n.peerIPCount[ip] <= 0 {
			delete(n.peerIPCount, ip)
		}
		n.peerIPMutex.Unlock()

		log.Printf("p2p: 🧹 evicted %s (score=%d)", id, n.computePeerScore(id))
		p.Close()
	}
}

/* =========================
   BEHAVIOR CONTROL
   ========================= */

func (n *Node) punishPeer(id PeerID, reason string) {

	log.Printf("p2p: ⚠️ punish %s (%s)", id, reason)

	n.adjustReputation(id, -5)

	if n.getReputation(id) <= minReputationBan {
		log.Printf("p2p: 🚫 banned %s", id)
		n.evictPeer(id)
	}
}

func (n *Node) rewardPeer(id PeerID) {
	n.adjustReputation(id, +1)
}

/* =========================
   ANTI-REPLAY SYSTEM
   ========================= */

func (n *Node) isReplay(nonce string) bool {
    now := time.Now()

    // Check replay
    if val, exists := n.seenNonces.Load(nonce); exists {
        if now.Sub(val.(time.Time)) < nonceTTL {
            return true
        }
    }

    // Store nonce
    n.seenNonces.Store(nonce, now)

    // Track nonce usage (thread-safe)
    n.nonceMu.Lock()
    n.nonceCount[nonce]++
    n.nonceMu.Unlock()

    // Global counter (atomic)
    atomic.AddInt64(&n.nonceTotal, 1)

    // Lightweight cleanup
    if atomic.LoadInt64(&n.nonceTotal) > maxNonces {

        i := 0

        n.seenNonces.Range(func(key, value any) bool {

            if i%10 == 0 {
                n.seenNonces.Delete(key)

                n.nonceMu.Lock()
                delete(n.nonceCount, key.(string))
                n.nonceMu.Unlock()

                atomic.AddInt64(&n.nonceTotal, -1)
            }

            i++
            return i < 1000
        })
    }

    return false
}

/* =========================
   HANDSHAKE VALIDATION
   ========================= */

func (n *Node) validateHandshake(p *Peer, claimedID PeerID, nonce string) error {

	// 1. TLS identity check intentionally removed.
	// tlsPeerCache is keyed by Ed25519 pubkey — not by NodeID.
	// NodeID is ephemeral and never matches a TLS pubkey.
	// TLS authenticity is already guaranteed by the TLS handshake itself.
	// On-chain identity verification happens in registerPeer() after handshake.

	// 2. Prevent identity hijack within the same connection.
	if p.id != "" && p.id != claimedID {
		return errors.New("identity mutation detected")
	}

	// 3. Replay protection.
	if n.isReplay(nonce) {
		return errors.New("replay detected")
	}

	return nil
}

func (n *Node) verifyPeerOnChain(minerID PeerID) bool {

        if n == nil || n.Ledger == nil {
                return false
        }

        if minerID == "" {
                return false
        }

        // Bootstrap: no identities exist yet.
        if n.Ledger.GetLatestBlockHeight() == 0 {
                return true
        }

        var pubKey []byte

        key := []byte("miner_pubkey:" + string(minerID))

        if err := n.Ledger.GetObject(key, &pubKey); err != nil {
                return false
        }

        return len(pubKey) == ed25519.PublicKeySize
}
