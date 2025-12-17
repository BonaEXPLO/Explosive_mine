// internal/p2p/node3.go
package p2p

import (
	"fmt"
        "strings"
	"math/rand"
	"time"

	"explosive/internal/ledger"
	"explosive/internal/scan"
)

// =============================================================================
// BALANCE & TRANSACTION HISTORY
// =============================================================================

func (n *Node) GetBalance(address string) (float64, float64, error) {
	if n == nil || n.Ledger == nil {
		return 0, 0, fmt.Errorf("ledger not initialized")
	}

	var bal ledger.Balance
	if err := n.Ledger.GetObject([]byte("balance:"+address), &bal); err != nil {
		return 0, 0, nil
	}
	return bal.EXPLO, bal.IMANI, nil
}

func (n *Node) GetTransactionHistory(address string, offset, limit int) ([]ledger.Transaction, error) {
	if n == nil || n.Ledger == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}
	txs, err := n.Ledger.GetTransactionsByAddress(address, offset, limit)
	if err != nil {
		return nil, err
	}
	result := make([]ledger.Transaction, len(txs))
	for i, t := range txs {
		result[i] = *t
	}
	return result, nil
}

// =============================================================================
// METRICS — SILENCIEUX & À LA DEMANDE
// =============================================================================

func (m MetricsData) Equals(o MetricsData) bool {
	return m.Timestamp == o.Timestamp &&
		m.MaxSupply == o.MaxSupply &&
		m.Circulating == o.Circulating &&
		m.TotalHolders == o.TotalHolders &&
		m.MinersCount == o.MinersCount &&
		m.MinersRemaining == o.MinersRemaining
}

func (n *Node) GetMetrics() MetricsData {
	if n == nil || n.Ledger == nil {
		return MetricsData{}
	}

	n.metricsMu.RLock()
	if n.cachedMetricsOnce {
		cached := n.CachedMetrics
		n.metricsMu.RUnlock()
		return cached
	}
	n.metricsMu.RUnlock()

	var m MetricsData
	if err := n.Ledger.GetObject([]byte("network:metrics"), &m); err != nil {
		return MetricsData{}
	}

	n.metricsMu.Lock()
	n.CachedMetrics = m
	n.cachedMetricsOnce = true
	n.metricsMu.Unlock()
	return m
}

func (n *Node) UpdateGlobalMetrics(m MetricsData) {
	if n == nil || n.Ledger == nil {
		return
	}

	n.metricsMu.RLock()
	unchanged := n.cachedMetricsOnce && m.Equals(n.CachedMetrics)
	n.metricsMu.RUnlock()
	if unchanged {
		return
	}

	_ = n.Ledger.PutObject([]byte("network:metrics"), &m)

	n.metricsMu.Lock()
	n.CachedMetrics = m
	n.cachedMetricsOnce = true
	n.GlobalMetrics = MetricsPayload{
		Timestamp:       m.Timestamp,
		MaxSupply:       m.MaxSupply,
		Circulating:     m.Circulating,
		TotalHolders:    m.TotalHolders,
		MinersCount:     m.MinersCount,
		MinersRemaining: m.MinersRemaining,
	}
	n.metricsMu.Unlock()
}

// =============================================================================
// BACKGROUND LOOPS — COMPLÈTEMENT DÉSACTIVÉS
// =============================================================================

func (n *Node) StartMetricsLoop(_ time.Duration)          {}
func (n *Node) StartMetricsBroadcastLoop(_ time.Duration) {}

// =============================================================================
// ON-DEMAND METRICS (menu option 8 + miner creation/restoration)
// =============================================================================

// FetchMetricsNow retrieves the latest network metrics on demand.
// It is triggered explicitly by user actions (viewing metrics, creating or restoring a miner)
// rather than running on a periodic timer, ensuring minimal battery and bandwidth usage.
//
// Behavior:
// - If the ledger is unavailable, returns an empty MetricsData struct.
// - Attempts to gather fresh metrics using the scan package.
// - Falls back to cached metrics if gathering fails.
// - Updates the local cached copy and global payload.
// - Immediately broadcasts the refreshed metrics to all connected peers,
//   ensuring network-wide consistency when users view sy
// FetchMetricsNow retrieves the latest network metrics on demand.
// Enhanced for V3 security:
// - After gathering fresh metrics, triggers an authenticated broadcast
//   using the local miner's Ed25519 identity if available.
// - Ensures metrics announcements are signed when RequireSignedMessages is enabled,
//   providing trustless proof of origin from a legitimate miner node.
// - Remains fully mobile-friendly: no periodic background activity.
func (n *Node) FetchMetricsNow() MetricsData {
    if n == nil || n.Ledger == nil {
        return MetricsData{}
    }

    md, err := scan.GatherMetrics(n.Ledger)
    if err != nil || md == nil {
        return n.GetMetrics()
    }

    // Convert scan metrics to P2P format
    metrics := MetricsData{
        Timestamp:       md.Timestamp,
        MaxSupply:       md.MaxSupply,
        Circulating:     md.Circulating,
        TotalHolders:    md.TotalHolders,
        MinersCount:     md.MinersCount,
        MinersRemaining: md.MinersRemaining,
    }

    n.UpdateGlobalMetrics(metrics)

    // Broadcast authenticated metrics if we have a local miner with V3 identity
    // This ensures network-wide metric consistency with cryptographic proof of origin
    if n.config.RequireSignedMessages {
        miners, err := n.Ledger.ListAllMiners()
        if err == nil && len(miners) > 0 {
            miner := &miners[0]
            if ledger.EnsureMinerSignature(miner) == nil {
                // Attach MinerInfo to the metrics envelope for identity proof
                env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeMetrics, n.GlobalMetrics)
                if err == nil {
                    env.MinerInfo = &MinerInfo{
                        MinerID:   miner.ID,
                        Timestamp: env.Timestamp,
                        PubKey:    miner.PubKey,
                    }
                    // Signature will be applied automatically in SendEnvelope/BroadcastEnvelope
                    n.BroadcastEnvelope(env)
                    return n.GetMetrics()
                }
            }
        }
    }

    // Fallback: unsigned broadcast (compatible with light nodes or pre-V3)
    n.BroadcastMetricsOnce()

    return n.GetMetrics()
}

// BroadcastMetricsOnce broadcasts current metrics to all peers.
// Now deprecated in favor of authenticated broadcast via FetchMetricsNow when possible.
// Kept for backward compatibility and light nodes without miner identity.
func (n *Node) BroadcastMetricsOnce() {
    if n == nil {
        return
    }

    n.metricsMu.RLock()
    metrics := n.GlobalMetrics
    n.metricsMu.RUnlock()

    env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeMetrics, metrics)
    if err != nil {
        return
    }

    // Unsigned broadcast – used only as fallback
    n.BroadcastEnvelope(env)
}

// GetSampleMiners returns a random sample of at most 'count' miner IDs.
// Uses Fisher-Yates shuffle on a permutation for efficient unbiased sampling.
func (n *Node) GetSampleMiners(count int) []string {
    if n == nil || n.Ledger == nil {
        return nil
    }

    miners, err := n.Ledger.ListAllMiners()
    if err != nil || len(miners) == 0 {
        return nil
    }

    total := len(miners)
    if count > total {
        count = total
    }

    // Generate permutation and take first 'count' unique indices
    perm := rand.Perm(total)
    result := make([]string, count)
    for i := 0; i < count; i++ {
        result[i] = miners[perm[i]].ID
    }

    return result
}

// ShowLiveMetrics displays a snapshot of network metrics and a small sample of miners.
func ShowLiveMetrics(node *Node) {
	if node == nil {
		fmt.Println("❌ Node not initialized.")
		return
	}

	// Retrieve the current metrics snapshot
	m := node.GetMetrics()
	if m.Timestamp == 0 {
		fmt.Println("⏳ Metrics data not available yet.")
		return
	}

	// Print key network metrics
	fmt.Printf(
		"🌍 EXPLO Max:%d | Circulating:%.3f | Holders:%d | Miners:%d | NextHalvingIn:%d\n",
		m.MaxSupply,
		m.Circulating,
		m.TotalHolders,
		m.MinersCount,
		m.MinersRemaining,
	)

	// Display a small random sample of miners to keep output lightweight
	sample := node.GetSampleMiners(10)
	if len(sample) > 0 {
		fmt.Println("🔹 Sample miners:", strings.Join(sample, ", "))
	}
}
