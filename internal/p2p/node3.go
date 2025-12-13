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
// METRICS À LA DEMANDE (menu 8 + restauration + création)
// =============================================================================

func (n *Node) FetchMetricsNow() MetricsData {
	if n == nil || n.Ledger == nil {
		return MetricsData{}
	}

	md, err := scan.GatherMetrics(n.Ledger)
	if err != nil || md == nil {
		return n.GetMetrics()
	}

	// Conversion explicite scan.MetricsData → p2p.MetricsData
	metrics := MetricsData{
		Timestamp:       md.Timestamp,
		MaxSupply:       md.MaxSupply,
		Circulating:     md.Circulating,
		TotalHolders:    md.TotalHolders,
		MinersCount:     md.MinersCount,
		MinersRemaining: md.MinersRemaining,
	}

	n.UpdateGlobalMetrics(metrics)
	return n.GetMetrics()
}

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
	n.BroadcastEnvelope(env)
}

// Échantillon aléatoire de mineurs (IDs seulement)
func (n *Node) GetSampleMiners(count int) []string {
	if n == nil || n.Ledger == nil {
		return nil
	}

	miners, err := n.Ledger.ListAllMiners() // ← retourne []ledger.Miner
	if err != nil || len(miners) == 0 {
		return nil
	}

	total := len(miners)
	if count >= total {
		count = total
	}

	result := make([]string, 0, count)
	perm := rand.Perm(total)
	seen := make(map[int]bool)

	for len(result) < count {
		idx := perm[len(result)]
		if seen[idx] {
			continue
		}
		seen[idx] = true
		result = append(result, miners[idx].ID) // ← on prend uniquement l’ID
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
