// internal/p2p/node3.go
package p2p

import (
        "fmt"
        "math/rand"
        "strings"
        "time"

        "explosive/internal/ledger"
        "explosive/internal/scan"
)

// =============================================================================
// BALANCE & TRANSACTION HISTORY
// =============================================================================

// GetBalance retrieves the EXPLO and IMANI balance of a given address
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

// GetTransactionHistory retrieves transaction history for an address with pagination
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
// METRICS — SILENT & ON-DEMAND
// =============================================================================

// Equals compares two MetricsData structs for equality
func (m MetricsData) Equals(o MetricsData) bool {
        return m.Timestamp == o.Timestamp &&
                m.MaxSupply == o.MaxSupply &&
                m.Circulating == o.Circulating &&
                m.TotalHolders == o.TotalHolders &&
                m.MinersCount == o.MinersCount &&
                m.MinersRemaining == o.MinersRemaining
}

// GetMetrics returns the current cached metrics or fetches them from ledger if not cached
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

// UpdateGlobalMetrics updates the ledger-compatible global metrics (uint64 in Pastabo)
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

        // Store metrics in ledger (MetricsData in float64 for display)
        _ = n.Ledger.PutObject([]byte("network:metrics"), &m)

        n.metricsMu.Lock()
        n.CachedMetrics = m
        n.cachedMetricsOnce = true

        // Convert float64 EXPLO to uint64 Pastabo for GlobalMetrics payload
        n.GlobalMetrics = MetricsPayload{
                Timestamp:       m.Timestamp,
                MaxSupply:       uint64(m.MaxSupply * float64(ledger.PastaboPerEXPLO)),   // Pastabo
                Circulating: m.Circulating,
                TotalHolders:    m.TotalHolders,
                MinersCount:     m.MinersCount,
                MinersRemaining: m.MinersRemaining,
        }

        n.metricsMu.Unlock()
}

// FetchMetricsNow retrieves latest network metrics on-demand
func (n *Node) FetchMetricsNow() MetricsData {
        if n == nil || n.Ledger == nil {
                return MetricsData{}
        }

        // Gather live metrics from scan
        md, err := scan.GatherMetrics(n.Ledger)
        if err != nil || md == nil {
                return n.GetMetrics()
        }

        // Use float64 EXPLO for human-readable metrics
        metrics := MetricsData{
                Timestamp:       md.Timestamp,
                MaxSupply:       md.MaxSupply,
                Circulating:     md.Circulating,
                TotalHolders: int(md.TotalHolders),
                MinersCount:     int(md.MinersCount),
                MinersRemaining: int(md.MinersRemaining),
        }

        // Update global metrics in uint64 (Pastabo) format
        n.UpdateGlobalMetrics(metrics)

        // Only broadcast if metrics changed
        if n.GetMetrics().Equals(metrics) {
                return metrics
        }

        // Broadcast authenticated metrics if a local miner exists
        env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeMetrics, n.GlobalMetrics)
        if err != nil {
                return n.GetMetrics()
        }

        if n.config.RequireSignedMessages {
                miners, err := n.Ledger.ListAllMiners()
                if err == nil && len(miners) > 0 {
                        miner := &miners[0]
                        if ledger.EnsureMinerSignature(miner) == nil {
                                env.MinerInfo = &MinerInfo{
                                        MinerID:   miner.ID,
                                        Timestamp: env.Timestamp,
                                        PubKey:    miner.PubKey,
                                }
                        }
                }
        }

        // Random jitter 0-500ms to stagger network broadcasts
        time.Sleep(time.Duration(rand.Intn(501)) * time.Millisecond)
        n.BroadcastEnvelope(env)

        return metrics // Return float64 metrics for display
}

// GetSampleMiners returns a random sample of miners for display
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

        perm := rand.Perm(total)
        result := make([]string, count)
        for i := 0; i < count; i++ {
                result[i] = miners[perm[i]].ID
        }
        return result
}

// ShowLiveMetrics prints current metrics & a sample of miners
func ShowLiveMetrics(node *Node) {
        if node == nil {
                fmt.Println("❌ Node not initialized.")
                return
        }

        m := node.GetMetrics()
        if m.Timestamp == 0 {
                fmt.Println("⏳ Metrics data not available yet.")
                return
        }

        fmt.Printf(
                "🌍 EXPLO Max:%.2f | Circulating:%.3f | Holders:%d | Miners:%d | NextHalvingIn:%d\n",
                m.MaxSupply,
                m.Circulating,
                m.TotalHolders,
                m.MinersCount,
                m.MinersRemaining,
        )

        sample := node.GetSampleMiners(10)
        if len(sample) > 0 {
                fmt.Println("🔹 Sample miners:", strings.Join(sample, ", "))
        }
}

// =============================================================================
// BACKGROUND LOOPS — DISABLED
// =============================================================================

// StartMetricsLoop is disabled in mobile nodes
func (n *Node) StartMetricsLoop(_ time.Duration) {}

// StartMetricsBroadcastLoop is disabled in mobile nodes
func (n *Node) StartMetricsBroadcastLoop(_ time.Duration) {}
