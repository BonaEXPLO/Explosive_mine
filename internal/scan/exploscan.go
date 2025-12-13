// internal/scan/exploscan.go
package scan

import (
	"bytes"
	"fmt"
	"time"
	"explosive/internal/ledger"
        "github.com/dgraph-io/badger/v4"
)

// MetricsData represents ephemeral chain statistics ready for broadcast.
// These values are computed on the fly, never stored.
type MetricsData struct {
	Timestamp       int64   `json:"timestamp"`
	MaxSupply       uint64  `json:"max_supply"`
	Circulating     float64 `json:"circulating"`
	TotalHolders    int     `json:"total_holders"`
	MinersCount     int     `json:"miners_count"`
	MinersRemaining int     `json:"miners_remaining"`
}

// Broadcaster defines a minimal interface to send messages (e.g. metrics)
// over the P2P network without requiring any persistent storage.
type Broadcaster interface {
	BroadcastMessage(msgType string, payload any) error
}

// StartExploscan starts a lightweight "dust" scanner that periodically
// computes metrics entirely in memory. No data is written to disk.
func StartExploscan(l *ledger.Ledger, broadcaster Broadcaster, stopCh <-chan struct{}) {
	if l == nil || l.GetDB() == nil {
		fmt.Println("❌ Exploscan: ledger not initialized")
		return
	}

	// Metrics refresh every 2 seconds (adjustable)
	secTicker := time.NewTicker(2 * time.Second)
	defer secTicker.Stop()

	go func() {
		for {
			select {
			case <-stopCh:
				fmt.Println("🛑 Exploscan stopped")
				return

			case <-secTicker.C:
				md, err := GatherMetrics(l)
				if err != nil {
					fmt.Printf("⚠️ Exploscan error: %v\n", err)
					continue
				}

				// Ephemeral display — values exist only for observation
				now := time.Now().Format("15:04:05")
				fmt.Printf("[%s] EXPLO Max:%d  Circulating:%.3f  Holders:%d  Miners:%d  NextHalvingIn:%d\n",
					now, md.MaxSupply, md.Circulating, md.TotalHolders, md.MinersCount, md.MinersRemaining)

				// Broadcast to connected peers (optional)
				if broadcaster != nil {
					if err := broadcaster.BroadcastMessage("METRICS", md); err != nil {
						fmt.Printf("⚠️ Failed to broadcast metrics: %v\n", err)
					}
				}
			}
		}
	}()
}

// GatherMetrics calculates live metrics from the ledger database.
// It performs read-only access and never stores any result.
func GatherMetrics(l *ledger.Ledger) (*MetricsData, error) {
	db := l.GetDB()
	if db == nil {
		return nil, fmt.Errorf("ledger DB is nil")
	}

	var maxSupply uint64
	var circulating float64
	var minersCount int
	var balancesCount int
	minerIDs := make(map[string]struct{})
	balanceHasMiner := make(map[string]bool)

	// Get the configured maximum supply constant
	if ledger.MaxSupplyEXPLO > 0 {
		maxSupply = ledger.MaxSupplyEXPLO
	}

	// Override with DB metadata if available
	_ = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("meta:max_supply"))
		if err == nil {
			val, err := item.ValueCopy(nil)
			if err == nil && len(val) >= 8 {
				var v uint64
				for i := 0; i < 8; i++ {
					v = (v << 8) | uint64(val[i])
				}
				maxSupply = v
			}
		}
		return nil
	})

	// Default fallback supply
	if maxSupply == 0 {
		maxSupply = 50_000_000
	}

	// Count miners (read-only scan)
	_ = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek([]byte("miner:")); it.ValidForPrefix([]byte("miner:")); it.Next() {
			id := string(bytes.TrimPrefix(it.Item().Key(), []byte("miner:")))
			if id != "" {
				minerIDs[id] = struct{}{}
			}
		}
		return nil
	})
	minersCount = len(minerIDs)

	// Sum balances and count holders (read-only)
	_ = db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte("balance:")); it.ValidForPrefix([]byte("balance:")); it.Next() {
			id := string(bytes.TrimPrefix(it.Item().Key(), []byte("balance:")))
			if id == "" {
				continue
			}
			bal := &ledger.Balance{}
			if err := l.GetObject(it.Item().Key(), bal); err != nil {
				continue
			}
			balancesCount++
			circulating += bal.EXPLO
			if _, ok := minerIDs[id]; ok {
				balanceHasMiner[id] = true
			}
		}
		return nil
	})

	// Total holders = miners + balances not linked to miners
	nonMinerHolders := balancesCount - len(balanceHasMiner)
	if nonMinerHolders < 0 {
		nonMinerHolders = 0
	}
	totalHolders := minersCount + nonMinerHolders

	// Compute miners remaining before next halving
	minersRemaining := computeMinersToNextHalving(minersCount)

	return &MetricsData{
		Timestamp:       time.Now().Unix(),
		MaxSupply:       maxSupply,
		Circulating:     circulating,
		TotalHolders:    totalHolders,
		MinersCount:     minersCount,
		MinersRemaining: minersRemaining,
	}, nil
}

// computeMinersToNextHalving returns the number of miners remaining
// until the next halving threshold. Fully deterministic.
func computeMinersToNextHalving(current int) int {
	thresholds := []int{100_000, 200_000, 500_000, 600_000, 1_000_000}
	for _, t := range thresholds {
		if current < t {
			return t - current
		}
	}
	return 0
}
