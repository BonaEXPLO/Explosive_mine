// internal/scan/exploscan.go
package scan

import (
	"bytes"
	"fmt"
	"time"

	"explosive/internal/ledger"
	"explosive/internal/halving"

	"github.com/dgraph-io/badger/v4"
)

// StartExploscan launches a scanner that prints chain metrics every second and every minute.
// It only reads the DB, it does not write anything.
func StartExploscan(l *ledger.Ledger, stopCh <-chan struct{}) {
	if l == nil || l.GetDB() == nil {
		fmt.Println("❌ Exploscan: ledger not initialized")
		return
	}

	secTicker := time.NewTicker(1 * time.Second)
	minTicker := time.NewTicker(1 * time.Minute)

	go func() {
		defer secTicker.Stop()
		defer minTicker.Stop()

		for {
			select {
			case <-stopCh:
				fmt.Println("🛑 Exploscan stopped")
				return
			case <-secTicker.C:
				maxSupply, circ, holders, minersCount, minersRemaining, err := ScanAllMetrics(l)
				if err != nil {
					fmt.Printf("⚠️ Exploscan (sec) error: %v\n", err)
					continue
				}
				now := time.Now().Format("15:04:05")
				fmt.Printf("[%s] EXPLO Max:%d  Circulating:%.3f  Holders:%d  Miners:%d  NextHalvingIn:%d\n",
					now, maxSupply, circ, holders, minersCount, minersRemaining)
			case <-minTicker.C:
				maxSupply, circ, holders, minersCount, minersRemaining, err := ScanAllMetrics(l)
				if err != nil {
					fmt.Printf("⚠️ Exploscan (min) error: %v\n", err)
					continue
				}
				fmt.Println("────────────────────────────────────────────────────────")
				fmt.Println("📊 EXPLOSIVE CHAIN METRICS (minute report)")
				fmt.Printf("  • Time: %s\n", time.Now().Format(time.RFC3339))
				fmt.Printf("  • Max supply configured : %d EXPLO\n", maxSupply)
				fmt.Printf("  • Circulating supply    : %.6f EXPLO\n", circ)
				fmt.Printf("  • Total holders         : %d (miners + ordinary holders)\n", holders)
				fmt.Printf("  • Current miners        : %d\n", minersCount)
				if minersRemaining > 0 {
					fmt.Printf("  • Miners remaining to next halving: %d\n", minersRemaining)
				} else {
					fmt.Printf("  • Next halving: threshold already reached or final halving\n")
				}
				if reward, err := halving.GetCurrentReward(l.GetDB()); err == nil {
					fmt.Printf("  • Current EXPLO reward   : %.8f EXPLO\n", reward)
				}
				fmt.Println("────────────────────────────────────────────────────────")
			}
		}
	}()
}

// scanAllMetrics computes all chain metrics: max supply, circulating supply, total holders, miners count, miners to next halving.
func ScanAllMetrics(l *ledger.Ledger) (uint64, float64, int, int, int, error) {
	db := l.GetDB()
	if db == nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("ledger DB is nil")
	}

	var maxSupply uint64
	var circulating float64
	var minersCount int
	var balancesCount int
	minerIDs := make(map[string]struct{})
	balanceHasMiner := make(map[string]bool)

	// 1️⃣ Get max supply from ledger constant first
	if ledger.MaxSupplyEXPLO > 0 {
		maxSupply = ledger.MaxSupplyEXPLO
	}

	// 2️⃣ Override if meta:max_supply exists in DB
	err := db.View(func(txn *badger.Txn) error {
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
	if err != nil {
		// non-fatal
	}

	// fallback safe if maxSupply still zero
	if maxSupply == 0 {
		maxSupply = 50_000_000 // updated max supply
	}

	// 3️⃣ Count miners
	err = db.View(func(txn *badger.Txn) error {
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
	if err != nil {
		return maxSupply, circulating, 0, 0, 0, fmt.Errorf("failed to iterate miners: %v", err)
	}
	minersCount = len(minerIDs)

	// 4️⃣ Sum balances and holders
	err = db.View(func(txn *badger.Txn) error {
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
	if err != nil {
		return maxSupply, circulating, 0, 0, 0, fmt.Errorf("failed to iterate balances: %v", err)
	}

	// 5️⃣ Total holders = miners + (balances not attached to miners)
	nonMinerHolders := balancesCount - len(balanceHasMiner)
	if nonMinerHolders < 0 {
		nonMinerHolders = 0
	}
	totalHolders := minersCount + nonMinerHolders

	// 6️⃣ Miners remaining to next halving
	minersRemaining := computeMinersToNextHalving(minersCount)

	return maxSupply, circulating, totalHolders, minersCount, minersRemaining, nil
}

// computeMinersToNextHalving returns number of miners remaining for next halving threshold.
func computeMinersToNextHalving(current int) int {
	thresholds := []int{100000, 200000, 500000, 600000, 1000000}
	for _, t := range thresholds {
		if current < t {
			return t - current
		}
	}
	return 0
}
