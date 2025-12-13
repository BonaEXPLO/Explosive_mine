package p2p

import (
    "bytes"
    "fmt"
    "time"

    "explosive/internal/ledger"
    "github.com/dgraph-io/badger/v4"
)

// MetricsData holds live chain statistics.
type MetricsData struct {
    Timestamp       int64   `json:"timestamp"`
    MaxSupply       uint64  `json:"max_supply"`
    Circulating     float64 `json:"circulating"`
    TotalHolders    int     `json:"total_holders"`
    MinersCount     int     `json:"miners_count"`
    MinersRemaining int     `json:"miners_remaining"`
}

// GatherMetrics calculates live metrics directly from the ledger DB.
// Logic fully mirrors internal/scan/exploscan.go
func GatherMetrics(l *ledger.Ledger) (*MetricsData, error) {
    if l == nil || l.GetDB() == nil {
        return nil, fmt.Errorf("ledger not initialized")
    }
    db := l.GetDB()

    var maxSupply uint64
    var circulating float64
    var minersCount int
    var balancesCount int
    minerIDs := make(map[string]struct{})
    balanceHasMiner := make(map[string]bool)

    // 1️⃣ MaxSupply
    if ledger.MaxSupplyEXPLO > 0 {
        maxSupply = ledger.MaxSupplyEXPLO
    }

    // try read from DB
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

    // fallback if still zero
    if maxSupply == 0 {
        maxSupply = 50_000_000
    }

    // 2️⃣ Count miners
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

    // 3️⃣ Sum balances and count holders
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

    // 4️⃣ Compute total holders
    nonMinerHolders := balancesCount - len(balanceHasMiner)
    if nonMinerHolders < 0 {
        nonMinerHolders = 0
    }
    totalHolders := minersCount + nonMinerHolders

    // 5️⃣ Compute miners remaining until next halving
    minersRemaining := computeMinersToNextHalving(minersCount)

    // return metrics
    return &MetricsData{
        Timestamp:       time.Now().Unix(),
        MaxSupply:       maxSupply,
        Circulating:     circulating,
        TotalHolders:    totalHolders,
        MinersCount:     minersCount,
        MinersRemaining: minersRemaining,
    }, nil
}

// computeMinersToNextHalving returns deterministic number of miners
// remaining to next halving threshold
func computeMinersToNextHalving(current int) int {
    thresholds := []int{100_000, 200_000, 500_000, 600_000, 1_000_000}
    for _, t := range thresholds {
        if current < t {
            return t - current
        }
    }
    return 0
}
