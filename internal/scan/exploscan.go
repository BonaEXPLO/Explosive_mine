package scan

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"explosive/internal/ledger"

	"github.com/dgraph-io/badger/v4"
)

// MetricsData represents canonical on-chain metrics
type MetricsData struct {
	Timestamp       int64   `json:"timestamp"`
	MaxSupply       float64 `json:"max_supply_explo"`
	Circulating     float64 `json:"circulating_explo"`
	TotalHolders    uint64  `json:"total_holders"`
	MinersCount     uint64  `json:"miners_count"`
	MinersRemaining uint64  `json:"miners_remaining"`
}

// Broadcaster sends metrics to the network
type Broadcaster interface {
	BroadcastMessage(msgType string, payload any) error
}

// StartExploscan launches a silent on-demand metrics engine
func StartExploscan(l *ledger.Ledger, broadcaster Broadcaster, stopCh <-chan struct{}) {
	if l == nil || l.DB() == nil {
		log.Println("❌ Exploscan: ledger not initialized")
		return
	}

	go func() {
		<-stopCh
		log.Println("🛑 Exploscan stopped")
	}()
}

// ---------------------------------------------------
// GatherMetrics — SINGLE SOURCE OF TRUTH
// ---------------------------------------------------
func GatherMetrics(l *ledger.Ledger) (*MetricsData, error) {
	if l == nil || l.DB() == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}

	db := l.DB()

	var (
		minerIDs     = make(map[string]struct{})
		balanceCount uint64
		circulating  float64
	)

	// 1️⃣ Scan miners
	if err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte("miner:")); it.ValidForPrefix([]byte("miner:")); it.Next() {
			id := string(bytes.TrimPrefix(it.Item().Key(), []byte("miner:")))
			if id != "" {
				minerIDs[id] = struct{}{}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// 2️⃣ Scan balances & sum EXPLO
	if err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte("balance:")); it.ValidForPrefix([]byte("balance:")); it.Next() {
			var bal ledger.Balance
			if err := l.GetObject(it.Item().Key(), &bal); err != nil {
				continue
			}
			circulating += bal.EXPLO
			balanceCount++
		}
		return nil
	}); err != nil {
		return nil, err
	}

	miners := uint64(len(minerIDs))
	holders := balanceCount
	if holders < miners {
		holders = miners
	}

	return &MetricsData{
		Timestamp:       time.Now().Unix(),
		MaxSupply:       float64(ledger.MaxPastaboSupply) / float64(ledger.PastaboPerEXPLO),
		Circulating:     circulating,
		TotalHolders:    holders,
		MinersCount:     miners,
		MinersRemaining: computeMinersToNextHalving(miners),
	}, nil
}

// ---------------------------------------------------
// Halving logic (deterministic)
// ---------------------------------------------------
func computeMinersToNextHalving(current uint64) uint64 {
	thresholds := []uint64{100_000, 200_000, 500_000, 600_000, 1_000_000}
	for _, t := range thresholds {
		if current < t {
			return t - current
		}
	}
	return 0
}
