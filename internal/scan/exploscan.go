package scan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"explosive/internal/ledger"

	"github.com/dgraph-io/badger/v4"
)

const (
	metaCirculatingKey = "meta:circulating_explo"
	metaMinersKey      = "meta:miners_count"
	metaHoldersKey     = "meta:holders_count"
	metaLastUpdateKey  = "meta:last_update"
)

// ---------------------------------------------------
// MetricsData — Canonical deterministic metrics
// ---------------------------------------------------
type MetricsData struct {
	Timestamp       int64   `json:"timestamp"`
	MaxSupply       float64 `json:"max_supply_explo"`
	Circulating     float64 `json:"circulating_explo"`
	TotalHolders    uint64  `json:"total_holders"`
	MinersCount     uint64  `json:"miners_count"`
	MinersRemaining uint64  `json:"miners_remaining"`
}

// ---------------------------------------------------
// Broadcaster interface
// ---------------------------------------------------
type Broadcaster interface {
	BroadcastMessage(msgType string, payload any) error
}

// ---------------------------------------------------
// StartExploscan — background broadcaster
// ---------------------------------------------------
func StartExploscan(l *ledger.Ledger, broadcaster Broadcaster, stopCh <-chan struct{}) {
	if l == nil || l.DB() == nil {
		log.Println("❌ Exploscan: ledger not initialized")
		return
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				metrics, err := GatherMetrics(l)
				if err != nil {
					log.Println("❌ Exploscan gather error:", err)
					continue
				}

				if broadcaster != nil {
					_ = broadcaster.BroadcastMessage("METRICS", metrics)
				}

			case <-stopCh:
				log.Println("🛑 Exploscan stopped")
				return
			}
		}
	}()
}

// ---------------------------------------------------
// GatherMetrics — Always deterministic
// ---------------------------------------------------
func GatherMetrics(l *ledger.Ledger) (*MetricsData, error) {
	if l == nil || l.DB() == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}

	// Always rebuild from balances for deterministic correctness
	meta, err := scanBalances(l)
	if err != nil {
		return nil, err
	}

	// Write cache (non-authoritative)
	_ = writeMeta(l.DB(), meta)

	return meta, nil
}

// ---------------------------------------------------
// scanBalances — SINGLE SOURCE OF TRUTH
// ---------------------------------------------------
func scanBalances(l *ledger.Ledger) (*MetricsData, error) {
	db := l.DB()

	var circulatingPastabo uint64
	var holders uint64
	minerIDs := make(map[string]struct{})

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()

			// ------------------------------
			// BALANCES
			// ------------------------------
			if bytes.HasPrefix(key, []byte("balance:")) {
				var bal ledger.Balance
				if err := l.GetObject(key, &bal); err != nil {
					continue
				}

				if bal.EXPLO > 0 {
					circulatingPastabo += bal.EXPLO
					holders++
				}
			}

			// ------------------------------
			// MINERS
			// ------------------------------
			if bytes.HasPrefix(key, ledger.PrefixMiner) {
				id := string(bytes.TrimPrefix(key, ledger.PrefixMiner))
				if id != "" {
					minerIDs[id] = struct{}{}
				}
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	miners := uint64(len(minerIDs))

	return &MetricsData{
		Timestamp:       time.Now().Unix(),
		MaxSupply:       float64(ledger.MaxPastaboSupply) / float64(ledger.PastaboPerEXPLO),
		Circulating:     float64(circulatingPastabo) / float64(ledger.PastaboPerEXPLO),
		TotalHolders:    holders,
		MinersCount:     miners,
		MinersRemaining: computeMinersToNextHalving(miners),
	}, nil
}

// ---------------------------------------------------
// writeMeta — cache only (never authoritative)
// ---------------------------------------------------
func writeMeta(db *badger.DB, m *MetricsData) error {
	return db.Update(func(txn *badger.Txn) error {

		writeUint := func(key string, v uint64) error {
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, v)
			return txn.Set([]byte(key), buf)
		}

		circPastabo := uint64(m.Circulating * float64(ledger.PastaboPerEXPLO))

		if err := writeUint(metaCirculatingKey, circPastabo); err != nil {
			return err
		}
		if err := writeUint(metaMinersKey, m.MinersCount); err != nil {
			return err
		}
		if err := writeUint(metaHoldersKey, m.TotalHolders); err != nil {
			return err
		}
		if err := writeUint(metaLastUpdateKey, uint64(m.Timestamp)); err != nil {
			return err
		}

		return nil
	})
}

// ---------------------------------------------------
// Halving logic
// ---------------------------------------------------
func computeMinersToNextHalving(current uint64) uint64 {
	thresholds := []uint64{
		100_000,
		200_000,
		500_000,
		600_000,
		1_000_000,
	}

	for _, t := range thresholds {
		if current < t {
			return t - current
		}
	}
	return 0
}
