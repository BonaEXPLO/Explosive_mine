// internal/ledger/mine.go
package ledger

import (
	"errors"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"explosive/internal/address"
	"explosive/internal/guardian"
	"explosive/internal/halving"
	"explosive/internal/imanifund"
	"github.com/dgraph-io/badger/v4"
)

// -----------------------------
// Constants
// -----------------------------
const (
	MaxLumen           = 50.0
	MaxEXPLOSupply     = 50_000_000.0
	SecondsPerDay      = 24 * 60 * 60
	MinDonationPercent = 0.0
	MaxDonationPercent = 0.1
)

// MinerState stores temporary miner session info (cooldown, symbolic IMANI, LUMEN)
type MinerState struct {
	LastMineUnix int64   // timestamp of last mining session
	IMANI        float64 // symbolic IMANI minted
	LUMEN        float64 // spiritual power derived from IMANI
}

// -----------------------------
// Ledger method to expose DB safely
// -----------------------------
func (l *Ledger) GetDB() *badger.DB {
	return l.db
}

// -----------------------------
// GetTotalEXPLOIssued reads the total EXPLO issued from DB
// -----------------------------
func (l *Ledger) GetTotalEXPLOIssued() (float64, error) {
	var total float64
	err := l.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("totalEXPLOIssued"))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				total = 0
				return nil
			}
			return err
		}
		return item.Value(func(val []byte) error {
			total, err = strconv.ParseFloat(string(val), 64)
			return err
		})
	})
	return total, err
}

// -----------------------------
// UpdateTotalEXPLOIssued safely writes the new total EXPLO issued to DB
// -----------------------------
func (l *Ledger) UpdateTotalEXPLOIssued(newTotal float64) error {
	return l.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("totalEXPLOIssued"), []byte(fmt.Sprintf("%.8f", newTotal)))
	})
}

// -----------------------------
// Adaptive Proof-of-Work benchmark
// -----------------------------
func benchmarkPoW(message string, zeros int, duration time.Duration) bool {
	start := time.Now()
	prefix := strings.Repeat("0", zeros)

	for nonce := uint64(0); time.Since(start) < duration; nonce++ {
		data := fmt.Sprintf("%s:%d", message, nonce)
		hash := sha3.Sum256([]byte(data))
		hashHex := fmt.Sprintf("%x", hash[:8]) // first 8 bytes only for speed

		if strings.HasPrefix(hashHex, prefix) {
			return true
		}
	}
	return false
}

// -----------------------------
// Mine performs a mining session for a miner (hermetic supply)
// -----------------------------
// This function is defensive: it protects against uninitialized IMANI subsystem
// (which can happen during early bootstrap or after restoring older snapshots).
// If the IMANI module isn't ready, we gracefully continue — mining rewards are
// still applied to the ledger and the donation amount is recorded in DB.
func Mine(db *Ledger, miner *Miner, state *MinerState, donationPercent float64) error {
	now := time.Now().Unix()

	// Validate donation percent
	if donationPercent < MinDonationPercent || donationPercent > MaxDonationPercent {
		return errors.New("donation percent must be between 0% and 10%")
	}

	// Enforce 24h cooldown
	if state.LastMineUnix > 0 && now < state.LastMineUnix+SecondsPerDay {
		remain := (state.LastMineUnix + SecondsPerDay) - now
		fmt.Printf("⏳ Time until next mining: %d hours %d minutes\n", remain/3600, (remain%3600)/60)
		return errors.New("mining cooldown active")
	}

	// Validate miner ID
	if !address.IsValidEXPLOAddress(miner.ID) {
		return errors.New("invalid miner ID")
	}

	// Adaptive PoW benchmark
	fmt.Println("⚙️ Running adaptive PoW (10s max each)...")
	benchmarks := []struct {
		name  string
		zeros int
	}{
		{"Benchmark1 (3 zeros)", 3},
		{"Benchmark2 (4 zeros)", 4},
		{"Benchmark3 (5 zeros)", 5},
	}

	passed := false
	for _, bench := range benchmarks {
		if benchmarkPoW("benchmark", bench.zeros, 10*time.Second) {
			fmt.Printf("✅ %s passed!\n", bench.name)
			passed = true
			break
		} else {
			fmt.Printf("⚠️ %s failed\n", bench.name)
		}
	}
	if !passed {
		return errors.New("❌ device not eligible for mining today")
	}

	// Halving-aware reward
	exploReward, err := halving.GetCurrentReward(db.GetDB())
	if err != nil {
		return fmt.Errorf("failed to get halving reward: %v", err)
	}

	donationAmount := exploReward * donationPercent
	netReward := exploReward - donationAmount
	imaniMint := donationAmount * 1000

	// Atomic update totalEXPLOIssued with DB transaction
	err = db.db.Update(func(txn *badger.Txn) error {
		// Get current total
		var total float64
		item, err := txn.Get([]byte("totalEXPLOIssued"))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				total = 0
			} else {
				return err
			}
		} else {
			err = item.Value(func(val []byte) error {
				total, err = strconv.ParseFloat(string(val), 64)
				return err
			})
			if err != nil {
				return err
			}
		}

		if total+netReward > MaxEXPLOSupply {
			return errors.New("❌ mining would exceed maximum EXPLO supply, aborted")
		}

		// Update total in DB
		newTotal := total + netReward
		if err := txn.Set([]byte("totalEXPLOIssued"), []byte(fmt.Sprintf("%.8f", newTotal))); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to safely update total EXPLO issued: %v", err)
	}

	// Mint IMANI (symbolic)
	state.IMANI += imaniMint
	state.LUMEN = math.Sqrt(state.IMANI)
	if state.LUMEN > MaxLumen {
		state.LUMEN = MaxLumen
	}

	// Register LUMEN in IMANI fund — protect against nil or uninitialized imanifund package.
	func() {
		defer func() {
			if r := recover(); r != nil {
				// IMANI subsystem not initialized or panicked — log and continue.
				log.Printf("imanifund.RegisterLumen panic recovered: %v — continuing without IMANI persistence", r)
			}
		}()
		imanifund.RegisterLumen(miner.ID, state.LUMEN)
	}()

	// Send donation — try IMANI fund first, fallback to persisting donpool to ledger DB on failure.
	addedToImani := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("imanifund.AddDonation panic recovered: %v — falling back to ledger donpool", r)
			}
		}()
		if err := imanifund.AddDonation(miner.ID, donationAmount); err != nil {
			// If AddDonation returns an error, log and fallback to ledger donpool storage
			log.Printf("imanifund.AddDonation error: %v — falling back to ledger donpool", err)
			return
		}
		addedToImani = true
	}()

	if !addedToImani && donationAmount > 0 {
		// Persist donation to ledger-level donpool as a durable fallback
		if err := CreditDonpool(db, donationAmount); err != nil {
			// Non-fatal for mining; log and continue
			log.Printf("CreditDonpool failed: %v", err)
		}
	}

	// Credit miner by creating and applying the mining reward transaction
	tx, err := NewMiningReward(miner.ID, netReward, imaniMint, time.Now().UnixMilli())
	if err != nil {
		return fmt.Errorf("failed to create mining reward tx: %v", err)
	}
	msg, err := db.ApplyAndPersistTransaction(tx)
	if err != nil {
		return fmt.Errorf("failed to apply mining reward: %v", err)
	}

	state.LastMineUnix = now

	// 💡 Inspire the miner with Guardian's ephemeral message
	encMsg := guardian.EncourageMessageEphemeral(miner.ConsciousnessFingerprint)
	totalMsgs := guardian.GetTotalMessages()

	// Display mining result
	fmt.Println(msg)
	fmt.Printf("🌟 LUMEN: %.2f / %.2f\n", state.LUMEN, MaxLumen)
	fmt.Println("💬 Guardian says:", encMsg)
	fmt.Printf("📜 Guardian has inspired miners %d times so far.\n", totalMsgs)

	return nil
}

// CreditDonpool ajoute le montant donné au donpool global du ledger
func CreditDonpool(db *Ledger, amount float64) error {
	if amount <= 0 {
		return nil
	}

	return db.db.Update(func(txn *badger.Txn) error {
		var current float64
		item, err := txn.Get([]byte("donpool"))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				current = 0
			} else {
				return err
			}
		} else {
			err = item.Value(func(val []byte) error {
				current, err = strconv.ParseFloat(string(val), 64)
				return err
			})
			if err != nil {
				return err
			}
		}

		newTotal := current + amount
		return txn.Set([]byte("donpool"), []byte(fmt.Sprintf("%.8f", newTotal)))
	})
}

func CreditSoul(db *Ledger, minerID string, amount float64) error {
    balanceKey := []byte("balance:" + minerID)
    bal := &Balance{}
    if err := db.GetObject(balanceKey, bal); err != nil {
        bal = &Balance{}
    }
    bal.EXPLO += amount
    return db.PutObject(balanceKey, bal)
}
