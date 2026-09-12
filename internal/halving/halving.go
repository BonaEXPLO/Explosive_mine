// internal/halving/halving.go
package halving

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/dgraph-io/badger/v4"
	"golang.org/x/crypto/sha3"
)

//
// ============================================================
// EXPLOSIVE HALVING SYSTEM — CONSENSUS SAFE VERSION
// ============================================================
//
// 1 EXPLO = 1,000,000,000 Pastabo
// All rewards are stored internally as uint64 Pastabo
// No float64 is used to guarantee deterministic consensus
//

const PastaboPerEXPLO uint64 = 1_000_000_000

// ------------------------------------------------------------
// Halving reward table (Pastabo units)
// ------------------------------------------------------------

var halvingRewardsPastabo = []uint64{
	250_000_000, // 0.25 EXPLO  (< 100k miners)
	125_000_000, // 0.125 EXPLO (>= 100k)
	62_500_000,  // 0.0625
	31_250_000,  // 0.03125
	15_625_000,  // 0.015625
	7_812_500,   // 0.0078125 (>= 1M)
}

// ------------------------------------------------------------
// Miner Counter (On-Chain State)
// ------------------------------------------------------------

// IncrementMinerCount increments global miner_count
func IncrementMinerCount(db *badger.DB) error {
	return db.Update(func(txn *badger.Txn) error {

		key := []byte("miner_count")

		var count uint64 = 0

		if item, err := txn.Get(key); err == nil {
			_ = item.Value(func(val []byte) error {
				count = binary.BigEndian.Uint64(val)
				return nil
			})
		}

		count++

		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, count)

		return txn.Set(key, buf)
	})
}

// GetMinerCount reads global miner_count
func GetMinerCount(db *badger.DB) (uint64, error) {

	var count uint64

	err := db.View(func(txn *badger.Txn) error {

		item, err := txn.Get([]byte("miner_count"))
		if err != nil {

			if err == badger.ErrKeyNotFound {
				count = 0
				return nil
			}

			return err
		}

		return item.Value(func(val []byte) error {
			count = binary.BigEndian.Uint64(val)
			return nil
		})
	})

	return count, err
}

// ------------------------------------------------------------
// Halving Logic
// ------------------------------------------------------------

// GetHalvingLevel returns the halving level based on miner count
func GetHalvingLevel(db *badger.DB) (int, error) {

	count, err := GetMinerCount(db)
	if err != nil {
		return 0, fmt.Errorf("failed to read miner_count: %v", err)
	}

	var level int

	switch {
	case count >= 1_000_000:
		level = 5
	case count >= 600_000:
		level = 4
	case count >= 500_000:
		level = 3
	case count >= 200_000:
		level = 2
	case count >= 100_000:
		level = 1
	default:
		level = 0
	}

	log.Printf("📊 Halving level: %d (%d miners)", level, count)

	return level, nil
}

// ------------------------------------------------------------
// Reward Accessors (Consensus Safe)
// ------------------------------------------------------------

// GetCurrentRewardPastabo returns current mining reward in Pastabo
func GetCurrentRewardPastabo(db *badger.DB) (uint64, error) {

	level, err := GetHalvingLevel(db)
	if err != nil {
		return 0, err
	}

	if level < 0 || level >= len(halvingRewardsPastabo) {
		return 0, errors.New("invalid halving level")
	}

	reward := halvingRewardsPastabo[level]

	log.Printf("🎁 Current reward: %d Pastabo (Level %d)", reward, level)

	return reward, nil
}

// GetCurrentRewardEXPLO returns reward in EXPLO (human readable only)
func GetCurrentRewardEXPLO(db *badger.DB) (float64, error) {

	pastabo, err := GetCurrentRewardPastabo(db)
	if err != nil {
		return 0, err
	}

	return float64(pastabo) / float64(PastaboPerEXPLO), nil
}

// ------------------------------------------------------------
// Reward Signatures (Security Layer)
// ------------------------------------------------------------

// hashReward computes SHA3-256 hash of reward message (Pastabo)
func hashReward(rewardPastabo uint64) []byte {

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, rewardPastabo)

	h := sha3.Sum256(buf)

	return h[:]
}

// SignReward signs the reward using Ed25519 private key
func SignReward(rewardPastabo uint64, privKey ed25519.PrivateKey) ([]byte, error) {

	hash := hashReward(rewardPastabo)

	sig := ed25519.Sign(privKey, hash)

	return sig, nil
}

// VerifyRewardSignature verifies reward signature
func VerifyRewardSignature(rewardPastabo uint64, pubKey ed25519.PublicKey, signature []byte) bool {

	hash := hashReward(rewardPastabo)

	return ed25519.Verify(pubKey, hash, signature)
}

// HexEncodeSignature helper
func HexEncodeSignature(sig []byte) string {
	return hex.EncodeToString(sig)
}

// ------------------------------------------------------------
// On-Chain Halving Metadata (meta:halving_level)
// ------------------------------------------------------------

var halvingLevelKey = []byte("meta:halving_level")

// GetStoredHalvingLevel reads halving level stored in ledger metadata.
// Returns 0 if not found.
func GetStoredHalvingLevel(db *badger.DB) (uint32, error) {

	var level uint32 = 0

	err := db.View(func(txn *badger.Txn) error {

		item, err := txn.Get(halvingLevelKey)
		if err != nil {

			if err == badger.ErrKeyNotFound {
				level = 0
				return nil
			}

			return err
		}

		return item.Value(func(val []byte) error {

			if len(val) != 4 {
				return errors.New("invalid halving level encoding")
			}

			level = binary.BigEndian.Uint32(val)
			return nil
		})
	})

	return level, err
}

// SetStoredHalvingLevel writes halving level into ledger metadata.
func SetStoredHalvingLevel(db *badger.DB, level uint32) error {

	return db.Update(func(txn *badger.Txn) error {

		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, level)

		return txn.Set(halvingLevelKey, buf)
	})
}

// UpdateHalvingLevelIfNeeded recalculates halving level and updates
// on-chain metadata only if a change occurred.
func UpdateHalvingLevelIfNeeded(db *badger.DB) (uint32, error) {

	calculatedLevel, err := GetHalvingLevel(db)
	if err != nil {
		return 0, err
	}

	storedLevel, err := GetStoredHalvingLevel(db)
	if err != nil {
		return 0, err
	}

	if uint32(calculatedLevel) == storedLevel {
		return storedLevel, nil
	}

	// Level changed → persist new value
	if err := SetStoredHalvingLevel(db, uint32(calculatedLevel)); err != nil {
		return 0, err
	}

	log.Printf(
		"🚀 HALVING LEVEL UPDATED: %d → %d",
		storedLevel,
		calculatedLevel,
	)

	return uint32(calculatedLevel), nil
}
