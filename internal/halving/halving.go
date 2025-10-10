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

// Table of daily EXPLO rewards by halving level
var halvingRewards = []float64{
	0.25,      // Level 0: < 100k miners
	0.125,     // Level 1: >= 100k
	0.0625,    // Level 2: >= 200k
	0.03125,   // Level 3: >= 500k
	0.015625,  // Level 4: >= 600k
	0.0078125, // Level 5: >= 1M
}

// ------------------- Miner Counter -------------------

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

// ------------------- Halving Logic -------------------

// GetHalvingLevel returns the halving level based on number of miners.
func GetHalvingLevel(db *badger.DB) (int, error) {
	count, err := GetMinerCount(db)
	if err != nil {
		return 0, fmt.Errorf("❌ failed to read miner_count: %v", err)
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

	log.Printf("📊 Halving level determined: %d (%d miners)", level, count)
	return level, nil
}

// GetCurrentReward returns the current reward for mining based on halving level.
func GetCurrentReward(db *badger.DB) (float64, error) {
	level, err := GetHalvingLevel(db)
	if err != nil {
		return 0, err
	}
	if level < 0 || level >= len(halvingRewards) {
		return 0, errors.New("invalid halving level")
	}
	reward := halvingRewards[level]
	log.Printf("🎁 Current reward: %.8f EXPLO (Level %d)", reward, level)
	return reward, nil
}

// ------------------- Signatures -------------------

// hashReward computes SHA3-256 hash of reward message
func hashReward(reward float64) []byte {
	msg := fmt.Sprintf("%.8f", reward)
	h := sha3.Sum256([]byte(msg))
	return h[:]
}

// SignReward signs the reward with Ed25519 private key
func SignReward(reward float64, privKey ed25519.PrivateKey) ([]byte, error) {
	hash := hashReward(reward)
	return ed25519.Sign(privKey, hash), nil
}

// VerifyRewardSignature checks the reward’s signature using Ed25519 public key
func VerifyRewardSignature(reward float64, pubKey ed25519.PublicKey, signature []byte) bool {
	hash := hashReward(reward)
	return ed25519.Verify(pubKey, hash, signature)
}

// HexEncodeSignature helper for pretty-print
func HexEncodeSignature(sig []byte) string {
	return hex.EncodeToString(sig)
}
