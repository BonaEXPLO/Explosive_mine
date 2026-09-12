package ledger

import (
	"encoding/binary"
	"fmt"
        "encoding/hex"
	"log"
	"math"
	"math/rand"
	"sort"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"
)

const (
	DistributionIntervalBlocks uint64 = 1440 // ~1 day
	MaxEligibleMinersPerRound         = 5000
	DistributionVersion        uint8  = 1
)

const (
	MinPoolPastabo  uint64 = 50 * PastaboPerEXPLO
	BlessingPastabo uint64 = 1 * PastaboPerEXPLO
)

type DistributionMetadata struct {
	Version       uint8    `cbor:"v"`
	Round         uint32   `cbor:"round"`
	Seed          [32]byte `cbor:"seed"`
	EligibleCount uint32   `cbor:"elig"`
	SuccessCount  uint32   `cbor:"succ"`
	TotalAmount   uint64   `cbor:"amt"`
	TriggerHeight uint64   `cbor:"height"`
	TriggerTime   int64    `cbor:"ts"`
}

// TryDistributeBlessings distributes IMANI blessings deterministically and atomically.
func (l *Ledger) TryDistributeBlessings(block *Block) error {
	if l == nil || l.db == nil || block == nil {
		return fmt.Errorf("invalid ledger or block")
	}

	height := block.Header.Height

	// Trigger only at fixed interval
	if height%DistributionIntervalBlocks != 0 {
		return nil
	}

	round := uint32(height / DistributionIntervalBlocks)
	roundKey := []byte(fmt.Sprintf("dist:done:v%d:%d", DistributionVersion, round))

	return l.db.Update(func(txn *badger.Txn) error {

		// ---------------- Idempotence ----------------
		if _, err := txn.Get(roundKey); err == nil {
			return nil
		} else if err != badger.ErrKeyNotFound {
			return err
		}

		// ---------------- Load pool safely ----------------
		item, err := txn.Get([]byte("meta:imani_pool"))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return nil
			}
			return err
		}

		var poolPastabo uint64
		if err := item.Value(func(val []byte) error {
			if len(val) != 8 {
				return fmt.Errorf("invalid imani_pool size")
			}
			poolPastabo = binary.BigEndian.Uint64(val)
			return nil
		}); err != nil {
			return err
		}

		if poolPastabo < MinPoolPastabo {
			return nil
		}

		// ---------------- Eligible miners ----------------
		eligible := l.getEligibleMinerIDsDeterministicTxn(txn)
		if len(eligible) == 0 {
			return nil
		}

		sort.Strings(eligible)

		if len(eligible) > MaxEligibleMinersPerRound {
			eligible = eligible[:MaxEligibleMinersPerRound]
		}

		required := uint64(len(eligible)) * BlessingPastabo
		if poolPastabo < required {
			return nil
		}

		// ---------------- Deterministic seed ----------------
		var seedInput [128]byte

		// IMPORTANT FIX: use HASH not raw string (deterministic size)
		prevHashBytes, err := hexTo32Bytes(block.Header.PrevHash)
		if err != nil {
			return fmt.Errorf("invalid prev hash: %w", err)
		}

		copy(seedInput[0:32], prevHashBytes)
		binary.BigEndian.PutUint64(seedInput[32:40], height)
		binary.BigEndian.PutUint32(seedInput[40:44], round)
		copy(seedInput[44:76], []byte("EXPLOSIVE-IMANI-DISTRIBUTION-v1"))

		seed := sha3.Sum256(seedInput[:])
		shuffled := deterministicShuffle(eligible, seed[:])

		var success uint32
		var total uint64
		var failures int

		// ---------------- Distribution loop ----------------
		for i, minerID := range shuffled {

			tx := &Transaction{
				From:          "SYSTEM",
				To:            minerID,
				AmountPastabo: BlessingPastabo,
				AmountEXP:     float64(BlessingPastabo) / float64(PastaboPerEXPLO),
				IsReward:      true,
				Timestamp:     block.Header.Timestamp,
				Nonce:         int64(height<<32 | uint64(i)),
				Note:          fmt.Sprintf("IMANI blessing round %d", round),
			}

			tx.TxHash = tx.ComputeHash()

			// ---------------- Load balance safely ----------------
			balKey := []byte("balance:" + minerID)
			recipient := &Balance{}

			if item, err := txn.Get(balKey); err == nil {
				_ = item.Value(func(val []byte) error {
					return cbor.Unmarshal(val, recipient)
				})
			}

			balances := map[string]*Balance{
				minerID: recipient,
			}

			_, err = ApplyTransaction(balances, tx, l)
			if err != nil {
				failures++
				log.Printf("[dist] tx failed for %s: %v", safeID(minerID), err)
				continue
			}

			encoded, err := cbor.Marshal(recipient)
			if err != nil {
				failures++
				continue
			}

			if err := txn.Set(balKey, encoded); err != nil {
				failures++
				continue
			}

			success++
			total += BlessingPastabo
		}

		if success == 0 {
			log.Printf("[dist] no successful blessings in round %d (failures=%d)", round, failures)
			return nil
		}

		// ---------------- Update pool ----------------
		newPool := poolPastabo - total
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, newPool)

		if err := txn.Set([]byte("meta:imani_pool"), buf); err != nil {
			return err
		}

		if err := txn.Set(roundKey, []byte{1}); err != nil {
			return err
		}

		// ---------------- Attach metadata ----------------
		block.Header.DistributionMeta = DistributionMetadata{
			Version:       DistributionVersion,
			Round:         round,
			Seed:          seed,
			EligibleCount: uint32(len(eligible)),
			SuccessCount:  success,
			TotalAmount:   total,
			TriggerHeight: height,
			TriggerTime:   block.Header.Timestamp,
		}

		log.Printf("[dist] round %d success: %d/%d | %.6f EXPLO",
			round, success, len(eligible),
			float64(total)/float64(PastaboPerEXPLO))

		return nil
	})
}

// Deterministic eligible miner selection
func (l *Ledger) getEligibleMinerIDsDeterministicTxn(txn *badger.Txn) []string {
	var ids []string

	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = true

	it := txn.NewIterator(opts)
	defer it.Close()

	prefix := []byte(PrefixMiner)

	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {

		key := it.Item().Key()
		minerID := string(key[len(prefix):])

		balKey := []byte("balance:" + minerID)
		item, err := txn.Get(balKey)
		if err != nil {
			continue
		}

		var bal Balance
		if err := item.Value(func(val []byte) error {
			return cbor.Unmarshal(val, &bal)
		}); err != nil {
			continue
		}

		if bal.IMANI == 0 {
			continue
		}

		imaniEXPLO := float64(bal.IMANI) / float64(PastaboPerEXPLO)
		lumen := math.Min(math.Sqrt(imaniEXPLO), 50.0)

		if lumen >= 15.0 && lumen <= 50.0 {
			ids = append(ids, minerID)
		}
	}

	return ids
}

func deterministicShuffle(ids []string, seed []byte) []string {
	out := make([]string, len(ids))
	copy(out, ids)

	if len(out) <= 1 {
		return out
	}

	h := sha3.Sum256(seed)
	rngSeed := int64(binary.BigEndian.Uint64(h[:8]))

	r := rand.New(rand.NewSource(rngSeed))
	r.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})

	return out
}

// ---------------- HELPERS ----------------

func hexTo32Bytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return b, nil
}

func safeID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
