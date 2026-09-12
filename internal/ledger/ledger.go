package ledger

import (
	"bytes"
	"encoding/binary"
	"errors"
        "strings"
	"fmt"
	"log"
	"math"
	"encoding/hex"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
        "explosive/internal/address"
        "explosive/internal/compressor"
	"github.com/fxamacker/cbor/v2"
)

// ---------------- Constants ----------------

const (
	PastaboPerEXPLO uint64 = 1_000_000_000
	MaxEXPLOSupply  uint64 = 50_000_000
	MaxPastaboSupply       = MaxEXPLOSupply * PastaboPerEXPLO
)

var (
	PrefixBlock   = []byte("blk:")
	PrefixTx      = []byte("tx:")
	PrefixAccount = []byte("acct:")
	PrefixMiner   = []byte("miner:")
	PrefixMeta    = []byte("meta:")

	MetaTotalIssued = append(PrefixMeta, []byte("total_issued")...)
	MetaChainTip    = append(PrefixMeta, []byte("chain_tip")...)
)

// ---------------- Ledger Struct ----------------

type Ledger struct {
	db     *badger.DB
	dbPath string

	asyncCh   chan kvPair
	stopAsync chan struct{}

	cborPool sync.Pool

	pruningMu        sync.Mutex
	lastPrunedHeight uint64
}

type kvPair struct {
	key []byte
	val []byte
}

// ---------------- OpenLedger ----------------

func OpenLedger(path string) (*Ledger, error) {
	opts := badger.DefaultOptions(path)
	opts.SyncWrites = false
	opts.Logger = nil

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open ledger DB: %w", err)
	}

	l := &Ledger{
		db:       db,
		dbPath:   path,
		asyncCh:  make(chan kvPair, 100_000),
		stopAsync: make(chan struct{}),
		cborPool: sync.Pool{
			New: func() interface{} { return new(bytes.Buffer) },
		},
		lastPrunedHeight: 0,
	}

	go l.asyncWriter()

	if err := InitLedger(l); err != nil {
		_ = db.Close()
		return nil, err
	}

	return l, nil
}

func InitLedger(l *Ledger) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    // Try to fetch existing Genesis
    block0, err := l.GetBlockByHeight(0)
    if err == nil && block0 != nil {
        if err := VerifyGenesis(l); err != nil {
            return err
        }
        fmt.Println("✅ Genesis block already exists and verified.")
        fmt.Printf("⚠️  %d EXPLO are permanently locked and cannot be spent.\n", GenesisEXPLO)
        return nil
    }

    // Genesis does not exist — create it
    block0, err = CreateGenesisBlock(l)
    if err != nil {
        return fmt.Errorf("failed to create genesis: %w", err)
    }

    // Double-check block 0 is now readable
    blockCheck, err := l.GetBlockByHeight(0)
    if err != nil || blockCheck == nil {
        return fmt.Errorf("genesis block created but cannot be read: %w", err)
    }

    return nil
}

func (l *Ledger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	close(l.stopAsync)
	return l.db.Close()
}

// ---------------- Async Writer ----------------

// asyncWriter listens on asyncCh and flushes writes to the DB
func (l *Ledger) asyncWriter() {
	for {
		select {
		case kv := <-l.asyncCh:
			_ = l.db.Update(func(txn *badger.Txn) error {
				return txn.Set(kv.key, kv.val)
			})
		case <-l.stopAsync:
			return
		}
	}
}

// AsyncPut is a fire-and-forget write using asyncCh
func (l *Ledger) AsyncPut(key, val []byte) {
	if l == nil || l.db == nil {
		return
	}

	select {
	case l.asyncCh <- kvPair{key, val}:
	default:
		_ = l.db.Update(func(txn *badger.Txn) error {
			return txn.Set(key, val)
		})
	}
}

// ---------------- Generic KV ----------------

func (l *Ledger) PutBytes(key, value []byte) error {
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}
	return l.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

func (l *Ledger) GetBytes(key []byte) ([]byte, error) {
	if l == nil || l.db == nil {
		return nil, errors.New("ledger not initialized")
	}
	var out []byte
	err := l.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		out, err = item.ValueCopy(nil)
		return err
	})
	return out, err
}

func (l *Ledger) DeleteBytes(key []byte) error {
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}
	return l.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(key)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		return err
	})
}

// ---------------- CBOR ----------------

func (l *Ledger) PutObject(key []byte, v interface{}) error {
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}
	buf := l.cborPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer l.cborPool.Put(buf)

	if err := cbor.NewEncoder(buf).Encode(v); err != nil {
		return fmt.Errorf("CBOR marshal failed: %w", err)
	}
	return l.PutBytes(key, buf.Bytes())
}

func (l *Ledger) GetObject(key []byte, out interface{}) error {
	data, err := l.GetBytes(key)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(data, out)
}

// ---------------- Async KV ----------------

// PutBytesAsync writes a KV pair asynchronously to the ledger
func (l *Ledger) PutBytesAsync(key, value []byte) error {
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}

	select {
	case l.asyncCh <- kvPair{key: key, val: value}:
		return nil
	default:
		// Channel full → fallback to synchronous write
		return l.PutBytes(key, value)
	}
}

// PutObjectAsync serializes a value with CBOR and stores it asynchronously
func (l *Ledger) PutObjectAsync(key []byte, v interface{}) error {
	buf := l.cborPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer l.cborPool.Put(buf)

	if err := cbor.NewEncoder(buf).Encode(v); err != nil {
		return fmt.Errorf("CBOR marshal failed: %w", err)
	}

	return l.PutBytesAsync(key, buf.Bytes())
}

// PutBytesAsyncWait writes asynchronously but waits for confirmation
func (l *Ledger) PutBytesAsyncWait(key, value []byte) error {
	done := make(chan error, 1)
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}

	go func() {
		err := l.PutBytes(key, value)
		done <- err
	}()

	return <-done
}

// PutObjectAsyncWait serializes CBOR, writes async, and waits confirmation
func (l *Ledger) PutObjectAsyncWait(key []byte, v interface{}) error {
	buf := l.cborPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer l.cborPool.Put(buf)

	if err := cbor.NewEncoder(buf).Encode(v); err != nil {
		return fmt.Errorf("CBOR marshal failed: %w", err)
	}

	return l.PutBytesAsyncWait(key, buf.Bytes())
}

// ---------------- Helpers ----------------

func NowMillis() int64 { return time.Now().UnixMilli() }

func DBPathUnderHome(dir string) string { return filepath.Clean(dir) }


// ---------------- Miner & Meta ----------------

// ListAllMiners returns all miners efficiently for large-scale ledgers
func (l *Ledger) ListAllMiners() ([]Miner, error) {
    if l == nil || l.db == nil {
        return nil, errors.New("ledger not initialized")
    }

    var miners []Miner
    prefix := []byte(PrefixMiner)

    err := l.db.View(func(txn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = true
        opts.Prefix = prefix
        it := txn.NewIterator(opts)
        defer it.Close()

        for it.Rewind(); it.Valid(); it.Next() {
            item := it.Item()
            val, err := item.ValueCopy(nil)
            if err != nil {
                return fmt.Errorf("failed to read miner value: %w", err)
            }
            var m Miner
            if err := cbor.Unmarshal(val, &m); err != nil {
                return fmt.Errorf("failed to decode miner: %w", err)
            }
            miners = append(miners, m)
        }
        return nil
    })
    return miners, err
}

func (l *Ledger) MarkRegistrationAttempt(minerID string) error {
    return l.PutObjectAsync([]byte("reg_attempt:"+minerID), NowMillis())
}

func (l *Ledger) HasRecentRegAttempt(minerID string, windowMs int64) bool {
    var ts int64
    if err := l.GetObject([]byte("reg_attempt:"+minerID), &ts); err != nil {
        return false
    }
    return NowMillis()-ts < windowMs
}

func (l *Ledger) HasMinerOnChain(minerID string) (bool, error) {
    var flag bool
    err := l.GetObject([]byte("onchain_miner:"+minerID), &flag)
    if err != nil {
        if errors.Is(err, badger.ErrKeyNotFound) {
            return false, nil
        }
        return false, err
    }
    return flag, nil
}

func (l *Ledger) SetMinerOnChain(minerID string) error {
    return l.PutObjectAsync([]byte("onchain_miner:"+minerID), true)
}


// ---------------- Supply ----------------

func projectTotalSupply(l *Ledger, reward uint64) (uint64, error) {
    current, err := l.GetTotalIssued()
    if err != nil {
        return 0, err
    }
    if reward > MaxPastaboSupply-current {
        return 0, errors.New("supply cap exceeded")
    }
    return current + reward, nil
}

func (l *Ledger) GetTotalIssued() (uint64, error) {
    data, err := l.GetBytes(MetaTotalIssued)
    if err != nil {
        if err == badger.ErrKeyNotFound {
            return 0, nil
        }
        return 0, err
    }
    if len(data) != 8 {
        return 0, fmt.Errorf("invalid MetaTotalIssued")
    }
    return binary.BigEndian.Uint64(data), nil
}

func (l *Ledger) GetTotalIssuedEXPLO() (float64, error) {
    total, err := l.GetTotalIssued()
    if err != nil {
        return 0, err
    }
    return float64(total) / float64(PastaboPerEXPLO), nil
}

func (l *Ledger) GetChainTipHeight() (uint64, error) {
    data, err := l.GetBytes(MetaChainTip)
    if err != nil {
        if err == badger.ErrKeyNotFound {
            return 0, nil
        }
        return 0, err
    }
    if len(data) != 8 {
        return 0, fmt.Errorf("invalid chain tip meta")
    }
    return binary.BigEndian.Uint64(data), nil
}

// RebuildMetaValuesFromBlocks performs a full and strict reconstruction
// of critical ledger metadata by scanning the entire blockchain from genesis.
//
// PRODUCTION MODE:
// - Full scan only (no resume mode)
// - Strict height continuity validation
// - Strict PrevHash validation
// - Strict block hash recomputation
// - Strict decompression validation
// - Supply overflow protection
// - Supply cap enforcement
// - Atomic metadata commit
//
// This function is safety-critical and intended for:
// - Genesis bootstrap
// - Corruption recovery
// - Explicit admin rebuild
func (l *Ledger) RebuildMetaValuesFromBlocks(progressInterval uint64) error {
	start := time.Now()
	log.Println("[META-REBUILD] Starting FULL blockchain scan")

	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}

	var (
		circulatingPastabo uint64
		expectedHeight     uint64
		lastHash           string
		maxHeight          uint64
		blockCount         uint64
	)

	seenMiners := make(map[string]struct{})

	// minerBalances accumulates EXPLO and IMANI per miner during the scan.
	// This allows atomic reconstruction of all balances in the second pass.
	type minerBalance struct {
		EXPLO              uint64
		IMANI              uint64
		TotalIMANIReceived uint64
	}
	minerBalances := make(map[string]*minerBalance)

	// ------------------ First pass: scan all blocks ------------------
	err := l.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = PrefixBlock
		opts.PrefetchValues = true

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(PrefixBlock); it.Next() {
			item := it.Item()
			key := item.Key()

			height, err := extractHeightFromBlockKey(key)
			if err != nil {
				return fmt.Errorf("invalid block key %s: %w", string(key), err)
			}

			// Strict height continuity.
			if height != expectedHeight {
				return fmt.Errorf("height discontinuity: expected %d, found %d", expectedHeight, height)
			}

			val, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf("failed to read block #%d: %w", height, err)
			}

			// Strict decompression.
			data, err := compressor.DecompressZSTD(val)
			if err != nil {
				return fmt.Errorf("ZSTD decompression failed at block #%d: %w", height, err)
			}

			var blk Block
			if err := cbor.Unmarshal(data, &blk); err != nil {
				return fmt.Errorf("CBOR decode failed at block #%d: %w", height, err)
			}

			// Validate height consistency.
			if blk.Header.Height != height {
				return fmt.Errorf("block height mismatch: key=%d header=%d", height, blk.Header.Height)
			}

			// Validate PrevHash chain.
			if height == 0 {
				lastHash = blk.BlockHash
			} else {
				if blk.Header.PrevHash != lastHash {
					return fmt.Errorf("PrevHash mismatch at block #%d", height)
				}
				lastHash = blk.BlockHash
			}

			// Recompute block hash.
			if blk.ComputeFinalHash() != blk.BlockHash {
				return fmt.Errorf("block hash mismatch at block #%d", height)
			}

			// Accumulate EXPLO supply and reconstruct IMANI balances.
			for _, tx := range blk.Transactions {
				if !tx.IsReward {
					continue
				}

				// FIX: use AmountPastabo (uint64) directly instead of
				// converting from AmountEXP (float64) to avoid precision drift
				// over millions of blocks.
				if tx.AmountPastabo > 0 {
					if math.MaxUint64-circulatingPastabo < tx.AmountPastabo {
						return fmt.Errorf("supply overflow at block %d", height)
					}
					circulatingPastabo += tx.AmountPastabo

					// Accumulate EXPLO balance per miner.
					if tx.To != "" {
						if minerBalances[tx.To] == nil {
							minerBalances[tx.To] = &minerBalance{}
						}
						minerBalances[tx.To].EXPLO += tx.AmountPastabo
					}
				}

				// IMANI is the accumulated consciousness of the miner on-chain.
				// Without this reconstruction, IMANI is lost on device restore.
				if tx.AmountIMPastabo > 0 && tx.To != "" {
					if minerBalances[tx.To] == nil {
						minerBalances[tx.To] = &minerBalance{}
					}
					minerBalances[tx.To].IMANI += tx.AmountIMPastabo
					minerBalances[tx.To].TotalIMANIReceived += tx.AmountIMPastabo
				}
			}

			// Track unique miners.
			minerAddr := strings.TrimSpace(blk.Header.MinerAddress)
			if minerAddr != "" && minerAddr != "genesis" && address.IsValidEXPLOAddress(minerAddr) {
				seenMiners[minerAddr] = struct{}{}
			}

			blockCount++
			expectedHeight++
			maxHeight = height

			if progressInterval > 0 && blockCount%progressInterval == 0 {
				log.Printf("[META-REBUILD] %d blocks processed...", blockCount)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("meta rebuild scan failed: %w", err)
	}

	if blockCount == 0 {
		return errors.New("no blocks found in ledger")
	}

	// Final supply cap validation.
	if circulatingPastabo > MaxPastaboSupply {
		return fmt.Errorf("supply cap exceeded: %d > %d", circulatingPastabo, MaxPastaboSupply)
	}

	minersCount := uint64(len(seenMiners))

	// ------------------ Second pass: atomic commit of meta + balances ------------------
	err = l.db.Update(func(txn *badger.Txn) error {
		writeU64 := func(keySuffix string, value uint64) error {
			key := append(PrefixMeta, []byte(keySuffix)...)
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, value)
			return txn.Set(key, buf)
		}

		// Write global metadata.
		if err := writeU64("circulating_pastabo", circulatingPastabo); err != nil {
			return err
		}
		if err := writeU64("miners_count", minersCount); err != nil {
			return err
		}
		if err := writeU64("last_update", uint64(time.Now().Unix())); err != nil {
			return err
		}

		// This ensures EXPLO and IMANI are both restored correctly
		// when a miner changes device and triggers a full ledger rebuild.
		for addr, mb := range minerBalances {
			bal := Balance{
				EXPLO:              mb.EXPLO,
				IMANI:              mb.IMANI,
				TotalIMANIReceived: mb.TotalIMANIReceived,
			}
			enc, err := cbor.Marshal(&bal)
			if err != nil {
				return fmt.Errorf("failed to marshal balance for %s: %w", addr, err)
			}
			if err := txn.Set([]byte("balance:"+addr), enc); err != nil {
				return fmt.Errorf("failed to write balance for %s: %w", addr, err)
			}
		}

		// Update chain tip.
		tipBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(tipBuf, maxHeight)
		if err := txn.Set(MetaChainTip, tipBuf); err != nil {
			return fmt.Errorf("failed to update MetaChainTip: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("meta commit failed: %w", err)
	}

	duration := time.Since(start)
	log.Printf(
		"[META-REBUILD] SUCCESS: %d blocks | %d miners | %d Pastabo | tip=%d | duration=%v",
		blockCount,
		minersCount,
		circulatingPastabo,
		maxHeight,
		duration,
	)

	return nil
}

func extractHeightFromBlockKey(key []byte) (uint64, error) {
	if len(key) < len(PrefixBlock)+8 {
		return 0, errors.New("invalid block key length")
	}
	return binary.BigEndian.Uint64(key[len(PrefixBlock):]), nil
}
// ---------------- Low-level U64 ----------------

func readU64(txn *badger.Txn, key string) (uint64, error) {
    item, err := txn.Get([]byte(key))
    if err != nil {
        if err == badger.ErrKeyNotFound { return 0, nil }
        return 0, err
    }
    val, err := item.ValueCopy(nil)
    if err != nil { return 0, err }
    if len(val) != 8 { return 0, fmt.Errorf("invalid u64 length") }
    return binary.BigEndian.Uint64(val), nil
}

func writeU64(txn *badger.Txn, key string, v uint64) error {
    buf := make([]byte, 8)
    binary.BigEndian.PutUint64(buf, v)
    return txn.Set([]byte(key), buf)
}

func incU64(txn *badger.Txn, key string, delta uint64) error {
    cur, err := readU64(txn, key)
    if err != nil { return err }
    if delta > math.MaxUint64-cur {
        return fmt.Errorf("uint64 overflow on incU64")
    }
    return writeU64(txn, key, cur+delta)
}

// ---------------- Identity Commitments ----------------

func (l *Ledger) HasCommitment(commitment []byte) (bool, error) {
    key := []byte("identity:" + hex.EncodeToString(commitment))
    var tmp struct { PubKey, Signature []byte }
    if err := l.GetObject(key, &tmp); err != nil {
        if errors.Is(err, badger.ErrKeyNotFound) { return false, nil }
        return false, err
    }
    return true, nil
}

func (l *Ledger) AddCommitment(commitment, pubKey, signature []byte) error {
    key := []byte("identity:" + hex.EncodeToString(commitment))
    exists, err := l.HasCommitment(commitment)
    if err != nil { return err }
    if exists { return fmt.Errorf("identity already exists") }

    record := struct { PubKey, Signature []byte }{pubKey, signature}
    return l.PutObject(key, record)
}
