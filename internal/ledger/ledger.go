// internal/ledger/ledger.go
package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
        "encoding/binary"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"
)

// ---------------- Constants ----------------

// MaxSupplyEXPLO defines the maximum amount of EXPLO tokens that can ever exist.
const MaxSupplyEXPLO uint64 = 50_000_000

// Exported key prefixes for block, transaction, account, and metadata storage.
var (
	PrefixBlock     = []byte("blk:")                  // blk:<8byte-height> -> compressed CBOR block bytes
	PrefixTx        = []byte("tx:")                   // tx:<txhash> -> transaction CBOR bytes
	PrefixAccount   = []byte("acct:")                 // acct:<address> -> account CBOR bytes
	PrefixMeta      = []byte("meta:")                 // meta:<key> -> metadata
	MetaTotalIssued = append(PrefixMeta, []byte("total_issued")...)
	MetaChainTip    = append(PrefixMeta, []byte("chain_tip")...)
)

// ---------------- Ledger Struct ----------------

type Ledger struct {
    db        *badger.DB
    asyncCh   chan kvPair   // channel for async batch writes
    stopAsync chan struct{} // signal to stop async writer
    cborPool  sync.Pool     // CBOR buffer pool for reuse
    dbPath    string        // chemin du dossier ledger
}

// kvPair represents a key/value pair for async batch writes.
type kvPair struct {
    key []byte
    val []byte
}

// ---------------- OpenLedger ----------------

// OpenLedger opens (or creates) a BadgerDB instance at the specified path
// and returns a Ledger instance with asynchronous write support and CBOR pooling.
// It also ensures the genesis block is initialized deterministically.
func OpenLedger(path string) (*Ledger, error) {
    // Configure BadgerDB options for high throughput
    opts := badger.DefaultOptions(path)
    opts.SyncWrites = false  // disable fsync for faster writes
    opts.Logger = nil        // disable default logging

    // Open (or create) the database
    db, err := badger.Open(opts)
    if err != nil {
        return nil, fmt.Errorf("failed to open ledger DB: %w", err)
    }

    // Initialize Ledger struct with async channel and CBOR buffer pool
    l := &Ledger{
        db:        db,
        asyncCh:   make(chan kvPair, 100_000), // large channel for high TPS
        stopAsync: make(chan struct{}),        // signal to stop async writer
        cborPool: sync.Pool{
            New: func() interface{} { return new(bytes.Buffer) }, // reuse CBOR buffers
        },
        dbPath: path, // <-- initialisation du chemin du ledger
    }

    // Start asynchronous batch writer in a separate goroutine
    go l.asyncWriter()

    // ----------------- INIT GENESIS BLOCK -----------------
    // Ensure the genesis block exists and is valid; create if absent
    err = InitLedger(l)
    if err != nil {
        _ = db.Close() // cleanup on failure
        return nil, fmt.Errorf("ledger initialization failed: %v", err)
    }

    return l, nil
}

func InitLedger(db *Ledger) error {
    if db == nil || db.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    block0, err := db.GetBlockByHeight(0)
    if err == nil && block0 != nil {
        if err := VerifyGenesis(db); err != nil {
            return fmt.Errorf("ledger corruption detected: %v", err)
        }
        fmt.Println("✅ Genesis block already exists and verified.")
        return nil
    }

    _, err = CreateGenesisBlock(db)
    if err != nil {
        return fmt.Errorf("failed to create genesis block: %v", err)
    }
    return nil
}

// Close safely closes the ledger, flushing any pending async writes.
func (l *Ledger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	close(l.stopAsync)
	return l.db.Close()
}

// ---------------- Async Batch Writer ----------------

// asyncWriter runs in a goroutine to batch writes asynchronously for high TPS.
func (l *Ledger) asyncWriter() {
	ticker := time.NewTicker(2 * time.Millisecond) // frequent flush for low latency
	defer ticker.Stop()

	batch := l.db.NewWriteBatch()
	defer batch.Cancel()
	count := 0

	for {
		select {
		case kv := <-l.asyncCh:
			_ = batch.Set(kv.key, kv.val)
			count++
			if count >= 2000 { // flush small batches frequently
				_ = batch.Flush()
				batch = l.db.NewWriteBatch()
				count = 0
			}
		case <-ticker.C:
			if count > 0 {
				_ = batch.Flush()
				batch = l.db.NewWriteBatch()
				count = 0
			}
		case <-l.stopAsync:
			if count > 0 {
				_ = batch.Flush()
			}
			return
		}
	}
}

// AsyncPut enqueues a key/value pair for async write. Falls back to sync write if channel is full.
func (l *Ledger) AsyncPut(key, val []byte) {
	if l == nil || l.db == nil {
		return
	}
	select {
	case l.asyncCh <- kvPair{key, val}:
	default:
		// fallback synchronous write
		_ = l.db.Update(func(txn *badger.Txn) error {
			return txn.Set(key, val)
		})
	}
}

// ---------------- Generic KV Helpers ----------------

// PutBytes writes raw bytes to the DB synchronously.
func (l *Ledger) PutBytes(key, value []byte) error {
	if l == nil || l.db == nil {
		return errors.New("ledger not initialized")
	}
	return l.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// GetBytes reads raw bytes from the DB.
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
		v, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// DeleteBytes removes a key from the ledger database.
// Safe for concurrent use and returns an error if the DB isn't initialized.
func (l *Ledger) DeleteBytes(key []byte) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    return l.db.Update(func(txn *badger.Txn) error {
        err := txn.Delete(key)
        if err == badger.ErrKeyNotFound {
            return nil // Not fatal — key simply didn't exist
        }
        return err
    })
}

// PutObject marshals an object to CBOR and stores it in the DB.
func (l *Ledger) PutObject(key []byte, v interface{}) error {
	data, err := cbor.Marshal(v)
	if err != nil {
		return err
	}
	return l.PutBytes(key, data)
}

// GetObject retrieves and unmarshals a CBOR object from the DB.
func (l *Ledger) GetObject(key []byte, out interface{}) error {
	data, err := l.GetBytes(key)
	if err != nil {
		return err
	}
	return cbor.Unmarshal(data, out)
}

// ---------------- Metadata Helpers ----------------

// GetChainTipHeight returns the latest block height stored.
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

// GetTotalIssued returns the total amount of EXPLO issued so far.
func (l *Ledger) GetTotalIssued() (uint64, error) {
	data, err := l.GetBytes(MetaTotalIssued)
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return 0, nil
		}
		return 0, err
	}
	if len(data) != 8 {
		return 0, fmt.Errorf("invalid total issued meta")
	}
	return binary.BigEndian.Uint64(data), nil
}

// ---------------- Time Helper ----------------

// NowMillis returns the current Unix time in milliseconds.
func NowMillis() int64 {
	return time.Now().UnixMilli()
}

// ---------------- Utility ----------------

// DBPathUnderHome returns a clean, absolute path for the DB.
func DBPathUnderHome(dir string) string {
	return filepath.Clean(dir)
}

// ApplyTransaction applies a transaction to the ledger.
// Placeholder: adapt selon ta logique réelle (mise à jour comptes, soldes, etc.)
func (l *Ledger) ApplyTransaction(tx *Transaction) error {
    // TODO: Implement actual transaction application logic
    // For now, just log and return nil
    fmt.Printf("Applying transaction %v\n", tx)
    return nil
}

func (l *Ledger) GetGlobalBalances() (map[string]interface{}, error) {
    if l == nil {
        return nil, fmt.Errorf("ledger not initialized")
    }

    // Get total EXPLO issued
    totalEXPLO, err := l.GetTotalIssued()
    if err != nil {
        return nil, err
    }

    // Get total IMANI (stored as CBOR object)
    var totalIMANI float64
    _ = l.GetObject([]byte("total_imani"), &totalIMANI)

    // Get total LUMEN (stored as CBOR object)
    var totalLUMEN float64
    _ = l.GetObject([]byte("total_lumen"), &totalLUMEN)

    // Construct result map
    data := map[string]interface{}{
        "total_explo_issued": totalEXPLO,
        "total_imani_issued": totalIMANI,
        "total_lumen_index":  totalLUMEN,
    }

    return data, nil
}

// ListAllMiners returns all miners currently stored in the ledger.
func (l *Ledger) ListAllMiners() ([]Miner, error) {
    if l == nil || l.db == nil {
        return nil, fmt.Errorf("ledger not initialized")
    }

    miners := []Miner{}
    prefix := []byte("miner:") // Tous les mineurs sont stockés avec cette clé

    err := l.db.View(func(txn *badger.Txn) error {
        it := txn.NewIterator(badger.DefaultIteratorOptions)
        defer it.Close()

        for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
            item := it.Item()

            val, err := item.ValueCopy(nil)
            if err != nil {
                return err
            }

            var m Miner
            if err := cbor.Unmarshal(val, &m); err != nil {
                return err
            }

            miners = append(miners, m)
        }

        return nil
    })

    if err != nil {
        return nil, err
    }

    return miners, nil
}

// MarkRegistrationAttempt stores the timestamp (ms) of the last registration attempt for a miner
func (l *Ledger) MarkRegistrationAttempt(minerID string) error {
    key := []byte("reg_attempt:" + minerID)
    ts := NowMillis()
    return l.PutObject(key, ts)
}

// HasRecentRegAttempt checks if the last registration attempt was within windowMs milliseconds
func (l *Ledger) HasRecentRegAttempt(minerID string, windowMs int64) bool {
    key := []byte("reg_attempt:" + minerID)
    var ts int64
    if err := l.GetObject(key, &ts); err != nil {
        return false // no record => no recent attempt
    }
    return NowMillis()-ts < windowMs
}

// HasMinerOnChain checks if the miner is already registered on-chain
// This is a placeholder; adapt selon ton état de ledger ou bucket miners_confirmed
// HasMinerOnChain checks if the miner is already registered on-chain
func (l *Ledger) HasMinerOnChain(minerID string) (bool, error) {
    key := []byte("onchain_miner:" + minerID)
    var flag bool

    err := l.GetObject(key, &flag)
    if err != nil {
        if errors.Is(err, badger.ErrKeyNotFound) {
            return false, nil
        }
        return false, err
    }
    return flag, nil
}
// SetMinerOnChain marks a miner as registered on-chain (à utiliser après réception du Tx signé)
func (l *Ledger) SetMinerOnChain(minerID string) error {
    key := []byte("onchain_miner:" + minerID)
    return l.PutObject(key, true)
}

