// internal/db/badgerdb.go
package db

import (
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "log"
        "os"
        "time"

        "github.com/dgraph-io/badger/v4"
        "github.com/fxamacker/cbor/v2"
)

// BadgerDB is the wrapper used across wallet + ledger
type BadgerDB struct {
        DB *badger.DB
}

// Key prefixes / namespaces
var (
        prefixBlock   = []byte("blk:")   // blk:<8byte-height>
        prefixTx      = []byte("tx:")    // tx:<txhash>
        prefixAccount = []byte("acct:")  // acct:<address>
        prefixMeta    = []byte("meta:")  // meta:<key>
        prefixIndex   = []byte("idx:")   // idx:<name>:... (generic indexes)
)

// Meta keys
var (
        metaTotalIssuedKey = append(prefixMeta, []byte("total_issued")...)
        metaChainTipKey    = append(prefixMeta, []byte("chain_tip")...)
)

// OpenDB opens a BadgerDB instance at the given path with options suitable for mobile and desktop
func OpenDB(path string) (*BadgerDB, error) {
        opts := badger.DefaultOptions(path)
        opts.SyncWrites = true           // Ensure writes are synced to disk for safety
        opts.Logger = nil                // Disable default logging
        opts.ValueLogFileSize = 1 << 20 // 1MB value log files for mobile

        db, err := badger.Open(opts)
        if err != nil {
                return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
        }

        return &BadgerDB{DB: db}, nil
}

// CloseDB closes the database safely
func (b *BadgerDB) CloseDB() {
        if b == nil || b.DB == nil {
                return
        }
        if err := b.DB.Close(); err != nil {
                log.Printf("Error closing BadgerDB: %v", err)
        }
}

// --- Generic helpers -----------------------------------------------------

func (b *BadgerDB) SetValue(key, value []byte) error {
        err := b.DB.Update(func(txn *badger.Txn) error {
                return txn.Set(key, value)
        })
        if err != nil {
                return fmt.Errorf("failed to set key: %w", err)
        }
        return nil
}

func (b *BadgerDB) GetValue(key []byte) ([]byte, error) {
        var valCopy []byte
        err := b.DB.View(func(txn *badger.Txn) error {
                item, err := txn.Get(key)
                if err != nil {
                        return err
                }
                val, err := item.ValueCopy(nil)
                if err != nil {
                        return err
                }
                valCopy = val
                return nil
        })
        if err != nil {
                return nil, fmt.Errorf("failed to get key: %w", err)
        }
        return valCopy, nil
}

func (b *BadgerDB) DeleteValue(key []byte) error {
        err := b.DB.Update(func(txn *badger.Txn) error {
                return txn.Delete(key)
        })
        if err != nil {
                return fmt.Errorf("failed to delete key: %w", err)
        }
        return nil
}

func (b *BadgerDB) IteratePrefix(prefix []byte, fn func(k, v []byte) error) error {
        return b.DB.View(func(txn *badger.Txn) error {
                opts := badger.DefaultIteratorOptions
                it := txn.NewIterator(opts)
                defer it.Close()
                for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
                        item := it.Item()
                        k := item.KeyCopy(nil)
                        v, err := item.ValueCopy(nil)
                        if err != nil {
                                return err
                        }
                        if err := fn(k, v); err != nil {
                                return err
                        }
                }
                return nil
        })
}

// --- Block helpers ------------------------------------------------------

func encodeHeight(h uint64) []byte {
        b := make([]byte, 8)
        binary.BigEndian.PutUint64(b, h)
        return b
}

func blockKeyByHeight(height uint64) []byte {
        k := make([]byte, 0, len(prefixBlock)+8)
        k = append(k, prefixBlock...)
        k = append(k, encodeHeight(height)...)
        return k
}

func blockIndexKey(hash []byte) []byte {
        hhex := hex.EncodeToString(hash)
        return append([]byte("idx:blk_hash:"), []byte(hhex)...)
}

func (b *BadgerDB) PutBlock(height uint64, blockHash []byte, blockBytes []byte) error {
        return b.DB.Update(func(txn *badger.Txn) error {
                blkKey := blockKeyByHeight(height)
                if err := txn.Set(blkKey, blockBytes); err != nil {
                        return err
                }
                idxKey := blockIndexKey(blockHash)
                heightB := encodeHeight(height)
                if err := txn.Set(idxKey, heightB); err != nil {
                        return err
                }
                if err := txn.Set(metaChainTipKey, heightB); err != nil {
                        return err
                }
                return nil
        })
}

func (b *BadgerDB) GetBlockByHeight(height uint64) ([]byte, error) {
        key := blockKeyByHeight(height)
        return b.GetValue(key)
}

func (b *BadgerDB) GetBlockByHash(hash []byte) ([]byte, error) {
        idxKey := blockIndexKey(hash)
        val, err := b.GetValue(idxKey)
        if err != nil {
                return nil, fmt.Errorf("block index lookup failed: %w", err)
        }
        if len(val) != 8 {
                return nil, fmt.Errorf("invalid height value in index")
        }
        height := binary.BigEndian.Uint64(val)
        return b.GetBlockByHeight(height)
}

// --- Account helpers ----------------------------------------------------

func (b *BadgerDB) PutAccount(address string, accountBytes []byte) error {
        key := append(prefixAccount, []byte(address)...)
        return b.SetValue(key, accountBytes)
}

func (b *BadgerDB) GetAccount(address string) ([]byte, error) {
        key := append(prefixAccount, []byte(address)...)
        return b.GetValue(key)
}

func (b *BadgerDB) IterateAccounts(fn func(address string, value []byte) error) error {
        return b.IteratePrefix(prefixAccount, func(k, v []byte) error {
                if len(k) <= len(prefixAccount) {
                        return nil
                }
                addr := string(k[len(prefixAccount):])
                return fn(addr, v)
        })
}

// --- Meta helpers (totalIssued) ----------------------------------------

func (b *BadgerDB) GetTotalIssued() (uint64, error) {
        val, err := b.GetValue(metaTotalIssuedKey)
        if err != nil {
                if err == badger.ErrKeyNotFound || isBadgerKeyNotFound(err) {
                        return 0, nil
                }
                return 0, err
        }
        if len(val) != 8 {
                return 0, fmt.Errorf("invalid total_issued meta length")
        }
        return binary.BigEndian.Uint64(val), nil
}

func (b *BadgerDB) AddToTotalIssued(amount uint64) (uint64, error) {
        var newTotal uint64
        err := b.DB.Update(func(txn *badger.Txn) error {
                item, err := txn.Get(metaTotalIssuedKey)
                var cur uint64
                if err != nil {
                        if err == badger.ErrKeyNotFound {
                                cur = 0
                        } else {
                                return err
                        }
                } else {
                        val, err := item.ValueCopy(nil)
                        if err != nil {
                                return err
                        }
                        if len(val) != 8 {
                                return fmt.Errorf("invalid total_issued meta length")
                        }
                        cur = binary.BigEndian.Uint64(val)
                }
                if cur > (^uint64(0) - amount) {
                        return fmt.Errorf("uint64 overflow on total issued")
                }
                newTotal = cur + amount
                buf := make([]byte, 8)
                binary.BigEndian.PutUint64(buf, newTotal)
                return txn.Set(metaTotalIssuedKey, buf)
        })
        if err != nil {
                return 0, err
        }
        return newTotal, nil
}

func (b *BadgerDB) SetTotalIssued(value uint64) error {
        buf := make([]byte, 8)
        binary.BigEndian.PutUint64(buf, value)
        return b.SetValue(metaTotalIssuedKey, buf)
}

// --- Utilities ----------------------------------------------------------

func (b *BadgerDB) BackupDB(backupPath string) error {
        file, err := os.Create(backupPath)
        if err != nil {
                return fmt.Errorf("failed to create backup file: %w", err)
        }
        defer file.Close()

        _, err = b.DB.Backup(file, 0)
        if err != nil {
                return fmt.Errorf("failed to backup DB: %w", err)
        }
        return nil
}

func (b *BadgerDB) CompactDB() {
        go func() {
                for {
                        if b == nil || b.DB == nil {
                                return
                        }
                        err := b.DB.RunValueLogGC(0.5)
                        if err != nil {
                                time.Sleep(1 * time.Minute)
                                continue
                        }
                        time.Sleep(10 * time.Second)
                }
        }()
}

func isBadgerKeyNotFound(err error) bool {
        return err == badger.ErrKeyNotFound || err.Error() == "ErrKeyNotFound"
}

// --- CBOR helpers ------------------------------------------------------

func MarshalCBOR(v interface{}) ([]byte, error) {
        return cbor.Marshal(v)
}

func UnmarshalCBOR(data []byte, v interface{}) error {
        return cbor.Unmarshal(data, v)
}

// --- Wallet deletion ---------------------------------------------------

func (b *BadgerDB) DeleteWallet(address string) error {
    if b == nil || b.DB == nil {
        return fmt.Errorf("database not initialized")
    }

    txPrefix := append([]byte("tx:"), []byte(address)...)
    acctKey := append([]byte("acct:"), []byte(address)...)

    err := b.DB.Update(func(txn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = false
        it := txn.NewIterator(opts)
        defer it.Close()
        for it.Seek(txPrefix); it.ValidForPrefix(txPrefix); it.Next() {
            item := it.Item()
            if err := txn.Delete(item.KeyCopy(nil)); err != nil {
                return err
            }
        }

        if err := txn.Delete(acctKey); err != nil && err != badger.ErrKeyNotFound {
            return err
        }

        return nil
    })

    if err != nil {
        return fmt.Errorf("failed to delete wallet: %w", err)
    }

    return nil
}
