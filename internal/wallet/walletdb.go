package wallet

import (
        "encoding/json"
        "fmt"
        "time"

        badger "github.com/dgraph-io/badger/v4"
)

// ------------------ Balance Struct ------------------

// WalletBalance represents the EXPLO and IMANI balance for a given wallet.
// Using float64 allows handling fractions of tokens if needed.
type WalletBalance struct {
        EXPLO float64 `json:"explo"`
        IMANI float64 `json:"imani"`
}

// ------------------ Balance Methods ------------------

// GetBalance retrieves the balance for the specified wallet address.
func (wdb *WalletDB) GetBalance(address string) (WalletBalance, error) {
        var bal WalletBalance
        err := wdb.db.View(func(txn *badger.Txn) error {
                item, err := txn.Get([]byte("BALANCE_" + address))
                if err != nil {
                        return err
                }
                val, err := item.ValueCopy(nil)
                if err != nil {
                        return err
                }
                return json.Unmarshal(val, &bal)
        })
        return bal, err
}

// SetBalance saves the balance for the specified wallet address.
func (wdb *WalletDB) SetBalance(address string, bal WalletBalance) error {
        data, err := json.Marshal(bal)
        if err != nil {
                return err
        }
        return wdb.db.Update(func(txn *badger.Txn) error {
                return txn.Set([]byte("BALANCE_"+address), data)
        })
}

// DeleteBalance removes the balance entry for a given address.
func (wdb *WalletDB) DeleteBalance(address string) error {
        return wdb.db.Update(func(txn *badger.Txn) error {
                return txn.Delete([]byte("BALANCE_" + address))
        })
}

// ------------------ Transaction History ------------------

// AppendTx stores a transaction record in the DB.
func (wdb *WalletDB) AppendTx(tx TxRecord) error {
        key := fmt.Sprintf("TX_%s_%d", tx.From, time.Now().UnixNano())
        data, err := json.Marshal(tx)
        if err != nil {
                return err
        }
        return wdb.db.Update(func(txn *badger.Txn) error {
                return txn.Set([]byte(key), data)
        })
}

// GetTxHistory retrieves all transaction records related to the given address.
func (wdb *WalletDB) GetTxHistory(address string) ([]TxRecord, error) {
        var history []TxRecord
        err := wdb.db.View(func(txn *badger.Txn) error {
                it := txn.NewIterator(badger.DefaultIteratorOptions)
                defer it.Close()
                prefix := []byte("TX_" + address + "_")
                for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
                        item := it.Item()
                        val, err := item.ValueCopy(nil)
                        if err != nil {
                                return err
                        }
                        var tx TxRecord
                        if err := json.Unmarshal(val, &tx); err != nil {
                                return err
                        }
                        history = append(history, tx)
                }
                return nil
        })
        return history, err
}

// ------------------ Password Timestamp ------------------

// UpdatePasswordTimestamp saves the last password update time for a wallet.
func (wdb *WalletDB) UpdatePasswordTimestamp(address string, ts int64) error {
        data := []byte(fmt.Sprintf("%d", ts))
        return wdb.db.Update(func(txn *badger.Txn) error {
                return txn.Set([]byte("PWTS_"+address), data)
        })
}

// GetPasswordTimestamp retrieves the last password update time for a wallet.
// Returns 0 if no timestamp is found.
func (wdb *WalletDB) GetPasswordTimestamp(address string) (int64, error) {
        var ts int64
        err := wdb.db.View(func(txn *badger.Txn) error {
                item, err := txn.Get([]byte("PWTS_" + address))
                if err != nil {
                        if err == badger.ErrKeyNotFound {
                                ts = 0
                                return nil
                        }
                        return err                                    }
                val, err := item.ValueCopy(nil)
                if err != nil {                                               return err
                }
                _, err = fmt.Sscan(string(val), &ts)
                return err
        })
        return ts, err
}
