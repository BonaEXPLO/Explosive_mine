// internal/wallet/save.go
package wallet

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"

	"explosive/internal/db" // Ledger DB
)

// WalletDB wraps a BadgerDB instance for wallet storage
type WalletDB struct {
	db *badger.DB
}

// OpenDB opens or creates the BadgerDB database at the specified path.
func OpenDB(path string) (*WalletDB, error) {
	opts := badger.DefaultOptions(path).
		WithLoggingLevel(badger.WARNING).
		WithNumCompactors(2).
		WithValueLogFileSize(1 << 20). // 1MiB value log file
		WithSyncWrites(true)

	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create DB folder: %w", err)
	}

	dbInstance, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	return &WalletDB{db: dbInstance}, nil
}

// Close safely closes the BadgerDB
func (wdb *WalletDB) Close() error {
	return wdb.db.Close()
}

// ValidatePassword checks if a password meets minimal security rules
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}<>?/|\\", c):
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return fmt.Errorf("password must contain upper, lower, digit, symbol")
	}
	return nil
}

// SaveWallet saves a wallet to BadgerDB using CBOR serialization.
func (wdb *WalletDB) SaveWallet(wallet *Wallet) error {
	if wallet == nil {
		return fmt.Errorf("nil wallet")
	}
	if !IsValidEXPLOAddress(wallet.Address) {
		return fmt.Errorf("invalid wallet address checksum: %s", wallet.Address)
	}
	if wallet.EncryptedPriv == nil {
		return fmt.Errorf("refusing to save wallet without EncryptedPriv")
	}

	data, err := cbor.Marshal(wallet)
	if err != nil {
		return fmt.Errorf("failed to serialize wallet with CBOR: %w", err)
	}

	err = wdb.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(wallet.Address), data)
	})
	if err != nil {
		return fmt.Errorf("failed to save wallet in DB: %w", err)
	}
	return nil
}

// LoadWallet loads a wallet from BadgerDB by address.
func (wdb *WalletDB) LoadWallet(address string) (*Wallet, error) {
	if !IsValidEXPLOAddress(address) {
		return nil, fmt.Errorf("invalid wallet address checksum: %s", address)
	}

	var wallet Wallet
	err := wdb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(address))
		if err != nil {
			return err
		}
		val, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return cbor.Unmarshal(val, &wallet)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load wallet: %w", err)
	}

	if wallet.EncryptedPriv == nil && wallet.Mnemonic != "" {
		return nil, fmt.Errorf("wallet record contains plaintext mnemonic — migrate securely")
	}

	return &wallet, nil
}

// DeleteWallet deletes a wallet from BadgerDB by address
func (wdb *WalletDB) DeleteWallet(address string) error {
	if !IsValidEXPLOAddress(address) {
		return fmt.Errorf("invalid wallet address checksum: %s", address)
	}

	err := wdb.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(address))
	})
	if err != nil {
		return fmt.Errorf("failed to delete wallet: %w", err)
	}
	return nil
}

// ListWallets returns all valid wallet records stored in the database.
//
// Wallet records are stored under their exact EXPLO address as the Badger key.
// The database may also contain auxiliary records such as BALANCE_* and TX_*.
// Those records must never be decoded as Wallet objects.
func (wdb *WalletDB) ListWallets() ([]*Wallet, error) {
	var wallets []*Wallet

	err := wdb.db.View(func(txn *badger.Txn) error {
		iter := txn.NewIterator(badger.DefaultIteratorOptions)
		defer iter.Close()

		for iter.Rewind(); iter.Valid(); iter.Next() {
			item := iter.Item()

			// Wallet records use the wallet address itself as the key.
			keyBytes := item.KeyCopy(nil)
			key := string(keyBytes)

			// Ignore all non-wallet records before attempting CBOR decoding.
			// Examples:
			//   BALANCE_explo...
			//   TX_explo...
			//   other ledger/synchronization records
			if !IsValidEXPLOAddress(key) {
				continue
			}

			val, err := item.ValueCopy(nil)
			if err != nil {
				return fmt.Errorf(
					"failed to read wallet record %q: %w",
					key,
					err,
				)
			}

			var w Wallet

			if err := cbor.Unmarshal(val, &w); err != nil {
				return fmt.Errorf(
					"failed to decode wallet record %q: %w",
					key,
					err,
				)
			}

			// The key and the wallet's internal address must agree.
			if w.Address != key {
				return fmt.Errorf(
					"wallet record key/address mismatch: key=%q address=%q",
					key,
					w.Address,
				)
			}

			// A valid wallet must contain encrypted private material.
			if w.EncryptedPriv == nil {
				return fmt.Errorf(
					"wallet record %q has no encrypted private material",
					key,
				)
			}

			// Plaintext mnemonic data must never be accepted.
			if w.Mnemonic != "" {
				return fmt.Errorf(
					"wallet record %q contains plaintext mnemonic",
					key,
				)
			}

			wallets = append(wallets, &w)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list wallets: %w", err)
	}

	return wallets, nil
}

// ExportWalletsCBORL exports all wallets to a CBORL file (one CBOR object per line, base64 encoded).
func (wdb *WalletDB) ExportWalletsCBORL(filePath string) error {
	wallets, err := wdb.ListWallets()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return fmt.Errorf("failed to create export folder: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open export file: %w", err)
	}
	defer f.Close()

	for _, w := range wallets {
		line, err := w.ToCBORLine()
		if err != nil {
			return err
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// ImportWalletsCBORL imports wallets from a CBORL file and optionally syncs with Ledger
func (wdb *WalletDB) ImportWalletsCBORL(filePath string, ledgerDB *db.BadgerDB) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read CBORL file: %w", err)
	}

	lines := splitLines(data)
	for idx, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		w, err := FromCBORLine(line)
		if err != nil {
			return fmt.Errorf("failed to parse CBORL at line %d: %w", idx+1, err)
		}
		if !IsValidEXPLOAddress(w.Address) {
			return fmt.Errorf("invalid wallet address in CBORL at line %d: %s", idx+1, w.Address)
		}
		if w.EncryptedPriv == nil && w.Mnemonic != "" {
			return fmt.Errorf("found wallet with plaintext mnemonic at line %d — import aborted", idx+1)
		}
		if err := wdb.SaveWallet(w); err != nil {
			return fmt.Errorf("failed to save wallet from CBORL at line %d: %w", idx+1, err)
		}

		// Sync wallet with Ledger after import
		if ledgerDB != nil {
			SyncWalletWithLedger(w, ledgerDB)
			if err := wdb.SaveWallet(w); err != nil {
				return fmt.Errorf("failed to update wallet after ledger sync at line %d: %w", idx+1, err)
			}
		}
	}
	return nil
}

// splitLines splits the input bytes into lines without including newline chars.
func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

// ----------------------------
// Synchronization with Ledger
// ----------------------------
func SyncWalletWithLedger(wallet *Wallet, ledgerDB *db.BadgerDB) error {
	if wallet == nil || ledgerDB == nil {
		return fmt.Errorf("wallet or ledgerDB is nil")
	}

	accountBytes, err := ledgerDB.GetAccount(wallet.Address)
	if err != nil {
		return fmt.Errorf("ledger account lookup failed: %w", err)
	}

	// Decode balances directly with CBOR
	var account struct {
		EXPLO float64 `cbor:"explo"`
		IMANI float64 `cbor:"imani"`
	}

	if err := cbor.Unmarshal(accountBytes, &account); err != nil {
		return fmt.Errorf("failed to unmarshal ledger account: %w", err)
	}

	wallet.BalanceEXP = account.EXPLO
	wallet.BalanceIM = account.IMANI

	return nil
}
