// internal/wallet/transaction.go
package wallet

import (
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "explosive/internal/address"
    "explosive/internal/db"
)

// ----------------------------
// Types
// ----------------------------

type TransactionType string

const (
    TxSend    TransactionType = "SEND"
    TxReceive TransactionType = "RECEIVE"
    TxCredit  TransactionType = "CREDIT"
    TxDebit   TransactionType = "DEBIT"
    TxBlocked TransactionType = "BLOCKED"
)

// Transaction represents a single ledger operation.
type Transaction struct {
    Timestamp time.Time       `json:"timestamp"`
    Type      TransactionType `json:"type"`
    AmountEXP float64         `json:"amount_exp"`
    AmountIM  float64         `json:"amount_imani"`
    From      string          `json:"from"`
    To        string          `json:"to"`
    Note      string          `json:"note,omitempty"`
}

// TxRecord is the lightweight format used for local wallet history.
type TxRecord struct {
    Timestamp string  `json:"timestamp"`
    Type      string  `json:"type"`
    From      string  `json:"from"`
    To        string  `json:"to"`
    AmountEXP float64 `json:"amount_exp"`
    AmountIM  float64 `json:"amount_im"`
    Note      string  `json:"note"`
}

// ----------------------------
// Address Validation
// ----------------------------

func ValidateEXPLOAddress(addr string) bool {
    return address.IsValidEXPLOAddress(addr)
}

// Alias for readability
func IsValidEXPLOAddress(addr string) bool {
    return ValidateEXPLOAddress(addr)
}

// ----------------------------
// Ledger-backed Wallet Functions
// ----------------------------

func GetBalance(ledgerDB *db.BadgerDB, addr string) (WalletBalance, error) {
    data, err := ledgerDB.GetAccount(addr)
    if err != nil {
        return WalletBalance{EXPLO: 0, IMANI: 0}, nil
    }
    var bal WalletBalance
    if err := json.Unmarshal(data, &bal); err != nil {
        return WalletBalance{}, err
    }
    return bal, nil
}

func SetBalance(ledgerDB *db.BadgerDB, addr string, bal WalletBalance) error {
    data, _ := json.Marshal(bal)
    return ledgerDB.PutAccount(addr, data)
}

func SaveTransaction(ledgerDB *db.BadgerDB, tx Transaction) error {
    key := fmt.Sprintf("tx:%d:%s:%s", tx.Timestamp.UnixNano(), tx.From, tx.To)
    data, _ := json.Marshal(tx)
    return ledgerDB.SetValue([]byte(key), data)
}

func GetTransactions(ledgerDB *db.BadgerDB, addr string) ([]Transaction, error) {
    var txs []Transaction
    err := ledgerDB.IteratePrefix([]byte("tx:"), func(k, v []byte) error {
        var tx Transaction
        if err := json.Unmarshal(v, &tx); err != nil {
            return err
        }
        if tx.From == addr || tx.To == addr {
            txs = append(txs, tx)
        }
        return nil
    })
    if err != nil {
        return nil, err
    }
    return txs, nil
}

func SendEXPLO(ledgerDB *db.BadgerDB, from, to string, amount float64) error {
    if !IsValidEXPLOAddress(to) || !IsValidEXPLOAddress(from) {
        return errors.New("invalid EXPLO address")
    }
    if amount <= 0 {
        return errors.New("amount must be positive")
    }

    fromBal, err := GetBalance(ledgerDB, from)
    if err != nil {
        return err
    }
    if fromBal.EXPLO < amount {
        return errors.New("insufficient EXPLO balance")
    }

    fromBal.EXPLO -= amount
    if err := SetBalance(ledgerDB, from, fromBal); err != nil {
        return err
    }

    toBal, err := GetBalance(ledgerDB, to)
    if err != nil {
        return err
    }
    toBal.EXPLO += amount
    if err := SetBalance(ledgerDB, to, toBal); err != nil {
        return err
    }

    tx := Transaction{
        Timestamp: time.Now(),
        Type:      TxSend,
        AmountEXP: amount,
        From:      from,
        To:        to,
        Note:      "EXPLO sent via Ledger",
    }
    return SaveTransaction(ledgerDB, tx)
}

func CreditWallet(ledgerDB *db.BadgerDB, addr string, expAmount, imaniAmount float64) error {
    bal, err := GetBalance(ledgerDB, addr)
    if err != nil {
        return err
    }

    if expAmount > 0 {
        bal.EXPLO += expAmount
        tx := Transaction{
            Timestamp: time.Now(),
            Type:      TxCredit,
            AmountEXP: expAmount,
            From:      "SYSTEM",
            To:        addr,
            Note:      "EXPLO credited",
        }
        if err := SaveTransaction(ledgerDB, tx); err != nil {
            return err
        }
    }

    if imaniAmount > 0 {
        bal.IMANI += imaniAmount
        tx := Transaction{
            Timestamp: time.Now(),
            Type:      TxBlocked,
            AmountIM:  imaniAmount,
            From:      "SYSTEM",
            To:        addr,
            Note:      "IMANI cannot be sent manually, sacred token",
        }
        if err := SaveTransaction(ledgerDB, tx); err != nil {
            return err
        }
    }

    return SetBalance(ledgerDB, addr, bal)
}

func DisplayWalletBalance(bal WalletBalance) {
    fmt.Printf("💰 EXPLO: %.4f | 🌟 IMANI: %.4f\n", bal.EXPLO, bal.IMANI)
}

func DisplayTransactionHistory(ledgerDB *db.BadgerDB, addr string) error {
    txs, err := GetTransactions(ledgerDB, addr)
    if err != nil {
        return err
    }
    fmt.Println("=== TRANSACTION HISTORY ===")
    for _, tx := range txs {
        fmt.Printf("[%s] Type: %s | EXPLO: %.4f | IMANI: %.4f | From: %s | To: %s | Note: %s\n",
            tx.Timestamp.Format(time.RFC3339),
            tx.Type,
            tx.AmountEXP,
            tx.AmountIM,
            tx.From,
            tx.To,
            tx.Note)
    }
    fmt.Println("===========================")
    return nil
}
