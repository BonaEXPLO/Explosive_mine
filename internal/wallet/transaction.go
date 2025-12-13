// internal/wallet/transaction.go
package wallet

import (
    "crypto/ed25519"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "time"

    "explosive/internal/address"
    "explosive/internal/db"
    "explosive/internal/encryption"
    "explosive/internal/ledger"
    "explosive/internal/p2p"
)

//
// ===========================================================
// EXPLOSIVE WALLET TRANSACTION MODULE (clean & documented)
// ===========================================================
//

// TransactionType defines supported wallet-level transaction types.
type TransactionType string

const (
    TxSend    TransactionType = "SEND"
    TxReceive TransactionType = "RECEIVE"
    TxCredit  TransactionType = "CREDIT"
    TxDebit   TransactionType = "DEBIT"
    TxBlocked TransactionType = "BLOCKED"
)

// Transaction represents a wallet transaction stored locally.
// These records are user-facing and separate from blockchain-level
// ledger transactions.
type Transaction struct {
    Timestamp time.Time       `json:"timestamp"`
    Type      TransactionType `json:"type"`
    AmountEXP float64         `json:"amount_exp"`
    AmountIM  float64         `json:"amount_imani"`
    From      string          `json:"from"`
    To        string          `json:"to"`
    Note      string          `json:"note,omitempty"`
}

// TxRecord is a simplified export-friendly version of Transaction.
type TxRecord struct {
    Timestamp string  `json:"timestamp"`
    Type      string  `json:"type"`
    From      string  `json:"from"`
    To        string  `json:"to"`
    AmountEXP float64 `json:"amount_exp"`
    AmountIM  float64 `json:"amount_im"`
    Note      string  `json:"note"`
}

// -----------------------------------------------------------
// Address Validation
// -----------------------------------------------------------

// ValidateEXPLOAddress checks if an EXPLOSIVE address is valid.
func ValidateEXPLOAddress(addr string) bool {
    return address.IsValidEXPLOAddress(addr)
}

// IsValidEXPLOAddress provides the same validation for compatibility.
func IsValidEXPLOAddress(addr string) bool {
    return ValidateEXPLOAddress(addr)
}

// -----------------------------------------------------------
// Local Ledger / Balance Operations
// -----------------------------------------------------------

// GetBalance retrieves the EXPLO/IMANI wallet balance from the local database.
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

// SetBalance stores the updated wallet balance in the local database.
func SetBalance(ledgerDB *db.BadgerDB, addr string, bal WalletBalance) error {
    data, _ := json.Marshal(bal)
    return ledgerDB.PutAccount(addr, data)
}

// SaveTransaction persists a wallet transaction in the local DB.
func SaveTransaction(ledgerDB *db.BadgerDB, tx Transaction) error {
    key := fmt.Sprintf("tx:%d:%s:%s", tx.Timestamp.UnixNano(), tx.From, tx.To)
    data, _ := json.Marshal(tx)
    return ledgerDB.SetValue([]byte(key), data)
}

// GetTransactions retrieves all local transactions for the specified address.
func GetTransactions(ledgerDB *db.BadgerDB, addr string) ([]Transaction, error) {
    var txs []Transaction
    err := ledgerDB.IteratePrefix([]byte("tx:"), func(k, v []byte) error {
        var tx Transaction
        if err := json.Unmarshal(v, &tx); err != nil {
            return err
        }
        if addr == "" || tx.From == addr || tx.To == addr {
            txs = append(txs, tx)
        }
        return nil
    })
    if err != nil {
        return nil, err
    }
    return txs, nil
}

// -----------------------------------------------------------
// Network Integration (Broadcasting)
// -----------------------------------------------------------

var activeNode *p2p.Node

// SetActiveNode defines the currently connected P2P node for broadcasting.
func SetActiveNode(node *p2p.Node) {
    activeNode = node
}

// broadcastTxSigned signs a transaction using the wallet and broadcasts it to the network.
func broadcastTxSigned(tx Transaction, w *Wallet, password string) {
    if activeNode == nil {
        fmt.Println("⚠️ No active P2P node connected — transaction not broadcasted")
        return
    }

    ltx, err := tx.ToLedgerTransactionWithSignature(w, password)
    if err != nil {
        fmt.Println("❌ Failed to sign transaction:", err)
        return
    }

    activeNode.BroadcastTransaction(ltx)
    fmt.Println("🌍 Transaction signed and broadcasted to EXPLOSIVE network")
}

// broadcastTxUnsigned sends a system-level (unsigned) transaction to the network.
func broadcastTxUnsigned(tx Transaction) {
    if activeNode == nil {
        fmt.Println("⚠️ No active P2P node connected — transaction not broadcasted")
        return
    }

    now := time.Now().UnixMilli()
    ltx := &ledger.Transaction{
        ID:        tx.From,
        From:      tx.From,
        To:        tx.To,
        AmountEXP: tx.AmountEXP,
        AmountIM:  tx.AmountIM,
        Fee:       0.0,
        Timestamp: now,
        Nonce:     now,
        Note:      tx.Note,
        IsReward:  (tx.From == "SYSTEM"),
    }
    ltx.TxHash = ltx.ComputeHash()
    activeNode.BroadcastTransaction(ltx)
    fmt.Println("🌍 SYSTEM transaction broadcasted to EXPLOSIVE network")
}

// broadcastBalanceUpdate synchronizes updated wallet balances across the network.
func broadcastBalanceUpdate(addr string, bal WalletBalance) {
    if activeNode == nil {
        return
    }
    payload := map[string]interface{}{
        "type":  "BALANCE_UPDATE",
        "addr":  addr,
        "exp":   bal.EXPLO,
        "imani": bal.IMANI,
        "time":  time.Now().Unix(),
    }
    if err := BroadcastCustom(payload); err != nil {
        log.Printf("[wallet] Failed to broadcast balance update: %v", err)
    }
}

// broadcastLedgerSync sends the full local ledger snapshot to connected peers.
func broadcastLedgerSync(ledgerDB *db.BadgerDB) {
    if activeNode == nil {
        return
    }
    txs, _ := GetTransactions(ledgerDB, "")
    payload := map[string]interface{}{
        "type": "LEDGER_SYNC",
        "data": txs,
    }
    if err := BroadcastCustom(payload); err != nil {
        log.Printf("[wallet] Failed to broadcast ledger sync: %v", err)
    }
}

// -----------------------------------------------------------
// Conversion & Signature
// -----------------------------------------------------------

// ToLedgerTransactionWithSignature converts a wallet Transaction into a fully
// signed ledger.Transaction ready for network propagation.
//
// It deterministically assigns timestamp and nonce, decrypts the wallet’s private key,
// signs the canonical hash, and attaches the signature, public key, and TxHash.
func (tx *Transaction) ToLedgerTransactionWithSignature(w *Wallet, password string) (*ledger.Transaction, error) {
    now := time.Now().UnixMilli()
    timestamp := now
    nonce := now

    ltx := &ledger.Transaction{
        From:      tx.From,
        To:        tx.To,
        AmountEXP: tx.AmountEXP,
        AmountIM:  tx.AmountIM,
        Fee:       0.001,
        Timestamp: timestamp,
        Nonce:     nonce,
        Note:      tx.Note,
        IsReward:  false,
    }

    // Decrypt the wallet’s private key
    // Decrypt the wallet’s private key
privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
if err != nil {
    return nil, fmt.Errorf("failed to decrypt wallet: %w", err)
}

    // Handle both 32-byte seed and 64-byte full private keys
    if len(privBytes) != ed25519.PrivateKeySize && len(privBytes) != ed25519.SeedSize {
        if len(privBytes) == ed25519.SeedSize {
            full := ed25519.NewKeyFromSeed(privBytes)
            privBytes = make([]byte, len(full))
            copy(privBytes, full)
            for i := range full {
                full[i] = 0
            }
        } else {
            return nil, fmt.Errorf("unexpected private key length: %d", len(privBytes))
        }
    }

    priv := ed25519.PrivateKey(privBytes)
    pub := priv.Public().(ed25519.PublicKey)

    // Sign canonical hash
    sig := ed25519.Sign(priv, ltx.HashForSignature())

    // Attach metadata
ltx.FromPubKey = pub
ltx.Signature = sig
ltx.TxHash = ltx.ComputeHash()
ltx.ID = tx.From

// 🟦Add miner inf
ltx.MinerInfo = &ledger.MinerInfo{
    MinerID:   tx.From,
    CreatedAt: timestamp,
    PublicKey: pub,
}

    // Zero out sensitive key material
    for i := range priv {
        priv[i] = 0
    }
    for i := range privBytes {
        privBytes[i] = 0
    }

    fmt.Println("🔏 Transaction signed with pubkey:", hex.EncodeToString(pub))
    return ltx, nil
}

// -----------------------------------------------------------
// Transaction Execution (Public API)
// -----------------------------------------------------------

// SendEXPLO performs a signed EXPLO token transfer and updates local balances.
func SendEXPLO(ledgerDB *db.BadgerDB, from, to string, amount float64, w *Wallet, password string) error {
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
        Note:      "EXPLO sent via Wallet",
    }

    if err := SaveTransaction(ledgerDB, tx); err != nil {
        return err
    }

    // Broadcast to network
    broadcastTxSigned(tx, w, password)
    broadcastBalanceUpdate(from, fromBal)
    broadcastBalanceUpdate(to, toBal)

    return nil
}

// CreditWallet adds EXPLO or IMANI credits to the wallet (system-originated).
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
            Note:      "EXPLO credited by system",
        }
        if err := SaveTransaction(ledgerDB, tx); err != nil {
            return err
        }
        broadcastTxUnsigned(tx)
    }

    if imaniAmount > 0 {
        bal.IMANI += imaniAmount
        tx := Transaction{
            Timestamp: time.Now(),
            Type:      TxBlocked,
            AmountIM:  imaniAmount,
            From:      "SYSTEM",
            To:        addr,
            Note:      "IMANI cannot be transferred manually (sacred token)",
        }
        if err := SaveTransaction(ledgerDB, tx); err != nil {
            return err
        }
        broadcastTxUnsigned(tx)
    }

    if err := SetBalance(ledgerDB, addr, bal); err != nil {
        return err
    }

    broadcastBalanceUpdate(addr, bal)
    return nil
}

// -----------------------------------------------------------
// Display Utilities
// -----------------------------------------------------------

// DisplayWalletBalance prints a human-readable summary of wallet balances.
func DisplayWalletBalance(bal WalletBalance) {
    fmt.Printf("💰 EXPLO: %.4f | 🌟 IMANI: %.4f\n", bal.EXPLO, bal.IMANI)
}

// DisplayTransactionHistory prints all stored transactions for a given address.
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

// BroadcastCustom safely broadcasts arbitrary structured data using the official P2P protocol (CBOR + MsgTypeCustomData).
// Replaces the old unsafe BroadcastData() method.
func BroadcastCustom(payload interface{}) error {
    if activeNode == nil {
        return errors.New("no active P2P node connected")
    }

    env, err := p2p.NewEnvelopeFromPayload(activeNode.ProtocolVersion(), p2p.MsgTypeCustomData, payload)
    if err != nil {
        return fmt.Errorf("failed to encode custom payload: %w", err)
    }

    activeNode.BroadcastEnvelope(env)
    return nil
}
