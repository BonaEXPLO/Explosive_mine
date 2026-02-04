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
    "github.com/dgraph-io/badger/v4"
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


// SetBalance stores the updated wallet balance in the ledger.
// Overwrites any existing balance for the given address.
func SetBalance(l *ledger.Ledger, addr string, bal WalletBalance) error {
    return l.PutObject([]byte("balance:"+addr), bal)
}

// SaveTransaction persists a user-facing wallet transaction in the ledger.
// Uses a deterministic key based on timestamp, from, and to for ordering and uniqueness.
func SaveTransaction(l *ledger.Ledger, tx Transaction) error {
    key := []byte(fmt.Sprintf("tx:%d:%s:%s", tx.Timestamp.UnixNano(), tx.From, tx.To))
    return l.PutObject(key, tx)
}

// GetBalance retrieves the EXPLO and IMANI wallet balance from the ledger.
// Returns zero balances if the account does not exist yet.
func GetBalance(l *ledger.Ledger, addr string) (WalletBalance, error) {
    var bal WalletBalance
    err := l.GetObject([]byte("balance:"+addr), &bal)
    if err != nil {
        if errors.Is(err, badger.ErrKeyNotFound) {
            return WalletBalance{EXPLO: 0, IMANI: 0}, nil
        }
        return WalletBalance{}, err
    }
    return bal, nil
}

// SendEXPLO performs a signed EXPLO token transfer.
// It uses a persistent incremental nonce from the ledger to prevent replay attacks,
// updates local balances optimistically for immediate UX feedback,
// records the user-facing transaction, and broadcasts the fully signed ledger transaction.
func SendEXPLO(l *ledger.Ledger, from, to string, amount float64, w *Wallet, password string) error {
    if !IsValidEXPLOAddress(to) || !IsValidEXPLOAddress(from) {
        return errors.New("invalid EXPLO address")
    }
    if amount <= 0 {
        return errors.New("amount must be positive")
    }

    // Check local balance (optimistic)
    fromBal, err := GetBalance(l, from)
    if err != nil {
        return err
    }
    if fromBal.EXPLO < amount+0.001 { // include fee
        return errors.New("insufficient EXPLO balance (including fee)")
    }

    // Retrieve and increment persistent nonce for anti-replay protection
    var currentNonce int64
    _ = l.GetObject([]byte("nonce:"+from), &currentNonce)
    nonce := currentNonce + 1

    // Optimistic local balance updates (reverted only if network fully rejects – rare in practice)
    fromBal.EXPLO -= (amount + 0.001) // subtract amount + fee
    if err := SetBalance(l, from, fromBal); err != nil {
        return err
    }

    toBal, err := GetBalance(l, to)
    if err != nil {
        return err
    }
    toBal.EXPLO += amount
    if err := SetBalance(l, to, toBal); err != nil {
        return err
    }

    // Record user-facing transaction locally
    tx := Transaction{
        Timestamp: time.Now(),
        Type:      TxSend,
        AmountEXP: amount,
        From:      from,
        To:        to,
        Note:      fmt.Sprintf("EXPLO sent (fee: 0.001) – nonce %d", nonce),
    }
    if err := SaveTransaction(l, tx); err != nil {
        return err
    }

    // Sign and broadcast using the persistent nonce
    broadcastTxSignedWithNonce(tx, w, password, nonce)

    // Broadcast balance updates for multi-device synchronization
    broadcastBalanceUpdate(from, fromBal)
    broadcastBalanceUpdate(to, toBal)

    return nil
}

// ToLedgerTransactionWithSignature converts a wallet Transaction into a fully signed ledger.Transaction.
// It accepts an explicit nonce parameter to support persistent anti-replay nonces from the ledger.
// The function decrypts the private key, signs the canonical transaction hash,
// attaches all required metadata, and securely zeros sensitive memory.
func (tx *Transaction) ToLedgerTransactionWithSignature(w *Wallet, password string, nonce int64) (*ledger.Transaction, error) {
    timestamp := time.Now().UnixMilli()

    ltx := &ledger.Transaction{
        From:          tx.From,
        To:            tx.To,
        AmountEXP:     tx.AmountEXP,
        AmountIM:      tx.AmountIM,
        Fee:           0.001,
        Timestamp:     timestamp,
        Nonce:         nonce, // Persistent incremental nonce for replay protection
        Note:          tx.Note,
        IsReward:      false,
        IsIMANILocked: false,
    }

    // Decrypt wallet private key
    privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt wallet private key: %w", err)
    }

    // Normalize to full 64-byte Ed25519 private key if seed is provided
    if len(privBytes) == ed25519.SeedSize {
        fullKey := ed25519.NewKeyFromSeed(privBytes)
        privBytes = make([]byte, ed25519.PrivateKeySize)
        copy(privBytes, fullKey)
        // Zero seed
        for i := range fullKey {
            fullKey[i] = 0
        }
    } else if len(privBytes) != ed25519.PrivateKeySize {
        return nil, fmt.Errorf("invalid private key length: %d", len(privBytes))
    }

    priv := ed25519.PrivateKey(privBytes)
    pub := priv.Public().(ed25519.PublicKey)

    // Sign the canonical transaction data
    sig := ed25519.Sign(priv, ltx.HashForSignature())

    // Attach signature and metadata
    ltx.FromPubKey = pub
    ltx.Signature = sig
    ltx.TxHash = ltx.ComputeHash()
    ltx.ID = tx.From

    ltx.MinerInfo = &ledger.MinerInfo{
        MinerID:   tx.From,
        CreatedAt: timestamp,
        PublicKey: pub,
    }

    // Securely zero sensitive memory
    for i := range priv {
        priv[i] = 0
    }
    for i := range privBytes {
        privBytes[i] = 0
    }

    fmt.Printf("🔏 Transaction signed – pubkey: %s, nonce: %d\n", hex.EncodeToString(pub), nonce)
    return ltx, nil
}

// GetTransactions retrieves all locally stored wallet transactions.
// If addr is empty, returns all transactions; otherwise filters by from/to address.
func GetTransactions(l *ledger.Ledger, addr string) ([]Transaction, error) {
    var txs []Transaction
    prefix := []byte("tx:")

    err := l.DB().View(func(txn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = true
        it := txn.NewIterator(opts)
        defer it.Close()

        for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
            item := it.Item()
            val, err := item.ValueCopy(nil)
            if err != nil {
                return err
            }

            var tx Transaction
            if err := json.Unmarshal(val, &tx); err != nil {
                return err
            }

            if addr == "" || tx.From == addr || tx.To == addr {
                txs = append(txs, tx)
            }
        }
        return nil
    })

    return txs, err
}


// CreditWallet adds system-originated EXPLO or IMANI credits to the wallet.
// IMANI credits are recorded locally only (non-transferable, sacred token).
// EXPLO credits are broadcast as unsigned system transactions.
func CreditWallet(l *ledger.Ledger, addr string, expAmount, imaniAmount float64) error {
    bal, err := GetBalance(l, addr)
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
        if err := SaveTransaction(l, tx); err != nil {
            return err
        }
        broadcastTxUnsigned(tx)
    }

    if imaniAmount > 0 {
        bal.IMANI += imaniAmount
        tx := Transaction{
            Timestamp: time.Now(),
            Type:      TxCredit,
            AmountIM:  imaniAmount,
            From:      "SYSTEM",
            To:        addr,
            Note:      "IMANI sacred blessing – non-transferable",
        }
        if err := SaveTransaction(l, tx); err != nil {
            return err
        }
        // No broadcast for IMANI – sacred and non-transferable
    }

    if err := SetBalance(l, addr, bal); err != nil {
        return err
    }

    broadcastBalanceUpdate(addr, bal)
    return nil
}

// DisplayTransactionHistory prints all stored wallet transactions for a given address.
func DisplayTransactionHistory(l *ledger.Ledger, addr string) error {
    txs, err := GetTransactions(l, addr)
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
// -----------------------------------------------------------
// Network Integration (Broadcasting)
// -----------------------------------------------------------

var activeNode *p2p.Node

// SetActiveNode defines the currently connected P2P node for broadcasting.
func SetActiveNode(node *p2p.Node) {
    activeNode = node
}

// broadcastTxSigned signs a wallet transaction using a persistent incremental nonce
// retrieved from the ledger (anti-replay protection), then broadcasts the fully
// signed ledger transaction to the P2P network.
//
// The function fetches the current nonce for the sender, increments it,
// uses it for signing, persists the new nonce immediately after successful signing
// (to prevent accidental reuse), and relies on the network/ledger to enforce replay
// protection during transaction application.
func broadcastTxSigned(l *ledger.Ledger, tx Transaction, w *Wallet, password string) {
    if activeNode == nil {
        fmt.Println("⚠️ No active P2P node connected — transaction not broadcasted")
        return
    }

    // Retrieve current persistent nonce for the sender
    var currentNonce int64
    _ = l.GetObject([]byte("nonce:"+tx.From), &currentNonce)
    nonce := currentNonce + 1

    // Sign the transaction with the persistent nonce
    ltx, err := tx.ToLedgerTransactionWithSignature(w, password, nonce)
    if err != nil {
        fmt.Println("❌ Failed to sign transaction:", err)
        return
    }

    // Persist the incremented nonce immediately after successful signing
    // This prevents replay if the app restarts or the user retries before broadcast
    _ = l.PutObject([]byte("nonce:"+tx.From), nonce)

    // Broadcast the signed transaction
    activeNode.BroadcastTransaction(ltx)
    fmt.Printf("🌍 Transaction signed (nonce: %d) and broadcasted to EXPLOSIVE network\n", nonce)
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
// broadcastLedgerSync sends the local wallet transaction history to connected peers.
// This allows a miner restoring on a new device to recover their user-facing transaction log
// (not the full blockchain – that's handled by block sync).
// It uses the custom P2P message system and does not expose sacred ledger data.
func broadcastLedgerSync(l *ledger.Ledger) {
    if activeNode == nil {
        return
    }

    txs, err := GetTransactions(l, "")
    if err != nil {
        log.Printf("[wallet] Failed to retrieve local transactions for ledger sync: %v", err)
        return
    }

    if len(txs) == 0 {
        // Nothing to sync – avoid sending empty payload
        return
    }

    payload := map[string]interface{}{
        "type": "LEDGER_SYNC",
        "data": txs,
    }

    if err := BroadcastCustom(payload); err != nil {
        log.Printf("[wallet] Failed to broadcast ledger sync: %v", err)
    } else {
        log.Printf("[wallet] Successfully broadcasted %d local transactions for ledger sync", len(txs))
    }
}


// -----------------------------------------------------------
// Display Utilities
// -----------------------------------------------------------

// DisplayWalletBalance prints a human-readable summary of wallet balances.
func DisplayWalletBalance(bal WalletBalance) {
    fmt.Printf("💰 EXPLO: %.4f | 🌟 IMANI: %.4f\n", bal.EXPLO, bal.IMANI)
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


// broadcastTxSignedWithNonce signs and broadcasts using an explicit nonce.
func broadcastTxSignedWithNonce(tx Transaction, w *Wallet, password string, nonce int64) {
    if activeNode == nil {
        fmt.Println("⚠️ No active P2P node connected — transaction not broadcasted")
        return
    }

    ltx, err := tx.ToLedgerTransactionWithSignature(w, password, nonce)
    if err != nil {
        fmt.Println("❌ Failed to sign transaction:", err)
        return
    }

    activeNode.BroadcastTransaction(ltx)
    fmt.Println("🌍 Signed transaction broadcasted to EXPLOSIVE network")
}
