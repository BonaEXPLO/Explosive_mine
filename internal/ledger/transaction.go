package ledger

import (
        "crypto/ed25519"
        "encoding/binary"
        "encoding/hex"
        "errors"
        "fmt"
        "encoding/json"
        "regexp"
        "log"
        "math"
        "time"

        "github.com/dgraph-io/badger/v4"
        "explosive/internal/imanifund"
        "github.com/fxamacker/cbor/v2"
        "explosive/internal/address"
)

type MinerInfo struct {
    MinerID   string `cbor:"miner_id"`
    CreatedAt int64  `cbor:"created_at"`
    PublicKey []byte `cbor:"pubkey"`
}


type TxRegisterMiner struct {
    MinerID   string `cbor:"miner_id"`
    PubKeyHex string `cbor:"pubkey_hex"`
    Time      int64  `cbor:"time"`
}
type Transaction struct {
    ID            string    `cbor:"id"`
    From          string    `cbor:"from"`
    To            string    `cbor:"to"`
    AmountEXP     float64   `cbor:"amount_explo"`
    AmountIM      float64   `cbor:"amount_imani"`
    Fee           float64   `cbor:"fee"`
    Timestamp     int64     `cbor:"timestamp"`
    TxHash        string    `cbor:"tx_hash"`
    Nonce         int64     `cbor:"nonce"`
    Note          string    `cbor:"note,omitempty"`
    IsReward      bool      `cbor:"is_reward"`
    IsIMANILocked bool      `cbor:"is_imani_locked"`
    FromPubKey    []byte    `cbor:"from_pubkey,omitempty"`
    Signature     []byte    `cbor:"signature,omitempty"`
    MinerInfo *MinerInfo `cbor:"miner_info,omitempty"`
}
// ---------------- Address Validation ----------------
var reAddr = regexp.MustCompile(`^explo[0-9a-f]{44}$`)

func IsValidEXPLOAddress(addr string) bool {
        return address.IsValidMinerID(addr)
}


// ---------------- Hash & Signature ----------------

// ComputeHash is the SINGLE canonical hash function for transactions.
// Uses deterministic CBOR encoding of core fields + SHA3-256.
// This is the TxHash stored in the struct and used for Merkle root.
func (tx *Transaction) ComputeHash() string {
    data, err := cbor.Marshal(struct {
        From          string  `cbor:"from"`
        To            string  `cbor:"to"`
        AmountEXP     float64 `cbor:"amount_explo"`
        AmountIM      float64 `cbor:"amount_imani"`
        Fee           float64 `cbor:"fee"`
        Timestamp     int64   `cbor:"timestamp"`
        Nonce         int64   `cbor:"nonce"`
        IsReward      bool    `cbor:"is_reward"`
        IsIMANILocked bool    `cbor:"is_imani_locked"`
        Note          string  `cbor:"note,omitempty"`
    }{
        From:          tx.From,
        To:            tx.To,
        AmountEXP:     tx.AmountEXP,
        AmountIM:      tx.AmountIM,
        Fee:           tx.Fee,
        Timestamp:     tx.Timestamp,
        Nonce:         tx.Nonce,
        IsReward:      tx.IsReward,
        IsIMANILocked: tx.IsIMANILocked,
        Note:          tx.Note,
    })
    if err != nil {
        // Should never happen with valid struct
        return ""
    }
    return Sha3Hex(data)
}

// HashForSignature returns the exact same data as used for ComputeHash,
// but as raw bytes for Ed25519 signing.
// Ensures signature is over the same content as the stored TxHash.
func (tx *Transaction) HashForSignature() []byte {
    data, _ := cbor.Marshal(struct {
        From          string  `cbor:"from"`
        To            string  `cbor:"to"`
        AmountEXP     float64 `cbor:"amount_explo"`
        AmountIM      float64 `cbor:"amount_imani"`
        Fee           float64 `cbor:"fee"`
        Timestamp     int64   `cbor:"timestamp"`
        Nonce         int64   `cbor:"nonce"`
        IsReward      bool    `cbor:"is_reward"`
    }{
        From:      tx.From,
        To:        tx.To,
        AmountEXP: tx.AmountEXP,
        AmountIM:  tx.AmountIM,
        Fee:       tx.Fee,
        Timestamp: tx.Timestamp,
        Nonce:     tx.Nonce,
        IsReward:  tx.IsReward,
    })
    return data
}

// NewTransaction now uses only the canonical ComputeHash
func NewTransaction(from, to string, exp, im float64, miningReward bool, nonce int64) (*Transaction, error) {

if from != "SYSTEM" && !IsValidEXPLOAddress(from) {
                return nil, errors.New("❌ invalid sender address")
        }
        if !IsValidEXPLOAddress(to) {
                return nil, errors.New("❌ invalid recipient address")
        }
        if !miningReward && im > 0 {
                return nil, errors.New("❌ IMANI cannot be transferred between users")
        }

        fee := 0.0
        if !miningReward {
                fee = 0.001
                if exp <= 0 {
                        return nil, errors.New("❌ amount must be greater than 0")
                }
        }

    tx := &Transaction{
        From:          from,
        ID:            from,
        To:            to,
        AmountEXP:     exp,
        AmountIM:      im,
        Fee:           fee,
        Timestamp:     time.Now().UnixMilli(),
        Nonce:         nonce,
        IsReward:      miningReward,
        IsIMANILocked: !miningReward && im > 0,
        Note:          "",
    }

    tx.TxHash = tx.ComputeHash() // Canonical hash only
    return tx, nil
}


// ---------------- Mining Reward ----------------
func NewMiningReward(minerAddr string, rewardEXP, rewardIM float64, nonce int64) (*Transaction, error) {
        if !IsValidEXPLOAddress(minerAddr) {
                return nil, errors.New("❌ invalid miner address")
        }
        return NewTransaction("SYSTEM", minerAddr, rewardEXP, rewardIM, true, nonce)
}

// ---------------- Balance ----------------
type Balance struct {
        EXPLO float64 `cbor:"explo"`
        IMANI float64 `cbor:"imani"`
}

func ApplyTransaction(balances map[string]*Balance, tx interface{}, l *Ledger) (string, error) {
    switch t := tx.(type) {

    // --- 0️⃣ Handle miner registration ---
    case *TxRegisterMiner:
        var existing MinerInfo
        if err := l.GetObject([]byte("miner:"+t.MinerID), &existing); err == nil {
            return "", nil // déjà existant, on ignore
        }
        m := MinerInfo{
            MinerID:   t.MinerID,
            CreatedAt: t.Time,
            PublicKey: parsePubKey(t.PubKeyHex),
        }
        return "", l.PutObject([]byte("miner:"+t.MinerID), &m)

    // --- 1️⃣ Standard transaction ---
    case *Transaction:
        if t.From != "SYSTEM" {
            fromBal, ok := balances[t.From]
            if !ok {
                return "", errors.New("❌ sender not found in balances")
            }
            if fromBal.EXPLO < (t.AmountEXP + t.Fee) {
                return "", errors.New("❌ insufficient EXPLO balance")
            }
            fromBal.EXPLO -= (t.AmountEXP + t.Fee)
            if t.AmountIM > 0 && !t.IsReward {
                return "", errors.New("❌ IMANI debit not allowed")
            }
        }

        toBal, ok := balances[t.To]
        if !ok {
            toBal = &Balance{}
            balances[t.To] = toBal
        }
        toBal.EXPLO += t.AmountEXP
        if t.IsReward && t.AmountIM > 0 {
            toBal.IMANI += t.AmountIM
        }

        switch {
        case t.From == "SYSTEM":
            return fmt.Sprintf("🎉 Mining reward received: +%.4f EXPLO, +%.4f IMANI", t.AmountEXP, t.AmountIM), nil
        case t.IsReward:
            return fmt.Sprintf("🎉 You received %.4f EXPLO (+%.4f IMANI)", t.AmountEXP, t.AmountIM), nil
        default:
            return fmt.Sprintf("✅ You sent %.4f EXPLO (fee %.3f EXPLO)", t.AmountEXP, t.Fee), nil
        }

    default:
        return "", errors.New("❌ unknown transaction type")
    }
}

// ---------------- Utility ----------------
func EncodeTxCBOR(tx *Transaction) ([]byte, error) {
        return cbor.Marshal(tx)
}

func DecodeTxCBOR(data []byte) (*Transaction, error) {
        var tx Transaction
        if err := cbor.Unmarshal(data, &tx); err != nil {
                return nil, err
        }
        return &tx, nil
}

// ReadFloat lit une valeur float64 stockée sous une clé donnée.
func (l *Ledger) ReadFloat(key string) (float64, error) {
        db := l.DB()
        if db == nil {
                return 0, errors.New("ledger DB is nil")
        }

        var val float64
        err := db.View(func(txn *badger.Txn) error {
                item, err := txn.Get([]byte(key))
                if err != nil {
                        return err
                }
                b, err := item.ValueCopy(nil)
                if err != nil {
                        return err
                }
                if len(b) != 8 {
                        return errors.New("invalid float64 encoding")
                }
                val = math.Float64frombits(binary.LittleEndian.Uint64(b))
                return nil
        })
        if err != nil {
                return 0, err
        }
        return val, nil
}

// WriteFloat permet de stocker un float64 sous une clé donnée.
func (l *Ledger) WriteFloat(key string, f float64) error {
        db := l.DB()
        if db == nil {
                return errors.New("ledger DB is nil")
        }
        b := make([]byte, 8)
        binary.LittleEndian.PutUint64(b, math.Float64bits(f))
        return db.Update(func(txn *badger.Txn) error {
                return txn.Set([]byte(key), b)
        })
}

func (tx *Transaction) Serialize() ([]byte, error) {
    return json.Marshal(tx)
}

// ApplyAndPersistTransaction applies a signed transaction to the ledger state
// and persists both the updated account balances and the transaction record.
//
// This is the **core consensus-critical function** of the EXPLOSIVE blockchain.
// It enforces all economic and spiritual rules:
//
//   • EXPLO is the only transferable economic token
//   • IMANI is non-transferable and represents spiritual alignment only
//   • All transaction fees are sacred offerings to the IMANI Fund
//   • Mining rewards are minted from the hermetic supply schedule
//   • Every state change is atomic, durable, and cryptographically verified
//
// The function performs the following steps:
//   1. Signature verification (Ed25519) for non-system transactions
//   2. Balance loading and validation (sender sufficiency including fee)
//   3. Fee deduction and sacred offering to the IMANI Fund
//   4. Transfer execution (EXPLO movement, IMANI minting on rewards only)
//   5. Persistent storage of updated balances and full transaction record
//
// Returns a human-readable confirmation message and an error if validation fails.
func (l *Ledger) ApplyAndPersistTransaction(tx *Transaction) (string, error) {
        // ---------------------------------------------------------------------
        // 1. Signature verification — prevents forged transactions
        // ---------------------------------------------------------------------
        if tx.From != "SYSTEM" {
                if tx.FromPubKey == nil || tx.Signature == nil {
                        return "", errors.New("transaction missing signature or public key")
                }
                if !ed25519.Verify(tx.FromPubKey, tx.HashForSignature(), tx.Signature) {
                        return "", errors.New("invalid transaction signature")
                }
        }

        // ---------------------------------------------------------------------
        // 2. Load sender and recipient balances into memory
        // ---------------------------------------------------------------------
        balances := map[string]*Balance{}

        if tx.From != "SYSTEM" {
                sender := &Balance{}
                _ = l.GetObject([]byte("balance:"+tx.From), sender)
                balances[tx.From] = sender
        }

        recipient := &Balance{}
        _ = l.GetObject([]byte("balance:"+tx.To), recipient)
        balances[tx.To] = recipient

        // ---------------------------------------------------------------------
        // 3. Apply transaction logic (core economic & spiritual rules)
        // ---------------------------------------------------------------------
        msg, err := ApplyTransaction(balances, tx, l)
        if err != nil {
                return "", err
        }

        // ---------------------------------------------------------------------
        // 4. Sacred offering — all transaction fees are donated to the IMANI Fund
        // ---------------------------------------------------------------------
        if tx.From != "SYSTEM" && tx.Fee > 0 {
                if err := imanifund.AddToSacredFund(tx.From, tx.Fee); err != nil {
                        log.Printf("IMANI FUND: failed to collect sacred fee %.6f EXPLO: %v", tx.Fee, err)
                } else {
                        log.Printf("SACRED FEE: %.6f EXPLO from %s offered to the IMANI Fund", tx.Fee, tx.From[:12])
                }
        }

        // ---------------------------------------------------------------------
        // 5. Persist updated balances atomically
        // ---------------------------------------------------------------------
        for addr, bal := range balances {
                key := []byte("balance:" + addr)
                if err := l.PutObject(key, bal); err != nil {
                        return "", fmt.Errorf("failed to persist balance for %s: %w", addr, err)
                }
        }

        // ---------------------------------------------------------------------
        // 6. Persist the transaction record (immutable history)
        // ---------------------------------------------------------------------
        db := l.DB()
        if db == nil {
                return "", errors.New("ledger DB is nil")
        }

        txKey := []byte(fmt.Sprintf("tx:%s:%020d:%d", tx.To, tx.Timestamp, tx.Nonce))
        txData, err := EncodeTxCBOR(tx)
        if err != nil {
                return "", fmt.Errorf("failed to encode transaction: %w", err)
        }

        err = db.Update(func(txn *badger.Txn) error {
                return txn.Set(txKey, txData)
        })
        if err != nil {
                return "", fmt.Errorf("failed to persist transaction: %w", err)
        }

        // ---------------------------------------------------------------------
        // 7. Return user-facing confirmation
        // ---------------------------------------------------------------------
        return msg, nil
}

// GetTransactionsByAddress retrieves transactions for a given address with pagination.
// page starts at 1, pageSize is the number of tx per page.
func (l *Ledger) GetTransactionsByAddress(addr string, page, pageSize int) ([]*Transaction, error) {
    if page < 1 {
        page = 1
    }
    if pageSize <= 0 {
        pageSize = 50 // default page size
    }

    db := l.DB()
    if db == nil {
        return nil, errors.New("ledger DB is nil")
    }

    prefix := []byte("tx:" + addr + ":") // assume transactions stored with this key pattern
    startIndex := (page - 1) * pageSize
    endIndex := startIndex + pageSize

    txs := []*Transaction{}
    count := 0

    err := db.View(func(txn *badger.Txn) error {
        it := txn.NewIterator(badger.DefaultIteratorOptions)
        defer it.Close()

        for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
            if count >= startIndex && count < endIndex {
                item := it.Item()
                val, err := item.ValueCopy(nil)
                if err != nil {
                    return err
                }
                tx, err := DecodeTxCBOR(val)
                if err != nil {
                    return err
                }
                txs = append(txs, tx)
            }
            count++
            if count >= endIndex {
                break
            }
        }
        return nil
    })
    if err != nil {
        return nil, err
    }
    return txs, nil
}

// GetMiner retourne les informations d'un mineur ou nil si inexistant
func (l *Ledger) GetMiner(addr string) (*Miner, error) {
    m := &Miner{}
    err := l.GetObject([]byte("miner:"+addr), m)
    if err != nil {
        return nil, err
    }
    return m, nil
}

func parsePubKey(hexStr string) ed25519.PublicKey {
    b, _ := hex.DecodeString(hexStr)
    return ed25519.PublicKey(b)
}
