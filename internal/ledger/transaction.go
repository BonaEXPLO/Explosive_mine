package ledger

import (
	"crypto/ed25519"
	"errors"
        "encoding/binary"
        "github.com/dgraph-io/badger/v4"
	"explosive/internal/address"
	"fmt"
	"regexp"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ---------------- Transaction Struct ----------------
type Transaction struct {
	ID            string  `cbor:"id"`                  // Wallet address of sender (From)
	From          string  `cbor:"from"`                // Sender address or "SYSTEM"
	To            string  `cbor:"to"`                  // Recipient address
	AmountEXP     float64 `cbor:"amount_explo"`        // EXPLO amount
	AmountIM      float64 `cbor:"amount_imani"`        // IMANI amount (only via mining rewards)
	Fee           float64 `cbor:"fee"`                 // Transaction fee in EXPLO
	Timestamp     int64   `cbor:"timestamp"`           // Unix timestamp (ms)
	TxHash        string  `cbor:"tx_hash"`             // SHA3-256 hash of the tx
	Note          string  `cbor:"note,omitempty"`      // Optional note
	IsReward      bool    `cbor:"is_reward"`           // True if mining/system reward
	IsIMANILocked bool    `cbor:"is_imani_locked"`     // IMANI is non-transferable
	FromPubKey    []byte  `cbor:"from_pubkey,omitempty"` // Ed25519 public key
	Signature     []byte  `cbor:"signature,omitempty"`  // Ed25519 signature
}

// ---------------- Address Validation ----------------
var reAddr = regexp.MustCompile(`^explo[0-9a-f]{44}$`)

func IsValidEXPLOAddress(addr string) bool {
	return address.IsValidMinerID(addr)
}

// ---------------- Transaction Helpers ----------------
func NewTransaction(from, to string, exp, im float64, miningReward bool) (*Transaction, error) {
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
        ID:            from, // ID = wallet address
        To:            to,
        AmountEXP:     exp,   // ✅ montant exact demandé
        AmountIM:      im,
        Fee:           fee,   // ✅ frais séparé
        Timestamp:     time.Now().UnixMilli(),
        IsReward:      miningReward,
        IsIMANILocked: !miningReward && im > 0,
    }

    tx.TxHash = tx.ComputeHash()
    return tx, nil
}

// ---------------- Hash & Signature ----------------
func (tx *Transaction) ComputeHash() string {
	data, _ := cbor.Marshal(struct {
		From      string  `cbor:"from"`
		To        string  `cbor:"to"`
		AmountEXP float64 `cbor:"amount_explo"`
		AmountIM  float64 `cbor:"amount_imani"`
		Fee       float64 `cbor:"fee"`
		Timestamp int64   `cbor:"timestamp"`
		IsReward  bool    `cbor:"is_reward"`
	}{
		From:      tx.From,
		To:        tx.To,
		AmountEXP: tx.AmountEXP,
		AmountIM:  tx.AmountIM,
		Fee:       tx.Fee,
		Timestamp: tx.Timestamp,
		IsReward:  tx.IsReward,
	})
	return Sha3Hex(data)
}

// HashForSignature returns the deterministic bytes used for Ed25519 signing
func (tx *Transaction) HashForSignature() []byte {
	data := fmt.Sprintf("%s|%s|%f|%f|%f|%d", tx.From, tx.To, tx.AmountEXP, tx.AmountIM, tx.Fee, tx.Timestamp)
	return []byte(data)
}

// ---------------- Mining Reward ----------------
func NewMiningReward(minerAddr string, rewardEXP, rewardIM float64) (*Transaction, error) {
	if !IsValidEXPLOAddress(minerAddr) {
		return nil, errors.New("❌ invalid miner address")
	}
	return NewTransaction("SYSTEM", minerAddr, rewardEXP, rewardIM, true)
}

// ---------------- Balance ----------------
type Balance struct {
	EXPLO float64 `cbor:"explo"`
	IMANI float64 `cbor:"imani"`
}

func ApplyTransaction(balances map[string]*Balance, tx *Transaction) (string, error) {
	if tx.From != "SYSTEM" {
		fromBal, ok := balances[tx.From]
		if !ok {
			return "", errors.New("❌ sender not found in balances")
		}
		if fromBal.EXPLO < (tx.AmountEXP + tx.Fee) {
			return "", errors.New("❌ insufficient EXPLO balance")
		}
		fromBal.EXPLO -= (tx.AmountEXP + tx.Fee)
		if tx.AmountIM > 0 && !tx.IsReward {
			return "", errors.New("❌ IMANI debit not allowed")
		}
	}

	toBal, ok := balances[tx.To]
	if !ok {
		toBal = &Balance{}
		balances[tx.To] = toBal
	}
	toBal.EXPLO += tx.AmountEXP
	if tx.IsReward && tx.AmountIM > 0 {
		toBal.IMANI += tx.AmountIM
	}

	if tx.From == "SYSTEM" {
		return fmt.Sprintf("🎉 Mining reward received: +%.4f EXPLO, +%.4f IMANI", tx.AmountEXP, tx.AmountIM), nil
	}
	if tx.IsReward {
		return fmt.Sprintf("🎉 You received %.4f EXPLO (+%.4f IMANI)", tx.AmountEXP, tx.AmountIM), nil
	}
	if tx.From != "SYSTEM" {
		return fmt.Sprintf("✅ You sent %.4f EXPLO (fee %.3f EXPLO)", tx.AmountEXP, tx.Fee), nil
	}
	return fmt.Sprintf("🎉 You received %.4f EXPLO", tx.AmountEXP), nil
}

// ---------------- Ledger Integration ----------------
func (l *Ledger) ApplyAndPersistTransaction(tx *Transaction) (string, error) {
	if tx.From != "SYSTEM" {
		if tx.FromPubKey == nil || tx.Signature == nil {
			return "", errors.New("❌ transaction missing signature or public key")
		}
		if !ed25519.Verify(tx.FromPubKey, tx.HashForSignature(), tx.Signature) {
			return "", errors.New("❌ invalid transaction signature")
		}
	}

	balances := map[string]*Balance{}
	if tx.From != "SYSTEM" {
		sender := &Balance{}
		_ = l.GetObject([]byte("balance:"+tx.From), sender)
		balances[tx.From] = sender
	}

	recipient := &Balance{}
	_ = l.GetObject([]byte("balance:"+tx.To), recipient)
	balances[tx.To] = recipient

	msg, err := ApplyTransaction(balances, tx)
	if err != nil {
		return "", err
	}

	for addr, bal := range balances {
		key := []byte("balance:" + addr)
		if err := l.PutObject(key, bal); err != nil {
			return "", fmt.Errorf("❌ failed to persist balance for %s: %w", addr, err)
		}
	}

	return msg, nil
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
// La clé peut être "balance:<minerID>:EXPLO", "total_imani", etc.
func (l *Ledger) ReadFloat(key string) (float64, error) {
    db := l.GetDB()
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
        val = float64(binary.LittleEndian.Uint64(b))
        return nil
    })
    if err != nil {
        return 0, err
    }
    return val, nil
}

// WriteFloat permet de stocker un float64 sous une clé donnée.
func (l *Ledger) WriteFloat(key string, f float64) error {
    db := l.GetDB()
    if db == nil {
        return errors.New("ledger DB is nil")
    }
    b := make([]byte, 8)
    binary.LittleEndian.PutUint64(b, uint64(f))
    return db.Update(func(txn *badger.Txn) error {
        return txn.Set([]byte(key), b)
    })
}
