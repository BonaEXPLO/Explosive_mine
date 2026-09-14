package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"

	"explosive/internal/address"
	"explosive/internal/imanifund"
)

// ============================================================
// EXPLOSIVE LEDGER TRANSACTION ENGINE
// ============================================================
//
// SECURITY MODEL
//
// The ledger is the monetary authority of EXPLOSIVE.
//
// Wallets:
//   - create keys
//   - sign transactions
//   - submit transactions
//
// P2P:
//   - transports transactions
//
// Ledger:
//   - validates transactions
//   - validates signatures
//   - validates addresses
//   - validates nonces
//   - validates balances
//   - applies supply rules
//   - applies fees
//   - persists consensus state
//
// IMPORTANT:
//
// No wallet, API, P2P peer or client is trusted to provide balances.
//
// Consensus monetary values use integer Pastabo.
//
// 1 EXPLO = 1,000,000,000 Pastabo
//
// ============================================================

// ---------------- Protocol constants ----------------

const (
	// Network fee = 0.01 EXPLO.
	DefaultFeePastabo uint64 = 10000000

	// Lifetime maximum EXPLO supply.
	MaxSupplyEXPLO uint64 = 50000000

	// Lifetime maximum in Pastabo.
	MaxSupplyPastabo uint64 = MaxSupplyEXPLO * PastaboPerEXPLO

	// IMANI multiplier for mining rewards.
	IMANIPerEXPLOReward uint64 = 1000

	// Maximum transaction note size.
	MaxTransactionNoteBytes = 1024

	// Maximum serialized transaction size.
	MaxTransactionCBORBytes = 256 * 1024

	// Timestamp tolerance.
	MaxFutureTransactionMs int64 = 2 * 60 * 60 * 1000
	MaxPastTransactionMs   int64 = 24 * 60 * 60 * 1000

	// Maximum history page size.
	MaxTransactionPageSize = 1000
)

// ============================================================
// Miner information
// ============================================================

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

// ============================================================
// Transaction
// ============================================================

type Transaction struct {
	// Legacy/display field.
	// TxHash is the canonical transaction identity.
	ID string `cbor:"id,omitempty"`

	From string `cbor:"from"`
	To   string `cbor:"to"`

	// UX fields.
	//
	// NEVER authoritative.
	AmountEXP float64 `cbor:"amount_explo,omitempty"`
	AmountIM  float64 `cbor:"amount_imani,omitempty"`
	Fee       float64 `cbor:"fee,omitempty"`

	// Consensus fields.
	//
	// These are authoritative.
	AmountPastabo   uint64 `cbor:"amount_pastabo"`
	AmountIMPastabo uint64 `cbor:"amount_imani_pastabo"`
	FeePastabo      uint64 `cbor:"fee_pastabo"`

	Timestamp int64  `cbor:"timestamp"`
	TxHash    string `cbor:"tx_hash"`
	Nonce     int64  `cbor:"nonce"`
	Note      string `cbor:"note,omitempty"`

	IsReward      bool `cbor:"is_reward"`
	IsIMANILocked bool `cbor:"is_imani_locked"`

	FromPubKey []byte `cbor:"from_pubkey,omitempty"`
	Signature  []byte `cbor:"signature,omitempty"`

	MinerInfo *MinerInfo `cbor:"miner_info,omitempty"`
}

// ============================================================
// Balance
// ============================================================

type Balance struct {
	// Consensus units.
	EXPLO uint64 `cbor:"explo_pastabo"`

	// IMANI is non-transferable.
	IMANI uint64 `cbor:"imani_pastabo"`

	// Lifetime amount received.
	TotalIMANIReceived uint64 `cbor:"total_imani_received"`
}

// ============================================================
// Address validation
// ============================================================

// IsValidEXPLOAddress is the single ledger address validator.
//
// internal/address/address.go is the source of truth.
func IsValidEXPLOAddress(addr string) bool {
	return address.IsValidEXPLOAddress(addr)
}

// ============================================================
// Canonical transaction payload
// ============================================================
//
// SECURITY:
//
// ComputeHash() and HashForSignature() MUST be based on the exact
// same canonical consensus fields.
//
// This prevents a transaction from being signed over one object
// while its transaction hash represents another object.
//
// Signature/public key are deliberately excluded because they are
// authentication metadata rather than the transaction payload.
//
// ============================================================

type canonicalTransaction struct {
	From            string `cbor:"from"`
	To              string `cbor:"to"`
	AmountPastabo   uint64 `cbor:"amount_pastabo"`
	AmountIMPastabo uint64 `cbor:"amount_imani_pastabo"`
	FeePastabo      uint64 `cbor:"fee_pastabo"`
	Timestamp       int64  `cbor:"timestamp"`
	Nonce           int64  `cbor:"nonce"`
	Note            string `cbor:"note,omitempty"`
	IsReward        bool   `cbor:"is_reward"`
	IsIMANILocked   bool   `cbor:"is_imani_locked"`
}

// canonicalPayload returns the exact bytes used for both hashing
// and signing.
func (tx *Transaction) canonicalPayload() ([]byte, error) {
	if tx == nil {
		return nil, errors.New("nil transaction")
	}

	payload := canonicalTransaction{
		From:            tx.From,
		To:              tx.To,
		AmountPastabo:   tx.AmountPastabo,
		AmountIMPastabo: tx.AmountIMPastabo,
		FeePastabo:      tx.FeePastabo,
		Timestamp:       tx.Timestamp,
		Nonce:           tx.Nonce,
		Note:            tx.Note,
		IsReward:        tx.IsReward,
		IsIMANILocked:   tx.IsIMANILocked,
	}

	data, err := cbor.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf(
			"canonical transaction encoding failed: %w",
			err,
		)
	}

	return data, nil
}

// ComputeHash computes the canonical transaction hash.
func (tx *Transaction) ComputeHash() string {
	data, err := tx.canonicalPayload()
	if err != nil {
		log.Printf("[ledger] ComputeHash failed: %v", err)
		return ""
	}

	return Sha3Hex(data)
}

// HashForSignature returns the exact canonical bytes signed by Ed25519.
func (tx *Transaction) HashForSignature() []byte {
	data, err := tx.canonicalPayload()
	if err != nil {
		return nil
	}

	return data
}

// ============================================================
// Transaction validation helpers
// ============================================================

func validateTimestamp(timestamp int64) error {
	if timestamp <= 0 {
		return errors.New("invalid timestamp")
	}

	now := time.Now().UnixMilli()

	if timestamp > now+MaxFutureTransactionMs {
		return errors.New("transaction timestamp too far in the future")
	}

	if timestamp < now-MaxPastTransactionMs {
		return errors.New("transaction timestamp too old")
	}

	return nil
}

func validateNonce(nonce int64) error {
	if nonce <= 0 {
		return errors.New("nonce must be positive")
	}

	return nil
}

func validateNote(note string) error {
	if len(note) > MaxTransactionNoteBytes {
		return errors.New("transaction note too large")
	}

	return nil
}

func validatePublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key length")
	}

	return nil
}

func validateSignature(sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature length")
	}

	return nil
}

func safeAddUint64(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, errors.New("uint64 overflow")
	}

	return a + b, nil
}

func safeSubUint64(a, b uint64) (uint64, error) {
	if b > a {
		return 0, errors.New("uint64 underflow")
	}

	return a - b, nil
}

func rewardIMANI(amountPastabo uint64) (uint64, error) {
	if amountPastabo == 0 {
		return 0, nil
	}

	if amountPastabo > math.MaxUint64/IMANIPerEXPLOReward {
		return 0, errors.New("IMANI reward overflow")
	}

	return amountPastabo * IMANIPerEXPLOReward, nil
}

// ============================================================
// Transaction structural validation
// ============================================================

func validateTransactionStructure(tx *Transaction) error {
	if tx == nil {
		return errors.New("nil transaction")
	}

	if err := validateTimestamp(tx.Timestamp); err != nil {
		return err
	}

	if err := validateNonce(tx.Nonce); err != nil {
		return err
	}

	if err := validateNote(tx.Note); err != nil {
		return err
	}

	if tx.From == "" {
		return errors.New("empty sender")
	}

	if tx.To == "" {
		return errors.New("empty recipient")
	}

	// SYSTEM is only valid for rewards.
	if tx.From == "SYSTEM" {
		if !tx.IsReward {
			return errors.New("SYSTEM may only create reward transactions")
		}
	} else {
		if !IsValidEXPLOAddress(tx.From) {
			return errors.New("invalid sender EXPLO address")
		}
	}

	if !IsValidEXPLOAddress(tx.To) {
		return errors.New("invalid recipient EXPLO address")
	}

	if tx.From != "SYSTEM" && tx.From == tx.To {
		return errors.New("sender and recipient cannot be identical")
	}

	// Zero-value normal transactions are forbidden.
	if tx.AmountPastabo == 0 && !tx.IsReward {
		return errors.New("zero amount transaction not allowed")
	}

	// A normal transfer can never carry IMANI.
	if !tx.IsReward && tx.AmountIMPastabo != 0 {
		return errors.New("IMANI cannot be transferred")
	}

	if !tx.IsReward && tx.IsIMANILocked {
		return errors.New("IMANI lock flag invalid on normal transaction")
	}

	// Rewards never pay transaction fees.
	if tx.IsReward && tx.FeePastabo != 0 {
		return errors.New("reward transaction cannot contain a fee")
	}

	// Normal transfers must use the protocol fee.
	if !tx.IsReward && tx.FeePastabo != DefaultFeePastabo {
		return errors.New("invalid transaction fee")
	}

	// UX values are display-only.
	//
	// If present, they must correspond to the authoritative
	// integer values.
	expectedEXP := float64(tx.AmountPastabo) / float64(PastaboPerEXPLO)
	expectedIM := float64(tx.AmountIMPastabo) / float64(PastaboPerEXPLO)
	expectedFee := float64(tx.FeePastabo) / float64(PastaboPerEXPLO)

	if !math.IsNaN(tx.AmountEXP) &&
		!math.IsInf(tx.AmountEXP, 0) &&
		tx.AmountEXP != 0 &&
		math.Abs(tx.AmountEXP-expectedEXP) > 1e-9 {
		return errors.New("AmountEXP does not match AmountPastabo")
	}

	if !math.IsNaN(tx.AmountIM) &&
		!math.IsInf(tx.AmountIM, 0) &&
		tx.AmountIM != 0 &&
		math.Abs(tx.AmountIM-expectedIM) > 1e-9 {
		return errors.New("AmountIM does not match AmountIMPastabo")
	}

	if !math.IsNaN(tx.Fee) &&
		!math.IsInf(tx.Fee, 0) &&
		tx.Fee != 0 &&
		math.Abs(tx.Fee-expectedFee) > 1e-9 {
		return errors.New("Fee does not match FeePastabo")
	}

	// Reward amount must be positive.
	if tx.IsReward && tx.AmountPastabo == 0 {
		return errors.New("zero mining reward not allowed")
	}

	// Validate the reward IMANI relationship.
	if tx.IsReward {
		expectedIMANI, err := rewardIMANI(tx.AmountPastabo)
		if err != nil {
			return err
		}

		if tx.AmountIMPastabo != expectedIMANI {
			return errors.New("invalid IMANI reward amount")
		}

		if !tx.IsIMANILocked {
			return errors.New("reward IMANI must be locked")
		}
	}

	return nil
}

// ============================================================
// Transaction creation
// ============================================================

func NewTransaction(
	from,
	to string,
	amountPastabo uint64,
	imaniPastabo uint64,
	feePastabo uint64,
	isReward bool,
	nonce int64,
	timestamp int64,
) (*Transaction, error) {

	if from != "SYSTEM" && !IsValidEXPLOAddress(from) {
		return nil, errors.New("invalid sender address")
	}

	if !IsValidEXPLOAddress(to) {
		return nil, errors.New("invalid recipient address")
	}

	if from != "SYSTEM" && from == to {
		return nil, errors.New("sender and recipient cannot be identical")
	}

	if timestamp <= 0 {
		return nil, errors.New("invalid timestamp")
	}

	if nonce <= 0 {
		return nil, errors.New("invalid nonce")
	}

	if !isReward && amountPastabo == 0 {
		return nil, errors.New("zero amount transaction not allowed")
	}

	if !isReward && imaniPastabo > 0 {
		return nil, errors.New("IMANI cannot be transferred")
	}

	if isReward {
		if from != "SYSTEM" {
			return nil, errors.New(
				"reward transaction must originate from SYSTEM",
			)
		}

		if feePastabo != 0 {
			return nil, errors.New("reward cannot contain a fee")
		}

		expectedIMANI, err := rewardIMANI(amountPastabo)
		if err != nil {
			return nil, err
		}

		if imaniPastabo != expectedIMANI {
			return nil, errors.New("invalid IMANI reward amount")
		}
	} else {
		if from == "SYSTEM" {
			return nil, errors.New(
				"SYSTEM cannot create normal transfers",
			)
		}

		if feePastabo != DefaultFeePastabo {
			return nil, errors.New("invalid transaction fee")
		}
	}

	tx := &Transaction{
		From:            from,
		To:              to,
		AmountPastabo:   amountPastabo,
		AmountIMPastabo: imaniPastabo,
		FeePastabo:      feePastabo,

		AmountEXP: float64(amountPastabo) / float64(PastaboPerEXPLO),
		AmountIM:  float64(imaniPastabo) / float64(PastaboPerEXPLO),
		Fee:       float64(feePastabo) / float64(PastaboPerEXPLO),

		Timestamp:     timestamp,
		Nonce:         nonce,
		IsReward:      isReward,
		IsIMANILocked: isReward && imaniPastabo > 0,
	}

	if err := validateTransactionStructure(tx); err != nil {
		return nil, err
	}

	tx.TxHash = tx.ComputeHash()

	if tx.TxHash == "" {
		return nil, errors.New("failed to compute transaction hash")
	}

	tx.ID = tx.TxHash

	return tx, nil
}

// ============================================================
// Mining reward creation
// ============================================================

func NewMiningReward(
	minerAddr string,
	rewardPastabo uint64,
	maniPastabo uint64,
	nonce int64,
	timestamp int64,
) (*Transaction, error) {

	if !IsValidEXPLOAddress(minerAddr) {
		return nil, errors.New("invalid miner address")
	}

	expectedIMANI, err := rewardIMANI(rewardPastabo)
	if err != nil {
		return nil, err
	}

	if maniPastabo != expectedIMANI {
		return nil, errors.New(
			"invalid mining reward IMANI amount",
		)
	}

	return NewTransaction(
		"SYSTEM",
		minerAddr,
		rewardPastabo,
		maniPastabo,
		0,
		true,
		nonce,
		timestamp,
	)
}

// ============================================================
// Pure transaction application
// ============================================================
//
// ApplyTransaction mutates only the supplied in-memory balance map.
//
// It performs NO database writes for normal transactions.
//
// ============================================================

func ApplyTransaction(
	balances map[string]*Balance,
	tx interface{},
	l *Ledger,
) (string, error) {

	if balances == nil {
		return "", errors.New("nil balances map")
	}

	switch t := tx.(type) {

	case *TxRegisterMiner:

		if t == nil {
			return "", errors.New("nil miner registration")
		}

		if l == nil {
			return "", errors.New("nil ledger")
		}

		if !IsValidEXPLOAddress(t.MinerID) {
			return "", errors.New("invalid miner ID")
		}

		if t.Time <= 0 {
			return "", errors.New("invalid miner registration timestamp")
		}

		pub := parsePubKey(t.PubKeyHex)

		if len(pub) != ed25519.PublicKeySize {
			return "", errors.New("invalid miner public key")
		}

		derived := address.GenerateEXPLOAddress(pub)

		if derived != t.MinerID {
			return "", errors.New(
				"miner ID does not match public key",
			)
		}

		var existing MinerInfo

		err := l.GetObject(
			append([]byte(nil), append(PrefixMiner, []byte(t.MinerID)...)...),
			&existing,
		)

		if err == nil {
			if !bytes.Equal(existing.PublicKey, pub) {
				return "", errors.New(
					"miner already registered with different public key",
				)
			}

			return "", nil
		}

		if err != badger.ErrKeyNotFound {
			return "", err
		}

		m := MinerInfo{
			MinerID:   t.MinerID,
			CreatedAt: t.Time,
			PublicKey: append([]byte(nil), pub...),
		}

		return "", l.PutObject(
			append([]byte(nil), append(PrefixMiner, []byte(t.MinerID)...)...),
			&m,
		)

	case *Transaction:

		if t == nil {
			return "", errors.New("nil transaction")
		}

		if err := validateTransactionStructure(t); err != nil {
			return "", err
		}

		// --------------------------------------------------------
		// SYSTEM reward
		// --------------------------------------------------------

		if t.From == "SYSTEM" {

			if !t.IsReward {
				return "", errors.New(
					"SYSTEM transaction must be a reward",
				)
			}

			if t.FeePastabo != 0 {
				return "", errors.New(
					"system reward cannot contain fee",
				)
			}

			expectedIMANI, err := rewardIMANI(
				t.AmountPastabo,
			)

			if err != nil {
				return "", err
			}

			if t.AmountIMPastabo != expectedIMANI {
				return "", errors.New(
					"invalid reward IMANI amount",
				)
			}
		}

		// --------------------------------------------------------
		// Normal transfer
		// --------------------------------------------------------

		if t.From != "SYSTEM" {

			fromBal, ok := balances[t.From]

			if !ok || fromBal == nil {
				return "", errors.New("sender not found")
			}

			required, err := safeAddUint64(
				t.AmountPastabo,
				t.FeePastabo,
			)

			if err != nil {
				return "", errors.New(
					"transaction amount plus fee overflow",
				)
			}

			if fromBal.EXPLO < required {
				return "", errors.New(
					"insufficient EXPLO balance",
				)
			}

			newSenderBalance, err := safeSubUint64(
				fromBal.EXPLO,
				required,
			)

			if err != nil {
				return "", err
			}

			fromBal.EXPLO = newSenderBalance
		}

		// --------------------------------------------------------
		// Recipient
		// --------------------------------------------------------

		toBal, ok := balances[t.To]

		if !ok || toBal == nil {
			toBal = &Balance{}
			balances[t.To] = toBal
		}

		newRecipientBalance, err := safeAddUint64(
			toBal.EXPLO,
			t.AmountPastabo,
		)

		if err != nil {
			return "", errors.New(
				"recipient EXPLO balance overflow",
			)
		}

		toBal.EXPLO = newRecipientBalance

		// --------------------------------------------------------
		// IMANI reward
		// --------------------------------------------------------

		if t.IsReward {

			expectedIMANI, err := rewardIMANI(
				t.AmountPastabo,
			)

			if err != nil {
				return "", err
			}

			if t.AmountIMPastabo != expectedIMANI {
				return "", errors.New(
					"invalid IMANI reward amount",
				)
			}

			newIMANI, err := safeAddUint64(
				toBal.IMANI,
				expectedIMANI,
			)

			if err != nil {
				return "", errors.New(
					"IMANI balance overflow",
				)
			}

			newTotal, err := safeAddUint64(
				toBal.TotalIMANIReceived,
				expectedIMANI,
			)

			if err != nil {
				return "", errors.New(
					"total IMANI overflow",
				)
			}

			toBal.IMANI = newIMANI
			toBal.TotalIMANIReceived = newTotal
		}

		// --------------------------------------------------------
		// Confirmation message
		// --------------------------------------------------------

		if t.IsReward {
			return fmt.Sprintf(
				"Mining reward: +%.8f EXPLO",
				t.AmountEXP,
			), nil
		}

		return fmt.Sprintf(
			"Sent %.8f EXPLO (fee %.8f)",
			t.AmountEXP,
			t.Fee,
		), nil

	default:
		return "", errors.New("unknown transaction type")
	}
}

// ============================================================
// Apply + Persist
// ============================================================
//
// Consensus-critical database operation.
//
// Every state mutation is executed atomically inside one Badger
// transaction.
//
// ============================================================

func (l *Ledger) ApplyAndPersistTransaction(
	tx *Transaction,
) (string, error) {

	if l == nil {
		return "", errors.New("nil ledger")
	}

	if l.db == nil {
		return "", errors.New("ledger DB is nil")
	}

	if tx == nil {
		return "", errors.New("nil transaction")
	}

	// --------------------------------------------------------
	// 1. Structural validation
	// --------------------------------------------------------

	if err := validateTransactionStructure(tx); err != nil {
		return "", err
	}

	// --------------------------------------------------------
	// 2. Canonical hash verification
	// --------------------------------------------------------

	computedHash := tx.ComputeHash()

	if computedHash == "" {
		return "", errors.New(
			"failed to compute transaction hash",
		)
	}

	if computedHash != tx.TxHash {
		return "", errors.New(
			"transaction hash mismatch",
		)
	}

	if tx.ID != "" && tx.ID != tx.TxHash {
		return "", errors.New(
			"transaction ID does not match TxHash",
		)
	}

	// --------------------------------------------------------
	// 3. Signature verification
	// --------------------------------------------------------

	if tx.From != "SYSTEM" {

		if err := validatePublicKey(tx.FromPubKey); err != nil {
			return "", err
		}

		if err := validateSignature(tx.Signature); err != nil {
			return "", err
		}

		// CRITICAL:
		//
		// The public key must actually derive the sender address.
		derivedAddress := address.GenerateEXPLOAddress(
			ed25519.PublicKey(tx.FromPubKey),
		)

		if derivedAddress != tx.From {
			return "", errors.New(
				"public key does not match sender address",
			)
		}

		signPayload := tx.HashForSignature()

		if len(signPayload) == 0 {
			return "", errors.New(
				"empty signature payload",
			)
		}

		if !ed25519.Verify(
			ed25519.PublicKey(tx.FromPubKey),
			signPayload,
			tx.Signature,
		) {
			return "", errors.New(
				"invalid transaction signature",
			)
		}

	} else {

		// SYSTEM transactions must never contain a user signature.
		if len(tx.Signature) != 0 ||
			len(tx.FromPubKey) != 0 {
			return "", errors.New(
				"SYSTEM reward cannot contain user signature",
			)
		}
	}

	// --------------------------------------------------------
	// 4. Chain time diagnostics
	// --------------------------------------------------------

	latestBlock, err := l.GetLatestBlock()

	if err == nil &&
		latestBlock != nil &&
		latestBlock.Header.Timestamp > 0 {

		lastBlockTime := latestBlock.Header.Timestamp

		const softFutureMs int64 = 60 * 60 * 1000
		const softPastMs int64 = 24 * 60 * 60 * 1000

		if tx.Timestamp > lastBlockTime+softFutureMs {
			log.Printf(
				"[ledger] warning: tx %s is ahead of chain time by %d ms",
				safeShort(tx.TxHash),
				tx.Timestamp-lastBlockTime,
			)
		}

		if tx.Timestamp < lastBlockTime-softPastMs {
			log.Printf(
				"[ledger] warning: tx %s is behind chain time by %d ms",
				safeShort(tx.TxHash),
				lastBlockTime-tx.Timestamp,
			)
		}
	}

	// --------------------------------------------------------
	// 5. Atomic database operation
	// --------------------------------------------------------

	var confirmation string

	err = l.db.Update(func(txn *badger.Txn) error {

		// =====================================================
		// 5.1 Global duplicate protection
		// =====================================================

		txKey := []byte("tx:" + tx.TxHash)

		if _, err := txn.Get(txKey); err == nil {
			return errors.New(
				"transaction already exists",
			)
		} else if err != badger.ErrKeyNotFound {
			return err
		}

		// =====================================================
		// 5.2 Nonce protection
		// =====================================================

		if tx.From != "SYSTEM" {

			nonceKey := []byte("nonce:" + tx.From)

			var lastNonce uint64

			item, err := txn.Get(nonceKey)

			if err == nil {

				err = item.Value(func(v []byte) error {

					if len(v) != 8 {
						return errors.New(
							"corrupted nonce record",
						)
					}

					lastNonce = binary.BigEndian.Uint64(v)

					return nil
				})

				if err != nil {
					return err
				}

			} else if err != badger.ErrKeyNotFound {
				return err
			}

			// Strict sequential nonce.
			if lastNonce == math.MaxUint64 {
				return errors.New(
					"nonce exhausted",
				)
			}

			expectedNonce := lastNonce + 1

			if uint64(tx.Nonce) != expectedNonce {
				return fmt.Errorf(
					"invalid nonce: expected %d got %d",
					expectedNonce,
					tx.Nonce,
				)
			}

			nonceBytes := make([]byte, 8)

			binary.BigEndian.PutUint64(
				nonceBytes,
				uint64(tx.Nonce),
			)

			if err := txn.Set(
				nonceKey,
				nonceBytes,
			); err != nil {
				return err
			}
		}

		// =====================================================
		// 5.3 Load balances
		// =====================================================

		balances := make(map[string]*Balance)

		if tx.From != "SYSTEM" {

			sender := &Balance{}

			err := l.getObjectTxn(
				txn,
				[]byte("balance:"+tx.From),
				sender,
			)

			if err != nil {

				if err != badger.ErrKeyNotFound {
					return fmt.Errorf(
						"failed to load sender balance: %w",
						err,
					)
				}

				sender = &Balance{}
			}

			balances[tx.From] = sender
		}

		recipient := &Balance{}

		err := l.getObjectTxn(
			txn,
			[]byte("balance:"+tx.To),
			recipient,
		)

		if err != nil {

			if err != badger.ErrKeyNotFound {
				return fmt.Errorf(
					"failed to load recipient balance: %w",
					err,
				)
			}

			recipient = &Balance{}
		}

		balances[tx.To] = recipient

		// =====================================================
		// 5.4 SYSTEM reward authorization
		// =====================================================

		if tx.From == "SYSTEM" {

			if !tx.IsReward {
				return errors.New(
					"SYSTEM transaction is not a reward",
				)
			}

			// Reward recipient must be a registered miner.
			minerKey := make([]byte, 0, len(PrefixMiner)+len(tx.To))
			minerKey = append(minerKey, PrefixMiner...)
			minerKey = append(minerKey, tx.To...)

			var miner MinerInfo

			err := l.getObjectTxn(
				txn,
				minerKey,
				&miner,
			)

			if err != nil {
				if err == badger.ErrKeyNotFound {
					return errors.New(
						"reward recipient is not a registered miner",
					)
				}

				return fmt.Errorf(
					"failed to load miner identity: %w",
					err,
				)
			}

			if miner.MinerID != tx.To {
				return errors.New(
					"miner identity mismatch",
				)
			}

			if len(miner.PublicKey) != ed25519.PublicKeySize {
				return errors.New(
					"registered miner has invalid public key",
				)
			}

			derivedMinerID := address.GenerateEXPLOAddress(
				ed25519.PublicKey(miner.PublicKey),
			)

			if derivedMinerID != miner.MinerID {
				return errors.New(
					"registered miner public key does not match ID",
				)
			}

			expectedIMANI, err := rewardIMANI(
				tx.AmountPastabo,
			)

			if err != nil {
				return err
			}

			if tx.AmountIMPastabo != expectedIMANI {
				return errors.New(
					"invalid reward IMANI amount",
				)
			}
		}

		// =====================================================
		// 5.5 Supply protection
		// =====================================================

		if tx.IsReward {

			currentSupply, err := l.getTotalIssuedTxn(txn)

			if err != nil {
				return fmt.Errorf(
					"failed to read total issued supply: %w",
					err,
				)
			}

			newSupply, err := safeAddUint64(
				currentSupply,
				tx.AmountPastabo,
			)

			if err != nil {
				return errors.New(
					"total supply overflow",
				)
			}

			if newSupply > MaxSupplyPastabo {
				return errors.New(
					"maximum EXPLO supply exceeded",
				)
			}

			supplyBytes := make([]byte, 8)

			binary.BigEndian.PutUint64(
				supplyBytes,
				newSupply,
			)

			if err := txn.Set(
				[]byte("meta:total_issued"),
				supplyBytes,
			); err != nil {
				return err
			}
		}

		// =====================================================
		// 5.6 Apply transaction
		// =====================================================

		msg, err := ApplyTransaction(
			balances,
			tx,
			l,
		)

		if err != nil {
			return err
		}

		confirmation = msg

		// =====================================================
		// 5.7 Persist balances
		// =====================================================

		for addr, bal := range balances {

			if !IsValidEXPLOAddress(addr) {
				return errors.New(
					"attempt to persist balance for invalid address",
				)
			}

			if bal == nil {
				return errors.New(
					"nil balance",
				)
			}

			if err := l.putObjectTxn(
				txn,
				[]byte("balance:"+addr),
				bal,
			); err != nil {
				return fmt.Errorf(
					"failed to persist balance %s: %w",
					addr,
					err,
				)
			}
		}

		// =====================================================
		// 5.8 Fee -> IMANI FUND
		// =====================================================

		if tx.FeePastabo > 0 {

			if tx.IsReward {
				return errors.New(
					"reward cannot generate transaction fee",
				)
			}

			if err := l.addToIMANIPoolTxn(
				txn,
				tx.FeePastabo,
			); err != nil {
				return fmt.Errorf(
					"failed to add fee to IMANI pool: %w",
					err,
				)
			}
		}

		// =====================================================
		// 5.9 Persist transaction and indexes
		// =====================================================

		if err := l.persistTransactionIndexes(
			txn,
			tx,
		); err != nil {
			return fmt.Errorf(
				"failed to persist transaction indexes: %w",
				err,
			)
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	return confirmation, nil
}

// ============================================================
// Total issued supply
// ============================================================

func (l *Ledger) getTotalIssuedTxn(
	txn *badger.Txn,
) (uint64, error) {

	key := []byte("meta:total_issued")

	item, err := txn.Get(key)

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return 0, nil
		}

		return 0, err
	}

	var value uint64

	err = item.Value(func(v []byte) error {

		if len(v) != 8 {
			return errors.New(
				"corrupted total issued value",
			)
		}

		value = binary.BigEndian.Uint64(v)

		return nil
	})

	return value, err
}

// ============================================================
// Miner lookup
// ============================================================

func (l *Ledger) GetMiner(addr string) (*MinerInfo, error) {

	if l == nil {
		return nil, errors.New("nil ledger")
	}

	if !IsValidEXPLOAddress(addr) {
		return nil, errors.New("invalid miner address")
	}

	key := make([]byte, 0, len(PrefixMiner)+len(addr))
	key = append(key, PrefixMiner...)
	key = append(key, addr...)

	m := &MinerInfo{}

	err := l.GetObject(
		key,
		m,
	)

	if err != nil {
		return nil, err
	}

	if m.MinerID != addr {
		return nil, errors.New(
			"miner identity mismatch",
		)
	}

	if err := validatePublicKey(m.PublicKey); err != nil {
		return nil, err
	}

	derived := address.GenerateEXPLOAddress(
		ed25519.PublicKey(m.PublicKey),
	)

	if derived != addr {
		return nil, errors.New(
			"miner public key does not match address",
		)
	}

	return m, nil
}

// ============================================================
// Public key parsing
// ============================================================

func parsePubKey(hexStr string) ed25519.PublicKey {

	if len(hexStr) != ed25519.PublicKeySize*2 {
		log.Printf(
			"[ledger] invalid public key hex length",
		)
		return nil
	}

	b, err := hex.DecodeString(hexStr)

	if err != nil {
		log.Printf(
			"[ledger] parsePubKey failed: %v",
			err,
		)
		return nil
	}

	if len(b) != ed25519.PublicKeySize {
		return nil
	}

	return ed25519.PublicKey(b)
}

// ============================================================
// Legacy AddTransaction
// ============================================================
//
// The old implementation allowed unsigned monetary transactions.
//
// That path is intentionally disabled.
//
// All real EXPLO transfers must use a signed Transaction.
//
// ============================================================

func (l *Ledger) AddTransaction(
	tx imanifund.TransactionLite,
) error {

	_ = l
	_ = tx

	return errors.New(
		"AddTransaction is disabled: unsigned EXPLO transactions are forbidden",
	)
}

// ============================================================
// IMANI FUND
// ============================================================

func (l *Ledger) addToIMANIPoolTxn(
	txn *badger.Txn,
	amountPastabo uint64,
) error {

	if amountPastabo == 0 {
		return nil
	}

	key := []byte("meta:imani_pool")

	var current uint64

	item, err := txn.Get(key)

	if err == nil {

		err = item.Value(func(v []byte) error {

			if len(v) != 8 {
				return errors.New(
					"corrupted IMANI pool value",
				)
			}

			current = binary.BigEndian.Uint64(v)

			return nil
		})

		if err != nil {
			return err
		}

	} else if err != badger.ErrKeyNotFound {
		return err
	}

	newPool, err := safeAddUint64(
		current,
		amountPastabo,
	)

	if err != nil {
		return errors.New(
			"IMANI pool overflow",
		)
	}

	buf := make([]byte, 8)

	binary.BigEndian.PutUint64(
		buf,
		newPool,
	)

	return txn.Set(
		key,
		buf,
	)
}

// ============================================================
// Badger helpers
// ============================================================

func (l *Ledger) getObjectTxn(
	txn *badger.Txn,
	key []byte,
	obj interface{},
) error {

	item, err := txn.Get(key)

	if err != nil {
		return err
	}

	return item.Value(func(val []byte) error {

		if len(val) == 0 {
			return errors.New(
				"empty database object",
			)
		}

		if len(val) > MaxTransactionCBORBytes {
			return errors.New(
				"database object too large",
			)
		}

		return cbor.Unmarshal(
			val,
			obj,
		)
	})
}

func (l *Ledger) putObjectTxn(
	txn *badger.Txn,
	key []byte,
	obj interface{},
) error {

	data, err := cbor.Marshal(obj)

	if err != nil {
		return err
	}

	if len(data) > MaxTransactionCBORBytes {
		return errors.New(
			"serialized object too large",
		)
	}

	return txn.Set(
		key,
		data,
	)
}

// ============================================================
// Transaction indexes
// ============================================================

func (l *Ledger) persistTransactionIndexes(
	txn *badger.Txn,
	tx *Transaction,
) error {

	if tx == nil {
		return errors.New("nil transaction")
	}

	if tx.TxHash == "" {
		return errors.New("empty transaction hash")
	}

	txData, err := cbor.Marshal(tx)
	if err != nil {
		return err
	}

	if len(txData) > MaxTransactionCBORBytes {
		return errors.New(
			"transaction CBOR exceeds maximum size",
		)
	}

	// Primary transaction storage.
	if err := txn.Set(
		[]byte("tx:"+tx.TxHash),
		txData,
	); err != nil {
		return err
	}

	// Sender index.
	if tx.From != "" {

		if tx.From != "SYSTEM" &&
			!IsValidEXPLOAddress(tx.From) {
			return errors.New(
				"invalid sender index address",
			)
		}

		if err := txn.Set(
			[]byte("txby:"+tx.From+":"+tx.TxHash),
			nil,
		); err != nil {
			return err
		}
	}

	// Receiver index.
	if tx.To != "" {

		// System destinations are valid non-wallet receivers.
		isSystemReceiver := tx.To == "IMANI_POOL"

		if !isSystemReceiver &&
			!IsValidEXPLOAddress(tx.To) {
			return errors.New(
				"invalid receiver index address",
			)
		}

		if err := txn.Set(
			[]byte("txby:"+tx.To+":"+tx.TxHash),
			nil,
		); err != nil {
			return err
		}
	}

	return nil
}

// ============================================================
// Transaction history
// ============================================================

func (l *Ledger) GetTransactionsByAddress(
	addr string,
	page,
	pageSize int,
) ([]*Transaction, error) {

	if l == nil {
		return nil, errors.New("nil ledger")
	}

	if !IsValidEXPLOAddress(addr) {
		return nil, errors.New(
			"invalid EXPLO address",
		)
	}

	if page < 1 {
		page = 1
	}

	if pageSize <= 0 {
		pageSize = 50
	}

	if pageSize > MaxTransactionPageSize {
		pageSize = MaxTransactionPageSize
	}

	// Overflow-safe pagination.
	if page > math.MaxInt/pageSize {
		return nil, errors.New(
			"pagination overflow",
		)
	}

	startIndex := (page - 1) * pageSize

	if startIndex < 0 {
		return nil, errors.New(
			"invalid pagination",
		)
	}

	endIndex := startIndex + pageSize

	if endIndex < startIndex {
		return nil, errors.New(
			"pagination overflow",
		)
	}

	db := l.DB()

	if db == nil {
		return nil, errors.New(
			"ledger DB is nil",
		)
	}

	prefix := []byte(
		"txby:" + addr + ":",
	)

	var txs []*Transaction

	count := 0

	err := db.View(func(txn *badger.Txn) error {

		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {

			if count >= endIndex {
				break
			}

			if count < startIndex {
				count++
				continue
			}

			keyCopy := append(
				[]byte(nil),
				it.Item().Key()...,
			)

			hashStart := len(prefix)

			if len(keyCopy) <= hashStart {
				count++
				continue
			}

			txHash := string(
				keyCopy[hashStart:],
			)

			if txHash == "" {
				count++
				continue
			}

			txItem, err := txn.Get(
				[]byte("tx:" + txHash),
			)

			if err != nil {
				if err == badger.ErrKeyNotFound {
					count++
					continue
				}

				return err
			}

			val, err := txItem.ValueCopy(nil)

			if err != nil {
				return err
			}

			tx, err := DecodeTxCBOR(val)

			if err != nil {
				return err
			}

			txs = append(
				txs,
				tx,
			)

			count++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return txs, nil
}

// ============================================================
// Stored transaction validation
// ============================================================

func validateStoredTransaction(
	tx *Transaction,
) error {

	if tx == nil {
		return errors.New(
			"nil stored transaction",
		)
	}

	if err := validateTransactionStructure(tx); err != nil {
		return err
	}

	expectedHash := tx.ComputeHash()

	if expectedHash == "" ||
		expectedHash != tx.TxHash {
		return errors.New(
			"stored transaction hash mismatch",
		)
	}

	if tx.ID != "" &&
		tx.ID != tx.TxHash {
		return errors.New(
			"stored transaction ID mismatch",
		)
	}

	return nil
}

// ============================================================
// CBOR decoding
// ============================================================

func DecodeTxCBOR(
	data []byte,
) (*Transaction, error) {

	if len(data) == 0 {
		return nil, errors.New(
			"empty transaction data",
		)
	}

	if len(data) > MaxTransactionCBORBytes {
		return nil, errors.New(
			"transaction data too large",
		)
	}

	var tx Transaction

	if err := cbor.Unmarshal(
		data,
		&tx,
	); err != nil {
		return nil, fmt.Errorf(
			"cbor unmarshal failed: %w",
			err,
		)
	}

	if err := validateStoredTransaction(
		&tx,
	); err != nil {
		return nil, err
	}

	return &tx, nil
}

// ============================================================
// Logging helpers
// ============================================================

func safeShort(s string) string {

	if len(s) <= 12 {
		return s
	}

	return s[:12]
}
