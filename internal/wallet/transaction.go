// internal/wallet/transaction.go
package wallet

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"

	"explosive/internal/address"
	"explosive/internal/encryption"
	"explosive/internal/ledger"
	"explosive/internal/p2p"
)

// ============================================================
// EXPLOSIVE WALLET TRANSACTION SECURITY MODULE
// ============================================================
//
// SECURITY PRINCIPLES:
//
// 1. The wallet is NOT a monetary authority.
// 2. The ledger is the only authority for balances and supply.
// 3. The wallet NEVER creates EXPLO or IMANI.
// 4. The wallet NEVER writes consensus balances directly.
// 5. The wallet NEVER broadcasts client-controlled balances.
// 6. Pastabo is authoritative at consensus level.
// 7. Wallet float values are display/UX values only.
// 8. Every spend must be signed by the wallet key.
// 9. Sender address must match the signing public key.
// 10. Nonces are anti-replay values enforced by the ledger.
// 11. Private key material is zeroed after use.
// 12. P2P peers are never trusted for wallet balances.
// 13. Wallet transaction history is local/UI data only.
// 14. Transaction fees are consensus-defined.
// 15. No wallet function may mint, burn or arbitrarily credit funds.
// ============================================================

const (
	// Consensus wallet fee.
	//
	// 0.01 EXPLO = 10,000,000 Pastabo.
	DefaultEXPLOFee float64 = 0.01

	// Maximum local transaction note size.
	MaxTransactionNoteBytes = 1024

	// Maximum wallet-local transaction history entries.
	MaxWalletHistoryEntries = 10000

	// Maximum EXPLO amount accepted by the wallet UI layer.
	//
	// Consensus supply is controlled by the ledger.
	MaxWalletEXPLOAmount float64 = 50000000.0
)

// ============================================================
// WALLET TRANSACTION TYPES
// ============================================================

// TransactionType defines wallet/UI transaction classifications.
//
// These are NOT blockchain consensus transaction types.
type TransactionType string

const (
	TxSend    TransactionType = "SEND"
	TxReceive TransactionType = "RECEIVE"
	TxCredit  TransactionType = "CREDIT"
	TxDebit   TransactionType = "DEBIT"
	TxBlocked TransactionType = "BLOCKED"
)

// ============================================================
// WALLET LOCAL TRANSACTION
// ============================================================

// Transaction is a wallet-local/UI transaction record.
//
// IMPORTANT:
//
// This structure is NOT the authoritative blockchain transaction.
// Consensus state belongs to ledger.Transaction.
type Transaction struct {
	Timestamp time.Time       `cbor:"timestamp"`
	Type      TransactionType `cbor:"type"`
	AmountEXP float64         `cbor:"amount_exp"`
	AmountIM  float64         `cbor:"amount_imani"`
	From      string          `cbor:"from"`
	To        string          `cbor:"to"`
	Note      string          `cbor:"note,omitempty"`
}

// TxRecord is an export-friendly representation.
type TxRecord struct {
	Timestamp string  `json:"timestamp"`
	Type      string  `json:"type"`
	From      string  `json:"from"`
	To        string  `json:"to"`
	AmountEXP float64 `json:"amount_exp"`
	AmountIM  float64 `json:"amount_im"`
	Note      string  `json:"note"`
}

// ============================================================
// ADDRESS VALIDATION
// ============================================================

// ValidateEXPLOAddress is the wallet-level address validator.
//
// internal/address is the single source of truth.
func ValidateEXPLOAddress(addr string) bool {
	return address.IsValidEXPLOAddress(addr)
}

// IsValidEXPLOAddress is retained for compatibility.
func IsValidEXPLOAddress(addr string) bool {
	return ValidateEXPLOAddress(addr)
}

// validateTransactionAddresses validates sender and recipient.
func validateTransactionAddresses(from, to string) error {
	if !ValidateEXPLOAddress(from) {
		return errors.New("invalid sender EXPLO address")
	}

	if !ValidateEXPLOAddress(to) {
		return errors.New("invalid recipient EXPLO address")
	}

	if from == to {
		return errors.New("sender and recipient cannot be identical")
	}

	return nil
}

// ============================================================
// CONSENSUS BALANCE PROTECTION
// ============================================================
//
// Wallet code MUST NOT directly mutate:
//
//     balance:<address>
//
// Only the ledger may modify consensus balances.
//

// SetBalance is retained for source compatibility.
//
// Direct wallet-side balance mutation is forbidden.
func SetBalance(l *ledger.Ledger, addr string, bal WalletBalance) error {
	_ = l
	_ = addr
	_ = bal

	return errors.New(
		"wallet balance mutation is forbidden: balances are ledger-controlled",
	)
}

// ============================================================
// WALLET LOCAL HISTORY
// ============================================================

// SaveTransaction stores a local wallet/UI transaction.
//
// It does NOT modify blockchain balances.
func SaveTransaction(l *ledger.Ledger, tx Transaction) error {
	if l == nil {
		return errors.New("nil ledger")
	}

	if err := validateLocalTransaction(tx); err != nil {
		return err
	}

	// Use a cryptographic local digest for collision resistance.
	raw := fmt.Sprintf(
		"%d|%s|%s|%s|%.9f|%.9f|%s",
		tx.Timestamp.UnixNano(),
		tx.Type,
		tx.From,
		tx.To,
		tx.AmountEXP,
		tx.AmountIM,
		tx.Note,
	)

	digest := sha3.Sum256([]byte(raw))

	key := fmt.Sprintf(
		"wtx:%d:%s:%s:%x",
		tx.Timestamp.UnixNano(),
		tx.From,
		tx.To,
		digest[:8],
	)

	return l.PutObject([]byte(key), tx)
}

// simpleLocalDigest is retained for compatibility.
//
// It is NOT a consensus hash and MUST NOT be used for signatures.
func simpleLocalDigest(data []byte) []byte {
	hash := sha3.Sum256(data)

	result := make([]byte, len(hash))
	copy(result, hash[:])

	return result
}

// ============================================================
// AUTHORITATIVE BALANCE READ
// ============================================================

// GetBalance reads the authoritative ledger balance.
//
// This function is strictly READ-ONLY.
func GetBalance(l *ledger.Ledger, addr string) (WalletBalance, error) {
	if l == nil {
		return WalletBalance{}, errors.New("nil ledger")
	}

	if !ValidateEXPLOAddress(addr) {
		return WalletBalance{}, errors.New("invalid EXPLO address")
	}

	var bal WalletBalance

	err := l.GetObject([]byte("balance:"+addr), &bal)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return WalletBalance{
				EXPLO: 0,
				IMANI: 0,
			}, nil
		}

		return WalletBalance{}, err
	}

	if !validWalletAmount(bal.EXPLO) {
		return WalletBalance{}, errors.New(
			"ledger returned invalid EXPLO balance",
		)
	}

	if !validWalletAmount(bal.IMANI) {
		return WalletBalance{}, errors.New(
			"ledger returned invalid IMANI balance",
		)
	}

	return bal, nil
}

// ============================================================
// AMOUNT VALIDATION
// ============================================================

// validWalletAmount validates a UI-level amount.
//
// This is NOT consensus validation.
func validWalletAmount(amount float64) bool {
	return !math.IsNaN(amount) &&
		!math.IsInf(amount, 0) &&
		amount >= 0 &&
		amount <= MaxWalletEXPLOAmount
}

// validateSpendAmount validates a positive EXPLO spend.
func validateSpendAmount(amount float64) error {
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return errors.New("amount must be finite")
	}

	if amount <= 0 {
		return errors.New("amount must be positive")
	}

	if amount > MaxWalletEXPLOAmount {
		return errors.New("amount exceeds wallet maximum")
	}

	return nil
}

// ============================================================
// EXACT PASTABO CONVERSION
// ============================================================
//
// Wallet UI values may remain float64 for compatibility.
//
// Consensus monetary values use uint64 Pastabo.
//
// Conversion is accepted only when the value can be represented
// at 1e-9 EXPLO precision.
//

func exploToPastabo(amount float64) (uint64, error) {
	if err := validateSpendAmount(amount); err != nil {
		return 0, err
	}

	scaled := amount * float64(ledger.PastaboPerEXPLO)

	if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
		return 0, errors.New("amount overflow")
	}

	if scaled < 1 {
		return 0, errors.New("amount is below one Pastabo")
	}

	rounded := math.Round(scaled)

	if rounded < 1 {
		return 0, errors.New("amount rounds below one Pastabo")
	}

	if rounded > float64(math.MaxUint64) {
		return 0, errors.New("Pastabo amount overflow")
	}

	// Reject values that cannot be represented at Pastabo precision.
	if math.Abs(scaled-rounded) > 0.000001 {
		return 0, errors.New(
			"amount exceeds Pastabo precision",
		)
	}

	return uint64(rounded), nil
}

// exploToPastaboAllowZero converts a non-negative display value.
func exploToPastaboAllowZero(amount float64) (uint64, error) {
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return 0, errors.New("amount must be finite")
	}

	if amount < 0 || amount > MaxWalletEXPLOAmount {
		return 0, errors.New("invalid EXPLO amount")
	}

	if amount == 0 {
		return 0, nil
	}

	scaled := amount * float64(ledger.PastaboPerEXPLO)

	if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
		return 0, errors.New("amount overflow")
	}

	rounded := math.Round(scaled)

	if rounded < 0 || rounded > float64(math.MaxUint64) {
		return 0, errors.New("Pastabo amount overflow")
	}

	if math.Abs(scaled-rounded) > 0.000001 {
		return 0, errors.New(
			"amount exceeds Pastabo precision",
		)
	}

	return uint64(rounded), nil
}

// ============================================================
// NONCE MANAGEMENT
// ============================================================
//
// The local mutex prevents concurrent sends in the same process
// from selecting the same nonce simultaneously.
//
// The ledger remains the final nonce authority.
//

var nonceLocks sync.Map

func getNonceLock(addr string) *sync.Mutex {
	value, _ := nonceLocks.LoadOrStore(
		addr,
		&sync.Mutex{},
	)

	return value.(*sync.Mutex)
}

// getNextLocalNonce obtains the next candidate nonce.
//
// This does NOT confirm transaction acceptance.
func getNextLocalNonce(
	l *ledger.Ledger,
	addr string,
) (int64, error) {

	if l == nil {
		return 0, errors.New("nil ledger")
	}

	if !ValidateEXPLOAddress(addr) {
		return 0, errors.New("invalid EXPLO address")
	}

	var currentNonce int64

	err := l.GetObject(
		[]byte("nonce:"+addr),
		&currentNonce,
	)

	if err != nil &&
		!errors.Is(err, badger.ErrKeyNotFound) {
		return 0, err
	}

	if currentNonce < 0 {
		return 0, errors.New("invalid negative nonce")
	}

	if currentNonce == math.MaxInt64 {
		return 0, errors.New("nonce exhausted")
	}

	return currentNonce + 1, nil
}

// ============================================================
// SEND EXPLO
// ============================================================

// SendEXPLO creates, signs and broadcasts an EXPLO transaction.
//
// The wallet:
//
// - validates the sender;
// - validates the recipient;
// - validates wallet identity;
// - reads the authoritative balance;
// - converts the amount to Pastabo;
// - applies the consensus fee;
// - obtains a candidate nonce;
// - signs the transaction;
// - broadcasts the signed transaction;
// - never modifies consensus balances.
//
// The wallet does NOT confirm its own payment.
func SendEXPLO(
	l *ledger.Ledger,
	from string,
	to string,
	amount float64,
	w *Wallet,
	password string,
) error {

	if l == nil {
		return errors.New("nil ledger")
	}

	if w == nil {
		return errors.New("nil wallet")
	}

	if err := validateTransactionAddresses(from, to); err != nil {
		return err
	}

	if err := validateSpendAmount(amount); err != nil {
		return err
	}

	if w.Address != from {
		return errors.New(
			"wallet identity does not match sender address",
		)
	}

	if err := w.IsValid(); err != nil {
		return fmt.Errorf(
			"invalid wallet: %w",
			err,
		)
	}

	amountPastabo, err := exploToPastabo(amount)
	if err != nil {
		return fmt.Errorf(
			"invalid EXPLO amount: %w",
			err,
		)
	}

	// The ledger defines the authoritative fee.
	feePastabo := uint64(ledger.DefaultFeePastabo)

	// Verify that the wallet's UX fee remains synchronized
	// with consensus.
	expectedFee := uint64(
		DefaultEXPLOFee *
			float64(ledger.PastaboPerEXPLO),
	)

	if feePastabo != expectedFee {
		return errors.New(
			"wallet fee configuration does not match ledger consensus fee",
		)
	}

	if amountPastabo >
		math.MaxUint64-feePastabo {

		return errors.New(
			"total transaction amount overflow",
		)
	}

	requiredPastabo := amountPastabo + feePastabo

	// Read authoritative balance.
	fromBal, err := GetBalance(l, from)
	if err != nil {
		return fmt.Errorf(
			"failed to read sender balance: %w",
			err,
		)
	}

	balancePastabo, err :=
		exploToPastaboAllowZero(fromBal.EXPLO)

	if err != nil {
		return fmt.Errorf(
			"invalid authoritative EXPLO balance: %w",
			err,
		)
	}

	if balancePastabo < requiredPastabo {
		return errors.New(
			"insufficient EXPLO balance including network fee",
		)
	}

	// Serialize nonce selection for this sender.
	lock := getNonceLock(from)

	lock.Lock()
	defer lock.Unlock()

	nonce, err := getNextLocalNonce(l, from)
	if err != nil {
		return fmt.Errorf(
			"failed to obtain transaction nonce: %w",
			err,
		)
	}

	tx := Transaction{
		Timestamp: time.Now().UTC(),
		Type:      TxSend,
		AmountEXP: amount,
		AmountIM:  0,
		From:      from,
		To:        to,
		Note: fmt.Sprintf(
			"EXPLO transfer - fee %.9f EXPLO - nonce %d",
			DefaultEXPLOFee,
			nonce,
		),
	}

	if err := validateLocalTransaction(tx); err != nil {
		return err
	}

	if err := broadcastTxSignedWithNonce(
		tx,
		w,
		password,
		nonce,
	); err != nil {
		return fmt.Errorf(
			"transaction broadcast failed: %w",
			err,
		)
	}

	// NEVER modify balance:<address> here.
	//
	// The ledger is responsible for:
	//
	// - validating the signature;
	// - validating the nonce;
	// - checking the balance;
	// - subtracting the amount;
	// - charging the fee;
	// - crediting the recipient;
	// - persisting the consensus transaction.

	if err := SaveTransaction(l, tx); err != nil {
		log.Printf(
			"[wallet] warning: transaction broadcasted but local history save failed: %v",
			err,
		)
	}

	log.Printf(
		"[wallet] transaction submitted from=%s to=%s nonce=%d amount=%d fee=%d",
		from,
		to,
		nonce,
		amountPastabo,
		feePastabo,
	)

	return nil
}

// ============================================================
// LEDGER TRANSACTION CONVERSION + SIGNING
// ============================================================

// ToLedgerTransactionWithSignature converts a wallet transaction
// into a fully populated signed ledger transaction.
func (tx *Transaction) ToLedgerTransactionWithSignature(
	w *Wallet,
	password string,
	nonce int64,
) (*ledger.Transaction, error) {

	if tx == nil {
		return nil, errors.New("nil wallet transaction")
	}

	if w == nil {
		return nil, errors.New("nil wallet")
	}

	if nonce <= 0 {
		return nil, errors.New("nonce must be positive")
	}

	if err := validateLocalTransaction(*tx); err != nil {
		return nil, err
	}

	if tx.Type != TxSend {
		return nil, errors.New(
			"only SEND transactions can be converted to ledger transactions",
		)
	}

	if !ValidateEXPLOAddress(tx.From) {
		return nil, errors.New("invalid sender address")
	}

	if !ValidateEXPLOAddress(tx.To) {
		return nil, errors.New("invalid recipient address")
	}

	if w.Address != tx.From {
		return nil, errors.New(
			"wallet address does not match transaction sender",
		)
	}

	if err := w.IsValid(); err != nil {
		return nil, fmt.Errorf(
			"invalid wallet: %w",
			err,
		)
	}

	// Convert the display amount to exact consensus units.
	amountPastabo, err := exploToPastabo(tx.AmountEXP)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid transaction amount: %w",
			err,
		)
	}

	// Consensus fee.
	feePastabo := uint64(ledger.DefaultFeePastabo)

	expectedFee := uint64(
		DefaultEXPLOFee *
			float64(ledger.PastaboPerEXPLO),
	)

	if feePastabo != expectedFee {
		return nil, errors.New(
			"wallet fee does not match ledger consensus fee",
		)
	}

	timestamp := tx.Timestamp.UnixMilli()

	if timestamp <= 0 {
		return nil, errors.New(
			"invalid transaction timestamp",
		)
	}

	// ========================================================
	// BUILD CONSENSUS TRANSACTION
	// ========================================================
	//
	// IMPORTANT:
	//
	// Pastabo fields are the authoritative monetary fields.
	//
	// AmountEXP / Fee are compatibility/display fields.
	//

	ltx := &ledger.Transaction{
		From: tx.From,
		To:   tx.To,

		AmountPastabo:   amountPastabo,
		AmountIMPastabo: 0,
		FeePastabo:      feePastabo,

		// Compatibility/display fields.
		AmountEXP: tx.AmountEXP,
		AmountIM:  0,
		Fee:       DefaultEXPLOFee,

		Timestamp: timestamp,
		Nonce:     nonce,

		Note: tx.Note,

		IsReward:      false,
		IsIMANILocked: false,
	}

	// ========================================================
	// DECRYPT PRIVATE KEY
	// ========================================================

	privBytes, _, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		password,
	)
	if err != nil {
		return nil, errors.New(
			"failed to decrypt wallet signing key",
		)
	}

	// zeroBytes is defined once in wallet/encryption.go.
	defer zeroBytes(privBytes)

	// Accept either legacy seed material or complete Ed25519
	// private-key material.
	var priv ed25519.PrivateKey

	switch len(privBytes) {
	case ed25519.SeedSize:

		priv = ed25519.NewKeyFromSeed(
			privBytes,
		)

	case ed25519.PrivateKeySize:

		priv = make(
			ed25519.PrivateKey,
			ed25519.PrivateKeySize,
		)

		copy(priv, privBytes)

	default:

		return nil, fmt.Errorf(
			"invalid private key length: %d",
			len(privBytes),
		)
	}

	defer zeroBytes(priv)

	// ========================================================
	// DERIVE PUBLIC KEY
	// ========================================================

	rawPub := priv.Public().(ed25519.PublicKey)

	pub := make(
		ed25519.PublicKey,
		ed25519.PublicKeySize,
	)

	copy(pub, rawPub)

	// ========================================================
	// VERIFY ADDRESS BINDING
	// ========================================================

	derivedAddress :=
		address.GenerateEXPLOAddress(pub)

	if !strings.EqualFold(
		derivedAddress,
		tx.From,
	) {
		zeroBytes(pub)

		return nil, errors.New(
			"signing key does not correspond to transaction sender address",
		)
	}

	// ========================================================
	// VERIFY WALLET PUBLIC IDENTITY
	// ========================================================

	storedPub, err := w.PublicKeyBytes("")
	if err != nil {
		zeroBytes(pub)

		return nil, fmt.Errorf(
			"failed to read wallet public key: %w",
			err,
		)
	}

	if len(storedPub) != ed25519.PublicKeySize {
		zeroBytes(pub)
		zeroBytes(storedPub)

		return nil, errors.New(
			"wallet contains invalid public key",
		)
	}

	if !ed25519.PublicKey(storedPub).Equal(pub) {
		zeroBytes(pub)
		zeroBytes(storedPub)

		return nil, errors.New(
			"wallet public identity does not match signing private key",
		)
	}

	zeroBytes(storedPub)

	// ========================================================
	// SIGN CANONICAL LEDGER PAYLOAD
	// ========================================================

	signBytes := ltx.HashForSignature()

	if len(signBytes) == 0 {
		zeroBytes(pub)

		return nil, errors.New(
			"empty transaction signing payload",
		)
	}

	sig := ed25519.Sign(
		priv,
		signBytes,
	)

	if len(sig) != ed25519.SignatureSize {
		zeroBytes(pub)

		return nil, errors.New(
			"invalid generated signature",
		)
	}

	// Store independent public-key material.
	ltx.FromPubKey = append(
		[]byte(nil),
		pub...,
	)

	// Store independent signature material.
	ltx.Signature = append(
		[]byte(nil),
		sig...,
	)

	zeroBytes(pub)

	// ========================================================
	// FINAL TRANSACTION HASH
	// ========================================================

	ltx.TxHash = ltx.ComputeHash()

	if ltx.TxHash == "" {
		return nil, errors.New(
			"failed to compute transaction hash",
		)
	}

	// Legacy compatibility field.
	//
	// TxHash is the real transaction identity.
	ltx.ID = ltx.TxHash

	log.Printf(
		"[wallet] transaction signed: from=%s to=%s nonce=%d tx=%s",
		tx.From,
		tx.To,
		nonce,
		shortHash(ltx.TxHash),
	)

	return ltx, nil
}

// ============================================================
// HASH DISPLAY
// ============================================================

// shortHash safely shortens a hash for logs.
func shortHash(hash string) string {
	if len(hash) <= 16 {
		return hash
	}

	return hash[:16]
}

// ============================================================
// LOCAL TRANSACTION VALIDATION
// ============================================================

func validateLocalTransaction(tx Transaction) error {
	if tx.Timestamp.IsZero() {
		return errors.New(
			"transaction timestamp is required",
		)
	}

	now := time.Now()

	if tx.Timestamp.After(
		now.Add(5 * time.Minute),
	) {
		return errors.New(
			"transaction timestamp is too far in the future",
		)
	}

	if tx.Timestamp.Before(
		now.Add(-24 * time.Hour),
	) {
		return errors.New(
			"transaction timestamp is too old",
		)
	}

	if !ValidateEXPLOAddress(tx.From) &&
		tx.From != "SYSTEM" {
		return errors.New(
			"invalid transaction sender",
		)
	}

	if !ValidateEXPLOAddress(tx.To) {
		return errors.New(
			"invalid transaction recipient",
		)
	}

	if tx.From != "SYSTEM" &&
		tx.From == tx.To {
		return errors.New(
			"sender and recipient cannot be identical",
		)
	}

	if !validWalletAmount(tx.AmountEXP) {
		return errors.New(
			"invalid EXPLO amount",
		)
	}

	if !validWalletAmount(tx.AmountIM) {
		return errors.New(
			"invalid IMANI amount",
		)
	}

	if len(tx.Note) > MaxTransactionNoteBytes {
		return errors.New(
			"transaction note too large",
		)
	}

	switch tx.Type {
	case TxSend,
		TxReceive,
		TxCredit,
		TxDebit,
		TxBlocked:

		// Valid local transaction type.

	default:

		return errors.New(
			"unsupported wallet transaction type",
		)
	}

	return nil
}

// ============================================================
// TRANSACTION HISTORY
// ============================================================

// GetTransactions retrieves wallet-local transaction history.
//
// It NEVER trusts network-supplied history.
func GetTransactions(
	l *ledger.Ledger,
	addr string,
) ([]Transaction, error) {

	if l == nil {
		return nil, errors.New("nil ledger")
	}

	if addr != "" &&
		!ValidateEXPLOAddress(addr) {
		return nil, errors.New(
			"invalid address filter",
		)
	}

	txs := make(
		[]Transaction,
		0,
	)

	prefix := []byte("wtx:")

	err := l.DB().View(
		func(txn *badger.Txn) error {

			opts := badger.DefaultIteratorOptions
			opts.PrefetchValues = true
			opts.Prefix = prefix

			it := txn.NewIterator(opts)
			defer it.Close()

			count := 0

			for it.Rewind(); it.Valid(); it.Next() {

				if count >= MaxWalletHistoryEntries {
					break
				}

				item := it.Item()

				value, err := item.ValueCopy(nil)
				if err != nil {
					return err
				}

				var tx Transaction

				if err := cbor.Unmarshal(
					value,
					&tx,
				); err != nil {

					log.Printf(
						"[wallet] skipping corrupted transaction record: %v",
						err,
					)

					continue
				}

				if err := validateLocalTransaction(tx); err != nil {

					log.Printf(
						"[wallet] skipping invalid transaction record: %v",
						err,
					)

					continue
				}

				if addr == "" ||
					tx.From == addr ||
					tx.To == addr {

					txs = append(
						txs,
						tx,
					)

					count++
				}
			}

			return nil
		},
	)

	return txs, err
}

// ============================================================
// CREDIT PROTECTION
// ============================================================
//
// Wallet code cannot manufacture balances.
//
// Mining rewards, genesis issuance, transfers and IMANI accounting
// must originate from ledger consensus.
//

// CreditWallet is retained for source compatibility but refuses
// arbitrary wallet-side monetary creation.
func CreditWallet(
	l *ledger.Ledger,
	addr string,
	expAmount float64,
	imaniAmount float64,
) error {

	_ = l
	_ = addr
	_ = expAmount
	_ = imaniAmount

	return errors.New(
		"wallet-side crediting is forbidden: use ledger consensus issuance",
	)
}

// ============================================================
// DISPLAY UTILITIES
// ============================================================

// DisplayTransactionHistory prints local wallet history.
func DisplayTransactionHistory(
	l *ledger.Ledger,
	addr string,
) error {

	if l == nil {
		return errors.New("nil ledger")
	}

	if addr != "" &&
		!ValidateEXPLOAddress(addr) {
		return errors.New(
			"invalid address",
		)
	}

	txs, err := GetTransactions(
		l,
		addr,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"=== TRANSACTION HISTORY ===",
	)

	for _, tx := range txs {

		fmt.Printf(
			"[%s] Type: %s | EXPLO: %.9f | IMANI: %.9f | From: %s | To: %s | Note: %s\n",
			tx.Timestamp.Format(time.RFC3339),
			tx.Type,
			tx.AmountEXP,
			tx.AmountIM,
			tx.From,
			tx.To,
			tx.Note,
		)
	}

	fmt.Println(
		"===========================",
	)

	return nil
}

// DisplayWalletBalance displays a read-only wallet balance.
func DisplayWalletBalance(
	bal WalletBalance,
) {
	fmt.Printf(
		"EXPLO: %.9f | IMANI: %.9f\n",
		bal.EXPLO,
		bal.IMANI,
	)
}

// ============================================================
// P2P INTEGRATION
// ============================================================

var activeNode *p2p.Node

var activeNodeMu sync.RWMutex

// SetActiveNode configures the active P2P transport.
//
// This does NOT grant the node authority over balances.
func SetActiveNode(node *p2p.Node) {
	activeNodeMu.Lock()
	defer activeNodeMu.Unlock()

	activeNode = node
}

func getActiveNode() *p2p.Node {
	activeNodeMu.RLock()
	defer activeNodeMu.RUnlock()

	return activeNode
}

// ============================================================
// SIGN + BROADCAST
// ============================================================

// broadcastTxSigned is retained for compatibility.
//
// It obtains a candidate nonce and broadcasts a signed transaction.
func broadcastTxSigned(
	l *ledger.Ledger,
	tx Transaction,
	w *Wallet,
	password string,
) {

	if l == nil {
		log.Printf(
			"[wallet] cannot broadcast: nil ledger",
		)

		return
	}

	if w == nil {
		log.Printf(
			"[wallet] cannot broadcast: nil wallet",
		)

		return
	}

	node := getActiveNode()

	if node == nil {
		log.Printf(
			"[wallet] no active P2P node connected - transaction not broadcast",
		)

		return
	}

	lock := getNonceLock(tx.From)

	lock.Lock()
	defer lock.Unlock()

	nonce, err := getNextLocalNonce(
		l,
		tx.From,
	)

	if err != nil {
		log.Printf(
			"[wallet] failed to obtain nonce: %v",
			err,
		)

		return
	}

	if err := broadcastSignedTransaction(
		node,
		tx,
		w,
		password,
		nonce,
	); err != nil {

		log.Printf(
			"[wallet] transaction broadcast failed: %v",
			err,
		)
	}
}

// broadcastTxSignedWithNonce broadcasts with an explicit nonce.
func broadcastTxSignedWithNonce(
	tx Transaction,
	w *Wallet,
	password string,
	nonce int64,
) error {

	node := getActiveNode()

	if node == nil {
		return errors.New(
			"no active P2P node - transaction not broadcasted",
		)
	}

	return broadcastSignedTransaction(
		node,
		tx,
		w,
		password,
		nonce,
	)
}

// broadcastSignedTransaction signs and broadcasts ONLY the signed
// consensus transaction.
//
// Never sends:
//
// - password
// - mnemonic
// - private key
// - wallet balance
// - local history
func broadcastSignedTransaction(
	node *p2p.Node,
	tx Transaction,
	w *Wallet,
	password string,
	nonce int64,
) error {

	if node == nil {
		return errors.New(
			"nil P2P node",
		)
	}

	ltx, err := tx.ToLedgerTransactionWithSignature(
		w,
		password,
		nonce,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to sign transaction: %w",
			err,
		)
	}

	if len(ltx.FromPubKey) != ed25519.PublicKeySize {
		return errors.New(
			"invalid transaction public key",
		)
	}

	if len(ltx.Signature) != ed25519.SignatureSize {
		return errors.New(
			"invalid transaction signature",
		)
	}

	if ltx.TxHash == "" {
		return errors.New(
			"transaction hash is empty",
		)
	}

	// Broadcast ONLY the signed transaction.
	if err := node.BroadcastTransaction(
		ltx,
	); err != nil {
		return fmt.Errorf(
			"failed to broadcast transaction: %w",
			err,
		)
	}

	log.Printf(
		"[wallet] signed transaction broadcasted: nonce=%d tx=%s",
		nonce,
		shortHash(ltx.TxHash),
	)

	return nil
}

// ============================================================
// CUSTOM P2P DATA
// ============================================================
//
// Custom messages must NEVER contain:
//
// - private keys
// - mnemonic phrases
// - passwords
// - client-controlled balances
// - arbitrary consensus state
//

// BroadcastCustom broadcasts a structured application message.
func BroadcastCustom(payload interface{}) error {

	node := getActiveNode()

	if node == nil {
		return errors.New(
			"no active P2P node connected",
		)
	}

	if payload == nil {
		return errors.New(
			"nil custom payload",
		)
	}

	env, err := p2p.NewEnvelopeFromPayload(
		node.ProtocolVersion(),
		p2p.MsgTypeCustomData,
		payload,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to encode custom payload: %w",
			err,
		)
	}

	node.BroadcastEnvelope(env)

	return nil
}

// ============================================================
// FORBIDDEN NETWORK STATE BROADCASTS
// ============================================================

// broadcastBalanceUpdate is deliberately disabled.
//
// Peers must never receive a client-declared balance.
func broadcastBalanceUpdate(
	addr string,
	bal WalletBalance,
) {
	_ = addr
	_ = bal

	log.Printf(
		"[wallet] blocked unsafe BALANCE_UPDATE broadcast",
	)
}

// broadcastLedgerSync is deliberately disabled.
//
// Wallet-local history is not blockchain consensus state.
func broadcastLedgerSync(
	l *ledger.Ledger,
) {
	_ = l

	log.Printf(
		"[wallet] blocked unsafe LEDGER_SYNC broadcast",
	)
}

// ============================================================
// DEBUG / SECURITY HELPERS
// ============================================================

// DebugTransactionSummary returns a safe transaction description.
//
// It intentionally excludes:
//
// - private key
// - mnemonic
// - password
func DebugTransactionSummary(
	tx *ledger.Transaction,
) string {

	if tx == nil {
		return "<nil transaction>"
	}

	return fmt.Sprintf(
		"tx=%s from=%s to=%s nonce=%d amount=%d fee=%d pubkey=%s signature=%s",
		shortHash(tx.TxHash),
		tx.From,
		tx.To,
		tx.Nonce,
		tx.AmountPastabo,
		tx.FeePastabo,
		safeHexPrefix(tx.FromPubKey),
		safeHexPrefix(tx.Signature),
	)
}

// safeHexPrefix safely displays only a small public-data prefix.
func safeHexPrefix(data []byte) string {

	if len(data) == 0 {
		return ""
	}

	encoded := hex.EncodeToString(data)

	if len(encoded) <= 16 {
		return encoded
	}

	return encoded[:16]
}
