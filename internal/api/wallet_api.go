package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	"explosive/internal/ledger"
	"explosive/internal/wallet"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	defaultEXPLOFee = 0.001

	maxJSONBodySize = 1 << 20 // 1 MiB

	maxTransactionsPageSize = 100
)

// -----------------------------------------------------------------------------
// Request / Response models
// -----------------------------------------------------------------------------

// CreateWalletRequest creates a new standard BIP-39 wallet.
type CreateWalletRequest struct {
	Password string `json:"password"`
}

// RestoreWalletRequest restores a wallet from a BIP-39 mnemonic.
type RestoreWalletRequest struct {
	Password string `json:"password"`
	Mnemonic string `json:"mnemonic"`
}

// SendRequest sends native EXPLO.
//
// The sender address is intentionally NOT accepted from the client.
// It is obtained from the authenticated session.
//
// Password is still required because the private key remains encrypted
// at rest and is never stored inside AuthDB.
type SendRequest struct {
	To       string  `json:"to"`
	Amount   float64 `json:"amount"`
	Password string  `json:"password"`
	Note     string  `json:"note,omitempty"`
}

// WalletBalanceResponse exposes authoritative blockchain balances.
//
// EXPLO and IMANI are read from the Ledger.
// LUMEN is deliberately absent because it is not a ledger token.
type WalletBalanceResponse struct {
	Address string  `json:"address"`
	EXPLO   float64 `json:"explo"`
	IMANI   float64 `json:"imani"`
}

// CreateWalletResponse is returned once after wallet creation.
//
// The mnemonic is returned to the client so the user can back it up.
// It is never stored in plaintext by the wallet.
type CreateWalletResponse struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Mnemonic string `json:"mnemonic"`
}

// RestoreWalletResponse confirms wallet restoration.
type RestoreWalletResponse struct {
	Address string `json:"address"`
}

// SendResponse is returned after the Ledger accepts the transaction.
type SendResponse struct {
	Success   bool    `json:"success"`
	TxHash    string  `json:"tx_hash"`
	From      string  `json:"from"`
	To        string  `json:"to"`
	AmountEXP float64 `json:"amount_explo"`
	FeeEXP    float64 `json:"fee_explo"`
	Nonce     int64   `json:"nonce"`
	Timestamp int64   `json:"timestamp"`
}

// TransactionResponse exposes authoritative Ledger transactions.
type TransactionResponse struct {
	ID            string  `json:"id,omitempty"`
	TxHash        string  `json:"tx_hash"`
	From          string  `json:"from"`
	To            string  `json:"to"`
	AmountEXP     float64 `json:"amount_explo"`
	AmountIM      float64 `json:"amount_imani"`
	Fee           float64 `json:"fee"`
	AmountPastabo uint64  `json:"amount_pastabo"`
	IMANIPastabo  uint64  `json:"amount_imani_pastabo"`
	FeePastabo    uint64  `json:"fee_pastabo"`
	Timestamp     int64   `json:"timestamp"`
	Nonce         int64   `json:"nonce"`
	Note          string  `json:"note,omitempty"`
	IsReward      bool    `json:"is_reward"`
	IsIMANILocked bool    `json:"is_imani_locked"`
}

// TransactionsResponse is the paginated transaction response.
type TransactionsResponse struct {
	Address      string                `json:"address"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
	Transactions []TransactionResponse `json:"transactions"`
}

// SimpleResponse is used for simple API responses.
type SimpleResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// -----------------------------------------------------------------------------
// Wallet API
// -----------------------------------------------------------------------------

type WalletAPI struct {
	// Blockchain source of truth.
	Ledger *ledger.Ledger

	// Encrypted wallet storage.
	Wallets *wallet.WalletDB

	// Wallet authentication/session service.
	Auth *AuthAPI

	// Prevents concurrent requests in this API process from selecting
	// the same nonce.
	nonceMu sync.Mutex
}

// NewWalletAPI creates the Wallet API.
//
// Authentication is attached separately with SetAuthAPI() so existing
// construction code remains compatible.
func NewWalletAPI(
	ldb *ledger.Ledger,
	wdb *wallet.WalletDB,
) *WalletAPI {
	return &WalletAPI{
		Ledger:  ldb,
		Wallets: wdb,
	}
}

// SetAuthAPI attaches the authentication service to the Wallet API.
func (api *WalletAPI) SetAuthAPI(authAPI *AuthAPI) {
	if api == nil {
		return
	}

	api.Auth = authAPI
}

// -----------------------------------------------------------------------------
// POST /api/wallet/create
// -----------------------------------------------------------------------------

func (api *WalletAPI) CreateWalletHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if api == nil || api.Wallets == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"wallet database unavailable",
		)
		return
	}

	var req CreateWalletRequest

	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	// Never trim passwords.
	if req.Password == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"password is required",
		)
		return
	}

	// Generate a real BIP-39 wallet.
	wlt, err := wallet.CreateWallet(req.Password)
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"wallet creation failed",
		)
		return
	}

	// The mnemonic is stored encrypted inside EncryptedPriv.
	// Reveal it only for this creation response.
	mnemonic, err := wlt.RevealMnemonic(req.Password)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to reveal wallet mnemonic",
		)
		return
	}

	// Save through the dedicated WalletDB.
	//
	// No plaintext mnemonic is stored.
	if err := api.Wallets.SaveWallet(wlt); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to save wallet",
		)
		return
	}

	// Never log the password or mnemonic.
	writeJSON(
		w,
		http.StatusCreated,
		CreateWalletResponse{
			Address:  wlt.Address,
			Mnemonic: mnemonic,
		},
	)
}

// -----------------------------------------------------------------------------
// POST /api/wallet/restore
// -----------------------------------------------------------------------------

func (api *WalletAPI) RestoreWalletHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if api == nil || api.Wallets == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"wallet database unavailable",
		)
		return
	}

	var req RestoreWalletRequest

	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	// Mnemonic whitespace is safe to normalize.
	req.Mnemonic = strings.TrimSpace(req.Mnemonic)

	// Never trim passwords.
	if req.Password == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"password is required",
		)
		return
	}

	if req.Mnemonic == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"mnemonic is required",
		)
		return
	}

	// Restore from the real BIP-39 mnemonic.
	wlt, err := wallet.RestoreWalletByMnemonic(
		req.Mnemonic,
		req.Password,
	)
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"wallet restoration failed",
		)
		return
	}

	if !ledger.IsValidEXPLOAddress(wlt.Address) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid restored wallet address",
		)
		return
	}

	// Save encrypted wallet.
	if err := api.Wallets.SaveWallet(wlt); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to save restored wallet",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		RestoreWalletResponse{
			Address: wlt.Address,
		},
	)
}

// -----------------------------------------------------------------------------
// GET /api/wallet/balance
// -----------------------------------------------------------------------------

func (api *WalletAPI) WalletBalanceHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	// Authenticate FIRST.
	addr, ok := api.authenticateWallet(w, r)
	if !ok {
		return
	}

	if api.Ledger == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"ledger unavailable",
		)
		return
	}

	// Do not trust a client-supplied address.
	//
	// If the client sends ?address=..., it must match the authenticated
	// wallet. This prevents accidental cross-wallet reads.
	requestedAddr := strings.TrimSpace(
		r.URL.Query().Get("address"),
	)

	if requestedAddr != "" && requestedAddr != addr {
		writeError(
			w,
			http.StatusForbidden,
			"wallet address does not match authenticated session",
		)
		return
	}

	balance, err := getLedgerBalance(
		api.Ledger,
		addr,
	)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to read wallet balance",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		WalletBalanceResponse{
			Address: addr,
			EXPLO:   pastaboToEXPLO(balance.EXPLO),
			IMANI:   pastaboToEXPLO(balance.IMANI),
		},
	)
}

// -----------------------------------------------------------------------------
// GET /api/wallet/address
// -----------------------------------------------------------------------------

func (api *WalletAPI) WalletAddressHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	// Authenticate FIRST.
	addr, ok := api.authenticateWallet(w, r)
	if !ok {
		return
	}

	// The authenticated session is the source of truth.
	requestedAddr := strings.TrimSpace(
		r.URL.Query().Get("address"),
	)

	if requestedAddr != "" && requestedAddr != addr {
		writeError(
			w,
			http.StatusForbidden,
			"wallet address does not match authenticated session",
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]string{
			"address": addr,
		},
	)
}

// -----------------------------------------------------------------------------
// POST /api/wallet/send
// -----------------------------------------------------------------------------

func (api *WalletAPI) SendHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	// -------------------------------------------------------------------------
	// Authenticate FIRST.
	//
	// IMPORTANT:
	//
	// The sender address comes from the authenticated session.
	// It is NEVER taken from the request body.
	// -------------------------------------------------------------------------

	from, ok := api.authenticateWallet(w, r)
	if !ok {
		return
	}

	if api.Ledger == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"ledger unavailable",
		)
		return
	}

	if api.Wallets == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"wallet database unavailable",
		)
		return
	}

	var req SendRequest

	if err := decodeJSONBody(w, r, &req); err != nil {
		return
	}

	req.To = strings.TrimSpace(req.To)
	req.Note = strings.TrimSpace(req.Note)

	if req.To == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"destination address is required",
		)
		return
	}

	// Password is required only to unlock the encrypted private key
	// for this signing operation.
	//
	// It is NOT stored in AuthDB.
	if req.Password == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"password is required",
		)
		return
	}

	if !ledger.IsValidEXPLOAddress(req.To) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid destination EXPLO address",
		)
		return
	}

	if from == req.To {
		writeError(
			w,
			http.StatusBadRequest,
			"sender and destination cannot be the same",
		)
		return
	}

	if math.IsNaN(req.Amount) ||
		math.IsInf(req.Amount, 0) ||
		req.Amount <= 0 {
		writeError(
			w,
			http.StatusBadRequest,
			"amount must be a positive finite number",
		)
		return
	}

	// -------------------------------------------------------------------------
	// Convert user EXPLO amount to consensus Pastabo.
	//
	// 1 EXPLO = 1,000,000,000 Pastabo.
	// -------------------------------------------------------------------------

	amountPastabo, err := exploToPastabo(req.Amount)
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid EXPLO amount",
		)
		return
	}

	feePastabo, err := exploToPastabo(defaultEXPLOFee)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"invalid network fee configuration",
		)
		return
	}

	// -------------------------------------------------------------------------
	// Load encrypted wallet.
	// -------------------------------------------------------------------------

	wlt, err := api.loadWallet(from)
	if err != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"wallet not available",
		)
		return
	}

	if wlt.Address != from {
		writeError(
			w,
			http.StatusUnauthorized,
			"wallet address mismatch",
		)
		return
	}

	// -------------------------------------------------------------------------
	// Nonce selection.
	//
	// The Ledger stores:
	//
	//     nonce:<address> -> 8 raw bytes, BigEndian
	//
	// The mutex prevents two concurrent requests in this API process
	// from selecting the same nonce.
	// -------------------------------------------------------------------------

	api.nonceMu.Lock()
	defer api.nonceMu.Unlock()

	nonce, err := getNextNonce(
		api.Ledger,
		from,
	)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to obtain transaction nonce",
		)
		return
	}

	timestamp := time.Now().UnixMilli()

	// -------------------------------------------------------------------------
	// Construct canonical ledger transaction.
	// -------------------------------------------------------------------------

	tx := &ledger.Transaction{
		From:          from,
		To:            req.To,
		AmountPastabo: amountPastabo,
		FeePastabo:    feePastabo,
		Timestamp:     timestamp,
		Nonce:         nonce,
		Note:          req.Note,
		IsReward:      false,
		IsIMANILocked: false,
	}

	tx.AmountEXP = pastaboToEXPLO(
		amountPastabo,
	)

	tx.Fee = pastaboToEXPLO(
		feePastabo,
	)

	// -------------------------------------------------------------------------
	// Sign the exact hash expected by the Ledger.
	// -------------------------------------------------------------------------

	signature, err := wallet.SignTransaction(
		wlt,
		req.Password,
		tx.HashForSignature(),
	)
	if err != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"invalid wallet password or signing failure",
		)
		return
	}

	pubKey, err := wlt.PublicKeyBytes(
		req.Password,
	)
	if err != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"failed to obtain wallet public key",
		)
		return
	}

	tx.FromPubKey = pubKey
	tx.Signature = signature

	// Compute canonical transaction hash.
	tx.TxHash = tx.ComputeHash()

	if tx.TxHash == "" {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to compute transaction hash",
		)
		return
	}

	// -------------------------------------------------------------------------
	// AUTHORITATIVE LEDGER OPERATION
	//
	// We deliberately do NOT:
	//
	//   - manually modify balances
	//   - manually write the nonce
	//   - call wallet.SendEXPLO()
	//   - store a second copy in WalletDB
	//
	// The Ledger validates and persists the transaction atomically.
	// -------------------------------------------------------------------------

	txHash, err := api.Ledger.ApplyAndPersistTransaction(tx)
	if err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			sanitizeLedgerError(err),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		SendResponse{
			Success:   true,
			TxHash:    txHash,
			From:      tx.From,
			To:        tx.To,
			AmountEXP: tx.AmountEXP,
			FeeEXP:    tx.Fee,
			Nonce:     tx.Nonce,
			Timestamp: tx.Timestamp,
		},
	)
}

// -----------------------------------------------------------------------------
// GET /api/wallet/transactions
// -----------------------------------------------------------------------------

func (api *WalletAPI) TransactionsHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	// Authenticate FIRST.
	addr, ok := api.authenticateWallet(w, r)
	if !ok {
		return
	}

	if api.Ledger == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"ledger unavailable",
		)
		return
	}

	// Never allow the client to read another wallet's history.
	requestedAddr := strings.TrimSpace(
		r.URL.Query().Get("address"),
	)

	if requestedAddr != "" && requestedAddr != addr {
		writeError(
			w,
			http.StatusForbidden,
			"wallet address does not match authenticated session",
		)
		return
	}

	page := parsePositiveInt(
		r.URL.Query().Get("page"),
		1,
	)

	pageSize := parsePositiveInt(
		r.URL.Query().Get("page_size"),
		20,
	)

	if pageSize > maxTransactionsPageSize {
		pageSize = maxTransactionsPageSize
	}

	txs, err := api.Ledger.GetTransactionsByAddress(
		addr,
		page,
		pageSize,
	)
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to read transactions",
		)
		return
	}

	result := make(
		[]TransactionResponse,
		0,
		len(txs),
	)

	for _, tx := range txs {
		if tx == nil {
			continue
		}

		result = append(
			result,
			TransactionResponse{
				ID:            tx.ID,
				TxHash:        tx.TxHash,
				From:          tx.From,
				To:            tx.To,
				AmountEXP:     tx.AmountEXP,
				AmountIM:      tx.AmountIM,
				Fee:           tx.Fee,
				AmountPastabo: tx.AmountPastabo,
				IMANIPastabo:  tx.AmountIMPastabo,
				FeePastabo:    tx.FeePastabo,
				Timestamp:     tx.Timestamp,
				Nonce:         tx.Nonce,
				Note:          tx.Note,
				IsReward:      tx.IsReward,
				IsIMANILocked: tx.IsIMANILocked,
			},
		)
	}

	writeJSON(
		w,
		http.StatusOK,
		TransactionsResponse{
			Address:      addr,
			Page:         page,
			PageSize:     pageSize,
			Transactions: result,
		},
	)
}

// -----------------------------------------------------------------------------
// Authentication
// -----------------------------------------------------------------------------

// authenticateWallet authenticates the Bearer token and returns the
// wallet address associated with the session.
//
// This is the security boundary for protected wallet endpoints.
func (api *WalletAPI) authenticateWallet(
	w http.ResponseWriter,
	r *http.Request,
) (string, bool) {
	if api == nil || api.Auth == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"authentication service unavailable",
		)
		return "", false
	}

	addr, err := api.Auth.Authenticate(r)
	if err != nil {
		writeError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return "", false
	}

	if !ledger.IsValidEXPLOAddress(addr) {
		writeError(
			w,
			http.StatusUnauthorized,
			"invalid authenticated wallet",
		)
		return "", false
	}

	return addr, true
}

// -----------------------------------------------------------------------------
// Wallet persistence
// -----------------------------------------------------------------------------

// loadWallet loads the encrypted wallet from WalletDB.
//
// WalletDB is the wallet repository.
// The blockchain Ledger is NOT used to store private wallet material.
func (api *WalletAPI) loadWallet(
	addr string,
) (*wallet.Wallet, error) {
	if api == nil || api.Wallets == nil {
		return nil, errors.New(
			"wallet database unavailable",
		)
	}

	addr = strings.TrimSpace(addr)

	if addr == "" {
		return nil, errors.New(
			"wallet address is empty",
		)
	}

	if !ledger.IsValidEXPLOAddress(addr) {
		return nil, errors.New(
			"invalid EXPLO address",
		)
	}

	wlt, err := api.Wallets.LoadWallet(addr)
	if err != nil {
		return nil, err
	}

	if wlt == nil {
		return nil, errors.New(
			"wallet not found",
		)
	}

	if wlt.Address != addr {
		return nil, errors.New(
			"wallet address mismatch",
		)
	}

	if wlt.EncryptedPriv == nil {
		return nil, errors.New(
			"encrypted private key missing",
		)
	}

	return wlt, nil
}

// -----------------------------------------------------------------------------
// Ledger balance
// -----------------------------------------------------------------------------

func getLedgerBalance(
	l *ledger.Ledger,
	addr string,
) (ledger.Balance, error) {
	if l == nil {
		return ledger.Balance{}, errors.New(
			"ledger is nil",
		)
	}

	var balance ledger.Balance

	err := l.GetObject(
		[]byte("balance:"+addr),
		&balance,
	)

	if err != nil {
		// A wallet that has never received anything has no balance key.
		if errors.Is(err, badger.ErrKeyNotFound) {
			return ledger.Balance{}, nil
		}

		return ledger.Balance{}, err
	}

	return balance, nil
}

// -----------------------------------------------------------------------------
// Nonce
// -----------------------------------------------------------------------------

// getNextNonce reads the nonce exactly as the Ledger stores it.
//
// Ledger format:
//
//     nonce:<address> -> 8 raw bytes, BigEndian
//
// No CBOR decoding is used here.
func getNextNonce(
	l *ledger.Ledger,
	addr string,
) (int64, error) {
	if l == nil {
		return 0, errors.New(
			"ledger is nil",
		)
	}

	raw, err := l.GetBytes(
		[]byte("nonce:" + addr),
	)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			// First transaction for this address.
			return 1, nil
		}

		return 0, err
	}

	if len(raw) != 8 {
		return 0, errors.New(
			"invalid stored nonce",
		)
	}

	var u uint64

	for _, b := range raw {
		u = (u << 8) | uint64(b)
	}

	if u > uint64(math.MaxInt64) {
		return 0, errors.New(
			"stored nonce exceeds int64",
		)
	}

	current := int64(u)

	if current < 0 {
		return 0, errors.New(
			"invalid stored nonce",
		)
	}

	if current == math.MaxInt64 {
		return 0, errors.New(
			"nonce exhausted",
		)
	}

	return current + 1, nil
}

// -----------------------------------------------------------------------------
// EXPLO <-> Pastabo
// -----------------------------------------------------------------------------

// exploToPastabo converts the user-facing EXPLO amount to the
// integer consensus unit.
//
// Protocol:
//
//     1 EXPLO = 1,000,000,000 Pastabo
func exploToPastabo(
	amount float64,
) (uint64, error) {
	if math.IsNaN(amount) ||
		math.IsInf(amount, 0) {
		return 0, errors.New(
			"amount must be finite",
		)
	}

	if amount <= 0 {
		return 0, errors.New(
			"amount must be greater than zero",
		)
	}

	raw := amount *
		float64(ledger.PastaboPerEXPLO)

	if math.IsNaN(raw) ||
		math.IsInf(raw, 0) {
		return 0, errors.New(
			"amount is too large",
		)
	}

	maxUint64 := float64(^uint64(0))

	if raw > maxUint64 {
		return 0, errors.New(
			"amount is too large",
		)
	}

	pastabo := uint64(
		math.Round(raw),
	)

	if pastabo == 0 {
		return 0, errors.New(
			"amount is smaller than one Pastabo",
		)
	}

	return pastabo, nil
}

func pastaboToEXPLO(
	amount uint64,
) float64 {
	return float64(amount) /
		float64(ledger.PastaboPerEXPLO)
}

// -----------------------------------------------------------------------------
// Ledger error sanitization
// -----------------------------------------------------------------------------

func sanitizeLedgerError(
	err error,
) string {
	if err == nil {
		return "ledger error"
	}

	msg := strings.TrimSpace(
		err.Error(),
	)

	if msg == "" {
		return "ledger rejected transaction"
	}

	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "signature"):
		return "invalid transaction signature"

	case strings.Contains(lower, "nonce"):
		return "invalid transaction nonce"

	case strings.Contains(lower, "balance"):
		return "insufficient balance"

	case strings.Contains(lower, "duplicate"):
		return "transaction already exists"

	default:
		return "ledger rejected transaction"
	}
}

// -----------------------------------------------------------------------------
// Pagination
// -----------------------------------------------------------------------------

func parsePositiveInt(
	value string,
	fallback int,
) int {
	value = strings.TrimSpace(value)

	if value == "" {
		return fallback
	}

	var n int

	if _, err := fmt.Sscanf(
		value,
		"%d",
		&n,
	); err != nil {
		return fallback
	}

	if n <= 0 {
		return fallback
	}

	return n
}

// -----------------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------------

func decodeJSONBody(
	w http.ResponseWriter,
	r *http.Request,
	dst interface{},
) error {
	if r == nil || r.Body == nil {
		writeError(
			w,
			http.StatusBadRequest,
			"request body is required",
		)

		return errors.New(
			"request body is nil",
		)
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		maxJSONBodySize,
	)

	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)

	// Reject unknown fields so API clients cannot silently send
	// misspelled or obsolete parameters.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError

		if errors.As(err, &maxErr) {
			writeError(
				w,
				http.StatusRequestEntityTooLarge,
				"request body too large",
			)

			return err
		}

		writeError(
			w,
			http.StatusBadRequest,
			"invalid JSON request",
		)

		return err
	}

	// Reject a second JSON value in the same request body.
	var extra interface{}

	err := decoder.Decode(&extra)

	if err != io.EOF {
		if err == nil {
			writeError(
				w,
				http.StatusBadRequest,
				"request body must contain a single JSON object",
			)

			return errors.New(
				"multiple JSON values in request body",
			)
		}

		writeError(
			w,
			http.StatusBadRequest,
			"invalid JSON request",
		)

		return err
	}

	return nil
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value interface{},
) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(status)

	// Headers have already been sent at this point.
	// There is nothing useful left to send if encoding fails.
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(
		w,
		status,
		ErrorResponse{
			Success: false,
			Error:   message,
		},
	)
}
