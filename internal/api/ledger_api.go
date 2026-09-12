package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"explosive/internal/common"
	"explosive/internal/ledger"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	ledgerAPIMaxBodySize     = 1 << 20 // 1 MiB
	ledgerAPIMaxPageSize     = 100
	ledgerAPIDefaultPageSize = 20
)

// -----------------------------------------------------------------------------
// LedgerAPI
// -----------------------------------------------------------------------------

// LedgerAPI exposes the miner/account layer of EXPLOSIVE BLOCK.
//
// Responsibilities:
//   - Create miner identity
//   - Restore miner identity
//   - Execute daily mining
//   - Read miner transaction history
//
// IMPORTANT:
// Consensus remains inside internal/ledger.
// This package is only an HTTP/API boundary.
//
// Authentication:
//   - Wallet authentication is handled by AuthAPI.
//   - Miner ID must match the authenticated wallet address.
//   - Sacred Words remain inside the miner subsystem.
//   - No private key, password or Sacred Words are stored by this API.
type LedgerAPI struct {
	Ledger *ledger.Ledger
	P2P    common.P2PNode
	Auth   *AuthAPI
}

// NewLedgerAPI creates a new ledger/mining API.
func NewLedgerAPI(
	l *ledger.Ledger,
	p2p common.P2PNode,
) *LedgerAPI {
	return &LedgerAPI{
		Ledger: l,
		P2P:    p2p,
	}
}

// SetAuthAPI connects the Ledger API to the authentication layer.
func (a *LedgerAPI) SetAuthAPI(authAPI *AuthAPI) {
	if a == nil {
		return
	}

	a.Auth = authAPI
}

// -----------------------------------------------------------------------------
// Request models
// -----------------------------------------------------------------------------

type CreateMinerRequest struct {
	ID       string   `json:"id"`
	Password string   `json:"password"`
	Words    []string `json:"words"`
}

type RestoreMinerRequest struct {
	ID       string   `json:"id"`
	Password string   `json:"password"`
	Words    []string `json:"words"`
}

type MineRequest struct {
	ID              string   `json:"id"`
	Password        string   `json:"password"`
	Words           []string `json:"words"`
	DonationPercent float64  `json:"donation_percent"`
}

// -----------------------------------------------------------------------------
// Response models
// -----------------------------------------------------------------------------

type CreateMinerResponse struct {
	Success         bool   `json:"success"`
	MinerID         string `json:"miner_id"`
	FingerprintHash string `json:"fingerprint_hash,omitempty"`
	Version         uint8  `json:"version"`
	Message         string `json:"message"`
}

type RestoreMinerResponse struct {
	Success         bool   `json:"success"`
	MinerID         string `json:"miner_id"`
	FingerprintHash string `json:"fingerprint_hash,omitempty"`
	Version         uint8  `json:"version"`
	Message         string `json:"message"`
}

type MineResponse struct {
	Success         bool    `json:"success"`
	MinerID         string  `json:"miner_id"`
	Message         string  `json:"message"`
	LastMineUnix    int64   `json:"last_mine_unix,omitempty"`
	DonationPercent float64 `json:"donation_percent"`
}

type MinerTransactionsResponse struct {
	Success      bool                       `json:"success"`
	MinerID      string                     `json:"miner_id"`
	Page         int                        `json:"page"`
	PageSize     int                        `json:"page_size"`
	Transactions []MinerTransactionResponse `json:"transactions"`
}

type MinerTransactionResponse struct {
	ID            string  `json:"id,omitempty"`
	TxHash        string  `json:"tx_hash"`
	From          string  `json:"from"`
	To            string  `json:"to"`
	AmountEXP     float64 `json:"amount_explo"`
	AmountIM      float64 `json:"amount_imani"`
	FeeEXP        float64 `json:"fee"`
	AmountPastabo uint64  `json:"amount_pastabo"`
	IMANIPastabo  uint64  `json:"amount_imani_pastabo"`
	FeePastabo    uint64  `json:"fee_pastabo"`
	Timestamp     int64   `json:"timestamp"`
	Nonce         int64   `json:"nonce"`
	Note          string  `json:"note,omitempty"`
	IsReward      bool    `json:"is_reward"`
	IsIMANILocked bool    `json:"is_imani_locked"`
}

// -----------------------------------------------------------------------------
// Generic API response
// -----------------------------------------------------------------------------

type ledgerAPIErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// -----------------------------------------------------------------------------
// Router registration
// -----------------------------------------------------------------------------

// RegisterRoutes registers the miner/ledger API endpoints.
//
// Routes:
//
//	POST /api/miner/create
//	POST /api/miner/restore
//	POST /api/miner/mine
//	GET  /api/miner/transactions
func (a *LedgerAPI) RegisterRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}

	mux.HandleFunc("/api/miner/create", a.handleCreateMiner)
	mux.HandleFunc("/api/miner/restore", a.handleRestoreMiner)
	mux.HandleFunc("/api/miner/mine", a.handleMine)
	mux.HandleFunc("/api/miner/transactions", a.handleMinerTransactions)
}

// -----------------------------------------------------------------------------
// POST /api/miner/create
// -----------------------------------------------------------------------------

func (a *LedgerAPI) handleCreateMiner(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeLedgerAPIError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if !a.ledgerReady(w) {
		return
	}

	minerID, ok := a.authenticateMiner(w, r)
	if !ok {
		return
	}

	var req CreateMinerRequest

	if err := decodeLedgerJSON(w, r, &req); err != nil {
		return
	}

	req.ID = strings.TrimSpace(req.ID)

	if req.ID != minerID {
		writeLedgerAPIError(
			w,
			http.StatusForbidden,
			"miner id does not match authenticated wallet",
		)
		return
	}

	if err := validateMinerRequest(
		req.ID,
		req.Password,
		req.Words,
	); err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"miner creation failed",
		)
		return
	}

	ipHash := hashClientIP(r)

	miner, fingerprintHash, err := ledger.CreateMiner(
		req.ID,
		req.Password,
		req.Words,
		ipHash,
		a.Ledger,
	)
	if err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"miner creation failed",
		)
		return
	}

	if miner == nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"miner creation returned nil miner",
		)
		return
	}

	response := CreateMinerResponse{
		Success:         true,
		MinerID:         miner.ID,
		FingerprintHash: fingerprintHash,
		Version:         miner.Version,
		Message:         "miner account created successfully",
	}

	writeLedgerJSON(
		w,
		http.StatusCreated,
		response,
	)
}

// -----------------------------------------------------------------------------
// POST /api/miner/restore
// -----------------------------------------------------------------------------

func (a *LedgerAPI) handleRestoreMiner(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeLedgerAPIError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if !a.ledgerReady(w) {
		return
	}

	minerID, ok := a.authenticateMiner(w, r)
	if !ok {
		return
	}

	var req RestoreMinerRequest

	if err := decodeLedgerJSON(w, r, &req); err != nil {
		return
	}

	req.ID = strings.TrimSpace(req.ID)

	if req.ID != minerID {
		writeLedgerAPIError(
			w,
			http.StatusForbidden,
			"miner id does not match authenticated wallet",
		)
		return
	}

	if err := validateMinerRequest(
		req.ID,
		req.Password,
		req.Words,
	); err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"miner restoration failed",
		)
		return
	}

	miner, fingerprintHash, err := ledger.RestoreMinerUniversal(
		req.ID,
		req.Words,
		req.Password,
		a.Ledger,
	)
	if err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"miner restoration failed",
		)
		return
	}

	if miner == nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"miner restoration returned nil miner",
		)
		return
	}

	response := RestoreMinerResponse{
		Success:         true,
		MinerID:         miner.ID,
		FingerprintHash: fingerprintHash,
		Version:         miner.Version,
		Message:         "miner account restored successfully",
	}

	writeLedgerJSON(
		w,
		http.StatusOK,
		response,
	)
}

// -----------------------------------------------------------------------------
// POST /api/miner/mine
// -----------------------------------------------------------------------------

func (a *LedgerAPI) handleMine(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeLedgerAPIError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if !a.ledgerReady(w) {
		return
	}

	minerID, ok := a.authenticateMiner(w, r)
	if !ok {
		return
	}

	var req MineRequest

	if err := decodeLedgerJSON(w, r, &req); err != nil {
		return
	}

	req.ID = strings.TrimSpace(req.ID)

	if req.ID != minerID {
		writeLedgerAPIError(
			w,
			http.StatusForbidden,
			"miner id does not match authenticated wallet",
		)
		return
	}

	if err := validateMinerRequest(
		req.ID,
		req.Password,
		req.Words,
	); err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"mining request rejected",
		)
		return
	}

	if req.DonationPercent < ledger.MinDonationPercent ||
		req.DonationPercent > ledger.MaxDonationPercent {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"donation_percent must be between 0 and 0.1",
		)
		return
	}

	// Reconstruct the deterministic miner identity.
	//
	// RestoreMinerUniversal() does not mint rewards.
	// It only reconstructs/verifies the miner identity.
	miner, _, err := ledger.RestoreMinerUniversal(
		req.ID,
		req.Words,
		req.Password,
		a.Ledger,
	)
	if err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"mining request rejected",
		)
		return
	}

	if miner == nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"unable to reconstruct miner identity",
		)
		return
	}

	// MinerState is only a UX state object.
	// The authoritative daily mining rule remains inside ledger.Mine().
	state := &ledger.MinerState{}

	if err := ledger.Mine(
		a.Ledger,
		miner,
		state,
		req.DonationPercent,
		a.P2P,
	); err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"mining request rejected",
		)
		return
	}

	response := MineResponse{
		Success:         true,
		MinerID:         miner.ID,
		Message:         "daily mining completed successfully",
		LastMineUnix:    state.LastMineUnix,
		DonationPercent: req.DonationPercent,
	}

	writeLedgerJSON(
		w,
		http.StatusOK,
		response,
	)
}

// -----------------------------------------------------------------------------
// GET /api/miner/transactions
// -----------------------------------------------------------------------------

func (a *LedgerAPI) handleMinerTransactions(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeLedgerAPIError(
			w,
			http.StatusMethodNotAllowed,
			"method not allowed",
		)
		return
	}

	if !a.ledgerReady(w) {
		return
	}

	authenticatedMinerID, ok := a.authenticateMiner(w, r)
	if !ok {
		return
	}

	minerID := strings.TrimSpace(
		r.URL.Query().Get("miner_id"),
	)

	if minerID == "" {
		minerID = authenticatedMinerID
	}

	if minerID != authenticatedMinerID {
		writeLedgerAPIError(
			w,
			http.StatusForbidden,
			"miner id does not match authenticated wallet",
		)
		return
	}

	if !ledger.IsValidEXPLOAddress(minerID) {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"invalid miner address",
		)
		return
	}

	page := parseLedgerPositiveInt(
		r.URL.Query().Get("page"),
		1,
	)

	pageSize := parseLedgerPositiveInt(
		r.URL.Query().Get("page_size"),
		ledgerAPIDefaultPageSize,
	)

	if pageSize > ledgerAPIMaxPageSize {
		pageSize = ledgerAPIMaxPageSize
	}

	txs, err := a.Ledger.GetTransactionsByAddress(
		minerID,
		page,
		pageSize,
	)
	if err != nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"failed to retrieve miner transactions",
		)
		return
	}

	response := MinerTransactionsResponse{
		Success:      true,
		MinerID:      minerID,
		Page:         page,
		PageSize:     pageSize,
		Transactions: make([]MinerTransactionResponse, 0, len(txs)),
	}

	for _, tx := range txs {
		if tx == nil {
			continue
		}

		response.Transactions = append(
			response.Transactions,
			MinerTransactionResponse{
				ID:            tx.ID,
				TxHash:        tx.TxHash,
				From:          tx.From,
				To:            tx.To,
				AmountEXP:     tx.AmountEXP,
				AmountIM:      tx.AmountIM,
				FeeEXP:        tx.Fee,
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

	writeLedgerJSON(
		w,
		http.StatusOK,
		response,
	)
}

// -----------------------------------------------------------------------------
// Authentication / authorization
// -----------------------------------------------------------------------------

// authenticateMiner authenticates the wallet session and ensures that the
// requested miner identity belongs to that authenticated wallet.
//
// The caller receives the authenticated wallet/miner address.
// No password or Sacred Words are stored in the API layer.
func (a *LedgerAPI) authenticateMiner(
	w http.ResponseWriter,
	r *http.Request,
) (string, bool) {
	if a.Auth == nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"authentication service is not configured",
		)
		return "", false
	}

	address, err := a.Auth.Authenticate(r)
	if err != nil {
		writeLedgerAPIError(
			w,
			http.StatusUnauthorized,
			"authentication required",
		)
		return "", false
	}

	address = strings.TrimSpace(address)

	if !ledger.IsValidEXPLOAddress(address) {
		writeLedgerAPIError(
			w,
			http.StatusUnauthorized,
			"invalid authenticated wallet",
		)
		return "", false
	}

	return address, true
}

// -----------------------------------------------------------------------------
// Ledger readiness
// -----------------------------------------------------------------------------

func (a *LedgerAPI) ledgerReady(w http.ResponseWriter) bool {
	if a == nil || a.Ledger == nil {
		writeLedgerAPIError(
			w,
			http.StatusInternalServerError,
			"ledger is not initialized",
		)
		return false
	}

	return true
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

func validateMinerRequest(
	id string,
	password string,
	words []string,
) error {
	if id == "" {
		return errors.New("miner id is required")
	}

	if !ledger.IsValidEXPLOAddress(id) {
		return errors.New("invalid miner address")
	}

	if password == "" {
		return errors.New("password is required")
	}

	if !ledger.IsValidPassword(password) {
		return errors.New(
			"invalid password: minimum 8 characters with uppercase, lowercase, digit and symbol required",
		)
	}

	if !ledger.IsValidSacredWords(words) {
		return errors.New("invalid sacred words")
	}

	return nil
}

// -----------------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------------

func decodeLedgerJSON(
	w http.ResponseWriter,
	r *http.Request,
	dst interface{},
) error {
	if r == nil || r.Body == nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"request body is required",
		)
		return errors.New("request body is nil")
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		ledgerAPIMaxBodySize,
	)
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"invalid JSON body",
		)
		return err
	}

	// Reject multiple JSON values in a single request body.
	var extra interface{}

	if err := decoder.Decode(&extra); err != io.EOF {
		writeLedgerAPIError(
			w,
			http.StatusBadRequest,
			"invalid JSON body",
		)

		if err == nil {
			return errors.New("multiple JSON values in request body")
		}

		return err
	}

	return nil
}

func writeLedgerJSON(
	w http.ResponseWriter,
	status int,
	payload interface{},
) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(payload)
}

func writeLedgerAPIError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeLedgerJSON(
		w,
		status,
		ledgerAPIErrorResponse{
			Success: false,
			Error:   message,
		},
	)
}

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------

func parseLedgerPositiveInt(
	value string,
	fallback int,
) int {
	if value == "" {
		return fallback
	}

	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return fallback
	}

	return n
}

// hashClientIP returns a deterministic SHA3-based IP fingerprint.
//
// IMPORTANT:
// The actual IP is never passed to the miner subsystem.
// CreateMiner() receives only this hashed representation.
func hashClientIP(r *http.Request) string {
	ip := clientIP(r)

	return ledger.Sha3Hex([]byte(ip))
}

func clientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	// Never blindly trust X-Forwarded-For.
	// The security middleware already treats the TCP peer as authoritative.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}

	return "unknown"
}
