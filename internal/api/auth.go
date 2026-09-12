package api

import (
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"

	"explosive/internal/encryption"
	"explosive/internal/ledger"
	"explosive/internal/wallet"
)

const (
	authSessionPrefix = "SESSION_"

	// Session lifetime.
	authSessionDuration = 24 * time.Hour

	// Access token size.
	authTokenBytes = 32

	// Maximum authentication request body.
	authMaxBodySize = 1 << 20
)

// AuthDB stores authentication sessions separately
// from the wallet database.
type AuthDB struct {
	db *badger.DB
}

// AuthSession represents one authenticated wallet session.
//
// IMPORTANT:
// The actual access token is NEVER stored.
// Only TokenHash is persisted.
type AuthSession struct {
	TokenHash         string `json:"token_hash"`
	WalletAddress     string `json:"wallet_address"`
	CreatedAt         int64  `json:"created_at"`
	ExpiresAt         int64  `json:"expires_at"`
	PasswordTimestamp int64  `json:"password_timestamp"`
	Revoked           bool   `json:"revoked"`
}

// AuthAPI handles wallet authentication and sessions.
type AuthAPI struct {
	Ledger  *ledger.Ledger
	Wallets *wallet.WalletDB
	AuthDB  *AuthDB
}

// NewAuthDB opens the authentication database.
func NewAuthDB(path string) (*AuthDB, error) {
	opts := badger.DefaultOptions(path).
		WithLoggingLevel(badger.WARNING).
		WithNumCompactors(2).
		WithValueLogFileSize(1 << 20).
		WithSyncWrites(true)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	return &AuthDB{
		db: db,
	}, nil
}

// Close closes the authentication database.
func (adb *AuthDB) Close() error {
	if adb == nil || adb.db == nil {
		return nil
	}

	return adb.db.Close()
}

// LoginRequest is the authentication request.
type LoginRequest struct {
	Address  string `json:"address"`
	Password string `json:"password"`
}

// LoginResponse is returned only after successful authentication.
type LoginResponse struct {
	Success   bool   `json:"success"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Address   string `json:"address"`
}

// LogoutResponse is returned after revoking a session.
type LogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// NewAuthAPI creates the authentication API.
func NewAuthAPI(
	l *ledger.Ledger,
	wdb *wallet.WalletDB,
	adb *AuthDB,
) *AuthAPI {
	return &AuthAPI{
		Ledger:  l,
		Wallets: wdb,
		AuthDB:  adb,
	}
}

// LoginHandler authenticates a wallet and creates a Bearer session.
func (a *AuthAPI) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if a == nil || a.Wallets == nil || a.AuthDB == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"authentication service unavailable",
		)
		return
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		authMaxBodySize,
	)

	var req LoginRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Reject a second JSON value.
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			writeError(
				w,
				http.StatusBadRequest,
				"request body must contain a single JSON object",
			)
			return
		}

		writeError(
			w,
			http.StatusBadRequest,
			"invalid JSON body",
		)
		return
	}

	req.Address = strings.TrimSpace(req.Address)

	if req.Address == "" {
		writeError(w, http.StatusBadRequest, "address is required")
		return
	}

	if !ledger.IsValidEXPLOAddress(req.Address) {
		writeError(w, http.StatusBadRequest, "invalid wallet address")
		return
	}

	// DO NOT trim the password.
	// Spaces can legitimately be part of a password.
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	// Load the wallet by address.
	wlt, err := a.Wallets.LoadWallet(req.Address)
	if err != nil {
		// Do not reveal whether the wallet exists.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if wlt == nil || wlt.EncryptedPriv == nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Decrypt only for authentication verification.
	//
	// The decrypted private key is immediately wiped.
	privBytes, _, err := encryption.DecryptWallet(
		wlt.EncryptedPriv,
		req.Password,
	)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	for i := range privBytes {
		privBytes[i] = 0
	}

	// Retrieve the current password timestamp.
	passwordTimestamp, err :=
		a.Wallets.GetPasswordTimestamp(req.Address)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"authentication service unavailable",
		)
		return
	}

	// Generate a cryptographically secure access token.
	token, err := generateAuthToken()
	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to create session",
		)
		return
	}

	// Only the hash is stored in AuthDB.
	tokenHash := hashAuthToken(token)

	now := time.Now().Unix()
	expiresAt := time.Now().
		Add(authSessionDuration).
		Unix()

	session := AuthSession{
		TokenHash:         tokenHash,
		WalletAddress:     req.Address,
		CreatedAt:         now,
		ExpiresAt:         expiresAt,
		PasswordTimestamp: passwordTimestamp,
		Revoked:           false,
	}

	if err := a.AuthDB.saveSession(session); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to create session",
		)
		return
	}

	// The real token is returned only once.
	writeJSON(w, http.StatusOK, LoginResponse{
		Success:   true,
		Token:     token,
		ExpiresAt: expiresAt,
		Address:   req.Address,
	})
}

// LogoutHandler revokes the current Bearer token.
func (a *AuthAPI) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if a == nil || a.AuthDB == nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"authentication service unavailable",
		)
		return
	}

	token, ok := extractBearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tokenHash := hashAuthToken(token)

	session, err := a.AuthDB.getSession(tokenHash)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid session")
			return
		}

		writeError(
			w,
			http.StatusInternalServerError,
			"authentication service unavailable",
		)
		return
	}

	session.Revoked = true

	if err := a.AuthDB.saveSession(session); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"failed to revoke session",
		)
		return
	}

	writeJSON(w, http.StatusOK, LogoutResponse{
		Success: true,
		Message: "session revoked",
	})
}

// Authenticate validates the Bearer token and returns the wallet address.
func (a *AuthAPI) Authenticate(r *http.Request) (string, error) {
	if a == nil || a.AuthDB == nil || a.Wallets == nil {
		return "", errors.New("authentication service unavailable")
	}

	token, ok := extractBearerToken(r)
	if !ok {
		return "", errors.New("authentication required")
	}

	tokenHash := hashAuthToken(token)

	session, err := a.AuthDB.getSession(tokenHash)
	if err != nil {
		return "", errors.New("invalid session")
	}

	if session.Revoked {
		return "", errors.New("session revoked")
	}

	now := time.Now().Unix()

	if session.ExpiresAt <= now {
		session.Revoked = true
		_ = a.AuthDB.saveSession(session)

		return "", errors.New("session expired")
	}

	// Check whether the wallet password was changed
	// after this session was created.
	currentPasswordTimestamp, err :=
		a.Wallets.GetPasswordTimestamp(session.WalletAddress)

	if err != nil {
		return "", errors.New("authentication service unavailable")
	}

	if currentPasswordTimestamp != session.PasswordTimestamp {
		session.Revoked = true
		_ = a.AuthDB.saveSession(session)

		return "", errors.New("session invalidated")
	}

	return session.WalletAddress, nil
}

// RevokeAllSessions revokes every active session belonging
// to the specified wallet address.
func (a *AuthAPI) RevokeAllSessions(address string) error {
	if a == nil || a.AuthDB == nil {
		return errors.New("authentication service unavailable")
	}

	address = strings.TrimSpace(address)

	if !ledger.IsValidEXPLOAddress(address) {
		return errors.New("invalid wallet address")
	}

	return a.AuthDB.revokeSessionsForWallet(address)
}

// saveSession persists a session.
func (adb *AuthDB) saveSession(session AuthSession) error {
	if adb == nil || adb.db == nil {
		return errors.New("authentication database unavailable")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	key := []byte(authSessionPrefix + session.TokenHash)

	return adb.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, data)
	})
}

// getSession retrieves a session by token hash.
func (adb *AuthDB) getSession(tokenHash string) (AuthSession, error) {
	var session AuthSession

	if adb == nil || adb.db == nil {
		return session, errors.New("authentication database unavailable")
	}

	key := []byte(authSessionPrefix + tokenHash)

	err := adb.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(value []byte) error {
			return json.Unmarshal(value, &session)
		})
	})

	if err != nil {
		return session, err
	}

	return session, nil
}

// revokeSessionsForWallet revokes all sessions for a wallet.
func (adb *AuthDB) revokeSessionsForWallet(address string) error {
	if adb == nil || adb.db == nil {
		return errors.New("authentication database unavailable")
	}

	prefix := []byte(authSessionPrefix)

	var sessions []AuthSession

	err := adb.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		iterator := txn.NewIterator(opts)
		defer iterator.Close()

		for iterator.Rewind(); iterator.Valid(); iterator.Next() {
			item := iterator.Item()

			err := item.Value(func(value []byte) error {
				var session AuthSession

				if err := json.Unmarshal(value, &session); err != nil {
					return err
				}

				if session.WalletAddress == address &&
					!session.Revoked {
					session.Revoked = true
					sessions = append(sessions, session)
				}

				return nil
			})

			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	return adb.db.Update(func(txn *badger.Txn) error {
		for _, session := range sessions {
			data, err := json.Marshal(session)
			if err != nil {
				return err
			}

			key := []byte(authSessionPrefix + session.TokenHash)

			if err := txn.Set(key, data); err != nil {
				return err
			}
		}

		return nil
	})
}

// generateAuthToken creates a cryptographically secure random token.
func generateAuthToken() (string, error) {
	raw := make([]byte, authTokenBytes)

	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw), nil
}

// hashAuthToken hashes the access token using SHA3-256.
func hashAuthToken(token string) string {
	sum := sha3.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// extractBearerToken extracts:
//
//	Authorization: Bearer <token>
func extractBearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	header := strings.TrimSpace(
		r.Header.Get("Authorization"),
	)

	if header == "" {
		return "", false
	}

	parts := strings.Fields(header)

	if len(parts) != 2 {
		return "", false
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(parts[1])

	if token == "" {
		return "", false
	}

	return token, true
}
