package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"explosive/internal/api"
	"explosive/internal/ledger"
	"explosive/internal/wallet"
)

const (
	defaultAPIPort    = "8080"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	dataDirectoryPerm = 0700
)

func main() {
	// -------------------------------------------------------------------------
	// Configuration
	// -------------------------------------------------------------------------

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("❌ unable to determine home directory: %v", err)
	}

	dataDir := filepath.Join(homeDir, ".explosive")

	ledgerPath := filepath.Join(dataDir, "ledger")
	walletDBPath := filepath.Join(dataDir, "walletdb")
	authDBPath := filepath.Join(dataDir, "authdb")

	port := strings.TrimSpace(os.Getenv("EXPLOSIVE_API_PORT"))
	if port == "" {
		port = defaultAPIPort
	}

	if err := validatePort(port); err != nil {
		log.Fatalf("❌ invalid EXPLOSIVE_API_PORT: %v", err)
	}

	// -------------------------------------------------------------------------
	// Ensure data directory exists
	// -------------------------------------------------------------------------

	if err := os.MkdirAll(dataDir, dataDirectoryPerm); err != nil {
		log.Fatalf("❌ unable to create data directory: %v", err)
	}

	// -------------------------------------------------------------------------
	// Open EXPLOSIVE Ledger
	// -------------------------------------------------------------------------

	l, err := ledger.OpenLedger(ledgerPath)
	if err != nil {
		log.Fatalf("❌ unable to open EXPLOSIVE ledger: %v", err)
	}

	defer func() {
		if err := l.Close(); err != nil {
			log.Printf("⚠️ ledger close error: %v", err)
		}
	}()

	// -------------------------------------------------------------------------
	// Guardian Identity Hooks
	//
	// Must be initialized after opening the Ledger.
	//
	// Guardian provides:
	//   1. Consciousness fingerprint
	//   2. Identity commitment
	//   3. On-chain identity existence checks
	//   4. On-chain identity registration
	// -------------------------------------------------------------------------

	ledger.SetupGuardianIdentityHooks(l)

	// -------------------------------------------------------------------------
	// Open Wallet DB
	// -------------------------------------------------------------------------

	walletDB, err := wallet.OpenDB(walletDBPath)
	if err != nil {
		log.Fatalf("❌ unable to open wallet database: %v", err)
	}

	defer func() {
		if err := walletDB.Close(); err != nil {
			log.Printf("⚠️ wallet DB close error: %v", err)
		}
	}()

	// -------------------------------------------------------------------------
	// Open Authentication DB
	//
	// AuthDB stores session metadata only.
	//
	// It does NOT store:
	//   - password
	//   - mnemonic
	//   - private key
	//   - plaintext bearer token
	// -------------------------------------------------------------------------

	authDB, err := api.NewAuthDB(authDBPath)
	if err != nil {
		log.Fatalf("❌ unable to open authentication database: %v", err)
	}

	defer func() {
		if err := authDB.Close(); err != nil {
			log.Printf("⚠️ authentication DB close error: %v", err)
		}
	}()

	// -------------------------------------------------------------------------
	// Authentication API
	// -------------------------------------------------------------------------

	authAPI := api.NewAuthAPI(
		l,
		walletDB,
		authDB,
	)

	// -------------------------------------------------------------------------
	// Wallet API
	//
	// Protected endpoints use:
	//
	//     Authorization: Bearer <token>
	//
	// AuthAPI determines the wallet address associated with the session.
	// -------------------------------------------------------------------------

	walletAPI := api.NewWalletAPI(
		l,
		walletDB,
	)

	walletAPI.SetAuthAPI(authAPI)

	// -------------------------------------------------------------------------
	// Miner / Ledger API
	//
	// P2P is intentionally nil for now.
	//
	// ledger.Mine() remains the authoritative mining engine.
	// Miner authentication is connected to AuthAPI below.
	// -------------------------------------------------------------------------

	ledgerAPI := api.NewLedgerAPI(
		l,
		nil,
	)

	// IMPORTANT:
	// Miner endpoints now authenticate through the same wallet session.
	ledgerAPI.SetAuthAPI(authAPI)

	// -------------------------------------------------------------------------
	// HTTP Router
	// -------------------------------------------------------------------------

	mux := http.NewServeMux()

	// -------------------------------------------------------------------------
	// Authentication endpoints
	// -------------------------------------------------------------------------

	// POST /api/auth/login
	mux.HandleFunc(
		"/api/auth/login",
		authAPI.LoginHandler,
	)

	// POST /api/auth/logout
	mux.HandleFunc(
		"/api/auth/logout",
		authAPI.LogoutHandler,
	)

	// -------------------------------------------------------------------------
	// Wallet endpoints
	// -------------------------------------------------------------------------

	// Public:
	// POST /api/wallet/create
	mux.HandleFunc(
		"/api/wallet/create",
		walletAPI.CreateWalletHandler,
	)

	// Public:
	// POST /api/wallet/restore
	mux.HandleFunc(
		"/api/wallet/restore",
		walletAPI.RestoreWalletHandler,
	)

	// Protected:
	// GET /api/wallet/balance
	mux.HandleFunc(
		"/api/wallet/balance",
		walletAPI.WalletBalanceHandler,
	)

	// Protected:
	// GET /api/wallet/address
	mux.HandleFunc(
		"/api/wallet/address",
		walletAPI.WalletAddressHandler,
	)

	// Protected:
	// POST /api/wallet/send
	mux.HandleFunc(
		"/api/wallet/send",
		walletAPI.SendHandler,
	)

	// Protected:
	// GET /api/wallet/transactions
	mux.HandleFunc(
		"/api/wallet/transactions",
		walletAPI.TransactionsHandler,
	)

	// -------------------------------------------------------------------------
	// Miner / Ledger endpoints
	//
	// RegisterRoutes() registers:
	//
	// POST /api/miner/create
	// POST /api/miner/restore
	// POST /api/miner/mine
	// GET  /api/miner/transactions
	//
	// These routes are authenticated through AuthAPI.
	// -------------------------------------------------------------------------

	ledgerAPI.RegisterRoutes(mux)

	// -------------------------------------------------------------------------
	// Health endpoint
	//
	// Public endpoint used for service health checks.
	// -------------------------------------------------------------------------

	mux.HandleFunc("/health", healthHandler)

	// -------------------------------------------------------------------------
	// HTTP Security Middleware
	//
	// Provides:
	//   - request size limiting
	//   - rate limiting
	//   - CORS policy
	//   - security headers
	//   - panic recovery
	//
	// Authentication itself is handled by AuthAPI.
	// -------------------------------------------------------------------------

	security := api.NewHTTPSecurityMiddleware()
	securedHandler := security(mux)

	// -------------------------------------------------------------------------
	// HTTP Server
	// -------------------------------------------------------------------------

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           securedHandler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// -------------------------------------------------------------------------
	// Start HTTP server
	// -------------------------------------------------------------------------

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("🚀 EXPLOSIVE API listening on %s", server.Addr)
		log.Printf("📂 Data directory: %s", dataDir)
		log.Printf("📂 Ledger: %s", ledgerPath)
		log.Printf("📂 Wallet DB: %s", walletDBPath)
		log.Printf("🔐 Auth DB: %s", authDBPath)

		log.Println("🔐 Wallet API enabled")
		log.Println("🔑 Authentication API enabled")
		log.Println("🛡️ Guardian identity hooks enabled")
		log.Println("🔒 HTTP security middleware enabled")
		log.Println("⛏️ Miner/Ledger API enabled")
		log.Println("🔗 Wallet authentication connected to Miner API")

		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// -------------------------------------------------------------------------
	// Graceful shutdown
	// -------------------------------------------------------------------------

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	select {
	case sig := <-stop:
		log.Printf("🛑 shutdown signal received: %s", sig)

	case err := <-serverErrors:
		log.Fatalf("❌ HTTP server error: %v", err)
	}

	log.Println("🛑 shutting down EXPLOSIVE API...")

	ctx, cancel := context.WithTimeout(
		context.Background(),
		shutdownTimeout,
	)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("⚠️ HTTP shutdown error: %v", err)
	} else {
		log.Println("✅ HTTP server stopped gracefully")
	}

	log.Println("✅ EXPLOSIVE API stopped")
}

// -----------------------------------------------------------------------------
// Health Handler
// -----------------------------------------------------------------------------

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte(
		`{"status":"ok","service":"explosive-api"}`,
	))
}

// -----------------------------------------------------------------------------
// Port Validation
// -----------------------------------------------------------------------------

func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	if n < 1 || n > 65535 {
		return strconv.ErrRange
	}

	return nil
}
