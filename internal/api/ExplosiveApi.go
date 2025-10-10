// internal/api/ExplosiveApi_mainnet.go
package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"explosive/internal/db"
	"explosive/internal/ledger"
	"explosive/internal/scan"
	"explosive/internal/wallet"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// -----------------------------
// Ledger Service Implementation
// -----------------------------
type LedgerServiceImpl struct {
	L  *ledger.Ledger
	DB *db.BadgerDB
}

// NewLedgerServiceImpl returns a service wrapping the given Ledger and DB.
func NewLedgerServiceImpl(l *ledger.Ledger, database *db.BadgerDB) *LedgerServiceImpl {
	return &LedgerServiceImpl{L: l, DB: database}
}

// Ledger functions
func (s *LedgerServiceImpl) GetGlobalBalances() (map[string]interface{}, error) {
	if s.L == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}
	return s.L.GetGlobalBalances()
}

func (s *LedgerServiceImpl) GetMinerBalances(minerID string) (map[string]interface{}, error) {
	bal, err := wallet.GetBalance(s.DB, minerID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"miner_id": minerID,
		"EXPLO":    bal.EXPLO,
		"IMANI":    bal.IMANI,
	}, nil
}

func (s *LedgerServiceImpl) GetScanMetrics() (map[string]interface{}, error) {
	max, circ, holders, miners, minersRemaining, err := scan.ScanAllMetrics(s.L)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"max_supply":             max,
		"circulating":            circ,
		"holders":                holders,
		"miners":                 miners,
		"miners_to_next_halving": minersRemaining,
	}, nil
}

func (s *LedgerServiceImpl) GetGuardianMessages(limit int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

func (s *LedgerServiceImpl) GetTransferLogs(limit int) ([]map[string]interface{}, error) {
	return []map[string]interface{}{}, nil
}

// -----------------------------
// Wallet Functions
// -----------------------------
func (s *LedgerServiceImpl) GetWalletBalance(addr string) (map[string]float64, error) {
	bal, err := wallet.GetBalance(s.DB, addr)
	if err != nil {
		return nil, err
	}

	return map[string]float64{
		"EXPLO": bal.EXPLO,
		"IMANI": bal.IMANI,
	}, nil
}

func (s *LedgerServiceImpl) GetWalletTransactions(addr string) ([]wallet.Transaction, error) {
	txs, err := wallet.GetTransactions(s.DB, addr)
	if err != nil {
		return nil, err
	}
	return txs, nil
}

func (s *LedgerServiceImpl) ValidateWalletAddress(addr string) bool {
	return wallet.IsValidEXPLOAddress(addr)
}

// -----------------------------
// Middlewares (simple, safe defaults)
// -----------------------------

// simple token based export key check
func ExportKeyMiddleware() gin.HandlerFunc {
	key := os.Getenv("EXPORT_KEY")
	return func(c *gin.Context) {
		if key == "" {
			// if no key configured, block the endpoint in prod; allow in dev
			if gin.Mode() == gin.ReleaseMode {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "exports disabled: set EXPORT_KEY"})
				return
			}
			c.Next()
			return
		}
		provided := c.GetHeader("X-EXPORT-KEY")
		if provided == "" || provided != key {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid export key"})
			return
		}
		c.Next()
	}
}

// Rate limiter per IP with mutex-protected map
type ipLimiterStore struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
	r        rate.Limit
	b        int
}

func newIPLimiterStore(r rate.Limit, b int) *ipLimiterStore {
	return &ipLimiterStore{visitors: make(map[string]*rate.Limiter), r: r, b: b}
}

func (s *ipLimiterStore) get(ip string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.visitors[ip]; ok {
		return l
	}
	l := rate.NewLimiter(s.r, s.b)
	s.visitors[ip] = l
	return l
}

func RateLimitMiddleware(store *ipLimiterStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		lim := store.get(ip)
		if !lim.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

// Logging middleware (structured-ish)
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		c.Next()
		lat := time.Since(start)
		status := c.Writer.Status()
		// Keep logs concise and useful for production
		fmt.Printf("%s - %s %s %d %s\n", start.UTC().Format(time.RFC3339), c.ClientIP(), path, status, lat)
	}
}

// -----------------------------
// Explosive API Router - Mainnet ready
// -----------------------------
// NewExplosiveAPI builds a router ready for production use:
// - runs in release mode by default
// - sets trusted proxies from TRUSTED_PROXIES env (comma separated)
// - registers health/metrics/export endpoints
// - applies basic rate limiting and logging middleware
func NewExplosiveAPI(service *LedgerServiceImpl) *gin.Engine {
	// default to release unless explicitly set
	if os.Getenv("GIN_MODE") == "" {
		os.Setenv("GIN_MODE", gin.ReleaseMode)
	}
	gin.SetMode(os.Getenv("GIN_MODE"))

	r := gin.New()
	r.Use(gin.Recovery())
	// logging + rate limit
	store := newIPLimiterStore( rate.Limit(envOrInt("RATE_LIMIT", 5)), envOrInt("RATE_BURST", 10) )
	r.Use(LoggingMiddleware(), RateLimitMiddleware(store))

	// Trusted proxies
	proxies := os.Getenv("TRUSTED_PROXIES")
	if proxies == "" {
		// safe default for local/mainnet (should be configured in deployment)
		proxies = "127.0.0.1"
	}
	if err := r.SetTrustedProxies(strings.Split(proxies, ",")); err != nil {
		// fatal in production - prefer early failure
		panic(fmt.Sprintf("failed to set trusted proxies: %v", err))
	}

	// Health & readiness
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// basic metrics (can be extended to Prometheus exposition)
	r.GET("/metrics", func(c *gin.Context) {
		m, err := service.GetScanMetrics()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, m)
	})

	// protected export endpoint
	r.GET("/export_snapshot", ExportKeyMiddleware(), func(c *gin.Context) {
		// example: return a lightweight snapshot of global balances
		data, err := service.GetGlobalBalances()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	// ----- Ledger Endpoints -----
	r.GET("/global_balances", func(c *gin.Context) {
		data, err := service.GetGlobalBalances()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	r.GET("/miner_balances", func(c *gin.Context) {
		minerID := c.Query("miner_id")
		if minerID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "miner_id query required"})
			return
		}
		data, err := service.GetMinerBalances(minerID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	r.GET("/scan_metrics", func(c *gin.Context) {
		data, err := service.GetScanMetrics()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	r.GET("/guardian_messages", func(c *gin.Context) {
		data, _ := service.GetGuardianMessages(50)
		c.JSON(http.StatusOK, data)
	})

	r.GET("/transfer_logs", func(c *gin.Context) {
		data, _ := service.GetTransferLogs(50)
		c.JSON(http.StatusOK, data)
	})

	// ----- Wallet Endpoints -----
	r.GET("/wallet_balance", func(c *gin.Context) {
		addr := c.Query("address")
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "address query required"})
			return
		}
		data, err := service.GetWalletBalance(addr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, data)
	})

	r.GET("/wallet_transactions", func(c *gin.Context) {
		addr := c.Query("address")
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "address query required"})
			return
		}
		txs, err := service.GetWalletTransactions(addr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, txs)
	})

	r.GET("/validate_address", func(c *gin.Context) {
		addr := c.Query("address")
		if addr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "address query required"})
			return
		}
		valid := service.ValidateWalletAddress(addr)
		c.JSON(http.StatusOK, gin.H{"valid": valid})
	})

	return r
}

// -----------------------------
// Helpers
// -----------------------------
func envOrInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var i int
	if _, err := fmt.Sscanf(v, "%d", &i); err != nil {
		return def
	}
	return i
}

func envOr(name, def string) string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v
}

// GracefulShutdown helper (can be used by callers) to stop server with context.
func GracefulShutdown(srv *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.Shutdown(ctx)
}
