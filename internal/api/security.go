package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Security configuration
// -----------------------------------------------------------------------------

const (
	defaultRateLimitWindow = time.Minute

	// Maximum number of requests from one client IP during the window.
	defaultRateLimitRequests = 60

	// More restrictive limit for cryptographically expensive endpoints.
	defaultSensitiveRateLimitRequests = 10

	rateLimiterCleanupInterval = 5 * time.Minute

	// Maximum request body accepted by the global HTTP security layer.
	globalMaxBodySize = 1 << 20 // 1 MiB
)

// -----------------------------------------------------------------------------
// Rate limiter
// -----------------------------------------------------------------------------

type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

type ipRateLimiter struct {
	mu sync.Mutex

	entries map[string]*rateLimitEntry

	window          time.Duration
	maxRequests     int
	sensitiveMax    int
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{
		entries:         make(map[string]*rateLimitEntry),
		window:          defaultRateLimitWindow,
		maxRequests:     defaultRateLimitRequests,
		sensitiveMax:    defaultSensitiveRateLimitRequests,
		cleanupInterval: rateLimiterCleanupInterval,
		lastCleanup:     time.Now(),
	}
}

func (rl *ipRateLimiter) allow(
	ip string,
	sensitive bool,
) (bool, time.Duration) {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodically remove expired entries.
	if now.Sub(rl.lastCleanup) >= rl.cleanupInterval {
		rl.cleanupLocked(now)
		rl.lastCleanup = now
	}

	entry, ok := rl.entries[ip]

	// Start a new rate-limit window.
	if !ok || now.Sub(entry.windowStart) >= rl.window {
		rl.entries[ip] = &rateLimitEntry{
			count:       1,
			windowStart: now,
		}

		return true, 0
	}

	limit := rl.maxRequests

	if sensitive {
		limit = rl.sensitiveMax
	}

	// Request limit reached.
	if entry.count >= limit {
		retryAfter := rl.window - now.Sub(entry.windowStart)

		if retryAfter < 0 {
			retryAfter = 0
		}

		return false, retryAfter
	}

	entry.count++

	return true, 0
}

func (rl *ipRateLimiter) cleanupLocked(now time.Time) {
	for ip, entry := range rl.entries {
		if now.Sub(entry.windowStart) >= rl.window {
			delete(rl.entries, ip)
		}
	}
}

// -----------------------------------------------------------------------------
// Security middleware
// -----------------------------------------------------------------------------

type securityMiddleware struct {
	rateLimiter *ipRateLimiter
	origins     map[string]struct{}
}

func newSecurityMiddleware() *securityMiddleware {
	return &securityMiddleware{
		rateLimiter: newIPRateLimiter(),
		origins:     loadAllowedOrigins(),
	}
}

// NewHTTPSecurityMiddleware creates the complete HTTP security middleware.
//
// This function is intentionally exported because cmd/explosiveapi/main.go
// needs to attach the security layer to the HTTP router.
//
// Usage:
//
//	security := api.NewHTTPSecurityMiddleware()
//	securedHandler := security(mux)
//
// The middleware provides:
//   - rate limiting
//   - CORS validation
//   - security headers
//   - global request-body protection
//   - panic recovery
//
// IMPORTANT:
// This is transport/request protection, not user authentication.
// Wallet authentication/session tokens must be implemented separately.
func NewHTTPSecurityMiddleware() func(http.Handler) http.Handler {
	middleware := newSecurityMiddleware()

	return func(next http.Handler) http.Handler {
		return middleware.Wrap(next)
	}
}

// Wrap applies all HTTP security protections.
func (s *securityMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ---------------------------------------------------------------------
		// Security headers
		// ---------------------------------------------------------------------

		setSecurityHeaders(w)

		// ---------------------------------------------------------------------
		// CORS
		// ---------------------------------------------------------------------

		if !s.handleCORS(w, r) {
			return
		}

		// Browser preflight.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// ---------------------------------------------------------------------
		// Basic request protection
		// ---------------------------------------------------------------------

		if r.URL == nil {
			writeSecurityError(
				w,
				http.StatusBadRequest,
				"invalid request",
			)
			return
		}

		// ---------------------------------------------------------------------
		// Rate limiting
		// ---------------------------------------------------------------------

		ip := requestClientIP(r)

		sensitive := isSensitiveEndpoint(r)

		allowed, retryAfter := s.rateLimiter.allow(
			ip,
			sensitive,
		)

		if !allowed {
			seconds := int(retryAfter.Seconds())

			if seconds < 1 {
				seconds = 1
			}

			w.Header().Set(
				"Retry-After",
				strconv.Itoa(seconds),
			)

			writeSecurityError(
				w,
				http.StatusTooManyRequests,
				"too many requests",
			)
			return
		}

		// ---------------------------------------------------------------------
		// Global request body protection
		//
		// Endpoint-specific decoders also apply their own body limit.
		// This outer limit guarantees that all API routes are protected.
		// ---------------------------------------------------------------------

		if r.Body != nil &&
			r.Method != http.MethodGet &&
			r.Method != http.MethodHead {

			r.Body = http.MaxBytesReader(
				w,
				r.Body,
				globalMaxBodySize,
			)
		}

		// ---------------------------------------------------------------------
		// Panic protection
		// ---------------------------------------------------------------------

		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf(
					"❌ HTTP handler panic: %v",
					recovered,
				)

				// If the response has already started, the HTTP server cannot
				// safely replace the response body. The generic error below is
				// still useful when the panic occurs before the response starts.
				writeSecurityError(
					w,
					http.StatusInternalServerError,
					"internal server error",
				)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------------
// CORS
// -----------------------------------------------------------------------------

func loadAllowedOrigins() map[string]struct{} {
	result := make(map[string]struct{})

	raw := strings.TrimSpace(
		os.Getenv("EXPLOSIVE_API_ALLOWED_ORIGINS"),
	)

	if raw == "" {
		// No wildcard by default.
		//
		// This is intentional: the API must not automatically allow every
		// website to make browser requests.
		return result
	}

	for _, origin := range strings.Split(raw, ",") {
		origin = strings.TrimSpace(origin)

		if origin == "" {
			continue
		}

		result[origin] = struct{}{}
	}

	return result
}

func (s *securityMiddleware) handleCORS(
	w http.ResponseWriter,
	r *http.Request,
) bool {
	origin := strings.TrimSpace(
		r.Header.Get("Origin"),
	)

	// Non-browser clients such as curl normally do not send Origin.
	if origin == "" {
		return true
	}

	if _, allowed := s.origins[origin]; !allowed {
		// Do not reveal configured origins.
		writeSecurityError(
			w,
			http.StatusForbidden,
			"origin not allowed",
		)
		return false
	}

	w.Header().Set(
		"Access-Control-Allow-Origin",
		origin,
	)

	w.Header().Set(
		"Vary",
		"Origin",
	)

	w.Header().Set(
		"Access-Control-Allow-Methods",
		"GET, POST, OPTIONS",
	)

	w.Header().Set(
		"Access-Control-Allow-Headers",
		"Content-Type, Authorization, X-Requested-With",
	)

	w.Header().Set(
		"Access-Control-Max-Age",
		"600",
	)

	return true
}

// -----------------------------------------------------------------------------
// Security headers
// -----------------------------------------------------------------------------

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set(
		"X-Content-Type-Options",
		"nosniff",
	)

	w.Header().Set(
		"X-Frame-Options",
		"DENY",
	)

	w.Header().Set(
		"Referrer-Policy",
		"no-referrer",
	)

	w.Header().Set(
		"Permissions-Policy",
		"camera=(), microphone=(), geolocation=()",
	)

	// The API returns JSON and does not need browser content sniffing.
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; frame-ancestors 'none'",
	)

	// Only activate HSTS when explicitly requested.
	//
	// This avoids breaking local HTTP development in Termux.
	if os.Getenv("EXPLOSIVE_API_HSTS") == "1" {
		w.Header().Set(
			"Strict-Transport-Security",
			"max-age=31536000; includeSubDomains",
		)
	}
}

// -----------------------------------------------------------------------------
// Endpoint classification
// -----------------------------------------------------------------------------

func isSensitiveEndpoint(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return true
	}

	switch r.URL.Path {
	case "/api/wallet/create",
		"/api/wallet/restore",
		"/api/wallet/send",
		"/api/miner/create",
		"/api/miner/restore",
		"/api/miner/mine":
		return true

	default:
		return false
	}
}

// -----------------------------------------------------------------------------
// Client IP
// -----------------------------------------------------------------------------

func requestClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	// Never blindly trust X-Forwarded-For.
	//
	// If a trusted reverse proxy is added later, this function can be adapted
	// to trust its forwarded headers explicitly.
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err == nil && host != "" {
		return host
	}

	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}

	return "unknown"
}

// -----------------------------------------------------------------------------
// Error helper
// -----------------------------------------------------------------------------

func writeSecurityError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
