package p2p

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/sha3"

	"explosive/internal/ledger"
	"explosive/internal/scan"
)

// MetricsData is canonical structure from scan package
type MetricsData = scan.MetricsData

// SignedMetrics wraps canonical metrics with a signature
type SignedMetrics struct {
	Metrics   *MetricsData `cbor:"metrics"`
	Signature []byte       `cbor:"signature"`
	NodeID    string       `cbor:"node_id"`
}

// -----------------------------------------------------------------------------
// Configuration — Mobile Safe
// -----------------------------------------------------------------------------

const (
	metricsBroadcastInterval = 30 * time.Second
)

var (
	lastBroadcastTime time.Time
	lastMetricsHash   [32]byte
	metricsLock       sync.Mutex

	// Canonical CBOR encoder (deterministic across all nodes)
	canonicalCBOR, _ = cbor.CanonicalEncOptions().EncMode()
)

// Broadcaster defines minimal broadcast capability.
type Broadcaster interface {
	BroadcastMessage(msgType string, payload any) error
}

// -----------------------------------------------------------------------------
// GatherMetrics — deterministic
// -----------------------------------------------------------------------------

func GatherMetrics(l *ledger.Ledger) (*MetricsData, error) {
	if l == nil || l.DB() == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}
	return scan.GatherMetrics(l)
}

// -----------------------------------------------------------------------------
// hashMetrics — SHA3-256 canonical
// -----------------------------------------------------------------------------

func hashMetrics(m *MetricsData) ([32]byte, error) {
	var empty [32]byte

	if m == nil {
		return empty, fmt.Errorf("nil metrics")
	}

	data, err := canonicalCBOR.Marshal(m)
	if err != nil {
		return empty, err
	}

	return sha3.Sum256(data), nil
}

// -----------------------------------------------------------------------------
// SignMetrics — deterministic CBOR signature
// -----------------------------------------------------------------------------

func SignMetrics(metrics *MetricsData, privKey ed25519.PrivateKey, nodeID string) (*SignedMetrics, error) {
	if metrics == nil {
		return nil, fmt.Errorf("metrics nil")
	}

	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key")
	}

	data, err := canonicalCBOR.Marshal(metrics)
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(privKey, data)

	return &SignedMetrics{
		Metrics:   metrics,
		Signature: signature,
		NodeID:    nodeID,
	}, nil
}

// -----------------------------------------------------------------------------
// SafeBroadcastMetrics — Deterministic + Rate Limited + Differential
// -----------------------------------------------------------------------------

func SafeBroadcastMetrics(
	l *ledger.Ledger,
	b Broadcaster,
	privKey ed25519.PrivateKey,
	nodeID string,
) {
	if l == nil || b == nil {
		return
	}

	metricsLock.Lock()

	// Rate limit protection
	if time.Since(lastBroadcastTime) < metricsBroadcastInterval {
		metricsLock.Unlock()
		return
	}

	lastBroadcastTime = time.Now()
	metricsLock.Unlock()

	go func() {

		metrics, err := GatherMetrics(l)
		if err != nil {
			return
		}

		hash, err := hashMetrics(metrics)
		if err != nil {
			return
		}

		metricsLock.Lock()

		// Differential broadcast protection
		if hash == lastMetricsHash {
			metricsLock.Unlock()
			return
		}

		lastMetricsHash = hash
		metricsLock.Unlock()

		// Sign metrics
		signedMetrics, err := SignMetrics(metrics, privKey, nodeID)
		if err != nil {
			return
		}

		// Broadcast signed metrics
		_ = b.BroadcastMessage("SIGNED_METRICS", signedMetrics)
	}()
}

// -----------------------------------------------------------------------------
// HookAfterBlock — Call After Any Chain Change
// -----------------------------------------------------------------------------

func HookAfterBlock(
	l *ledger.Ledger,
	b Broadcaster,
	privKey ed25519.PrivateKey,
	nodeID string,
) {
	SafeBroadcastMetrics(l, b, privKey, nodeID)
}
