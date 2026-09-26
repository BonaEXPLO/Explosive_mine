package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	nat4DefaultProbeTimeout = 3 * time.Second
	nat4MaxProbeCandidates  = 8
	nat4ProbeDelay          = 250 * time.Millisecond
	nat4MaxClockSkew        = 30 * time.Second
)

const (
	nat4ProbeKindRequest = "REQUEST"
	nat4ProbeKindResult  = "RESULT"
)

// NAT4ProbePayload contains public transport information used to coordinate
// a TCP connectivity attempt between two already authenticated peers.
//
// Peer identity is authenticated by the normal EXPLOSIVE envelope.
// This payload contains no wallet secret, password, mnemonic, sacred words,
// or private key material.
type NAT4ProbePayload struct {
	PeerID       string `cbor:"peer_id"`
	Kind         string `cbor:"kind"`
	TargetAddr   string `cbor:"target_addr"`
	ObservedAddr string `cbor:"observed_addr,omitempty"`
	Timestamp    int64  `cbor:"timestamp"`
	Nonce        uint64 `cbor:"nonce"`
	AttemptAt    int64  `cbor:"attempt_at"`
	Success      bool   `cbor:"success"`
	LatencyMs    int64  `cbor:"latency_ms,omitempty"`
	Error        string `cbor:"error,omitempty"`
}

// NAT4ProbeResult describes one coordinated TCP attempt.
type NAT4ProbeResult struct {
	Address   string
	Latency   time.Duration
	Success   bool
	Error     string
	StartedAt time.Time
	EndedAt   time.Time
}

// NAT4Config controls coordinated TCP probing.
type NAT4Config struct {
	ProbeTimeout time.Duration
	AttemptDelay time.Duration
}

func DefaultNAT4Config() NAT4Config {
	return NAT4Config{
		ProbeTimeout: nat4DefaultProbeTimeout,
		AttemptDelay: nat4ProbeDelay,
	}
}

func (c NAT4Config) normalize() NAT4Config {
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = nat4DefaultProbeTimeout
	}

	if c.AttemptDelay < 0 {
		c.AttemptDelay = 0
	}

	return c
}

func ValidateNAT4ProbePayload(
	payload NAT4ProbePayload,
	expectedPeerID string,
) error {

	expectedPeerID = strings.TrimSpace(expectedPeerID)

	if expectedPeerID == "" {
		return errors.New("expected peer ID is empty")
	}

	// ------------------------------------------------------------
	// PEER ID
	// ------------------------------------------------------------

	receivedPeerID := strings.TrimSpace(payload.PeerID)

	if receivedPeerID == "" {
		return errors.New("NAT4 peer ID is empty")
	}

	if receivedPeerID != expectedPeerID {
		return fmt.Errorf(
			"NAT4 peer identity mismatch: expected=%s received=%s",
			expectedPeerID,
			receivedPeerID,
		)
	}

	// ------------------------------------------------------------
	// MESSAGE KIND
	// ------------------------------------------------------------

	if payload.Kind != nat4ProbeKindRequest &&
		payload.Kind != nat4ProbeKindResult {
		return errors.New("invalid NAT4 probe kind")
	}

	// ------------------------------------------------------------
	// TARGET ADDRESS
	// ------------------------------------------------------------

	targetAddr := strings.TrimSpace(payload.TargetAddr)

	if targetAddr == "" {
		return errors.New("NAT4 target address is empty")
	}

	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf(
			"invalid NAT4 target address: %w",
			err,
		)
	}

	if strings.TrimSpace(host) == "" {
		return errors.New("NAT4 target host is empty")
	}

	var portNumber int

	if _, err := fmt.Sscanf(port, "%d", &portNumber); err != nil {
		return errors.New("invalid NAT4 target port")
	}

	if portNumber < 1 || portNumber > 65535 {
		return errors.New("invalid NAT4 target port range")
	}

	// ------------------------------------------------------------
	// TIMESTAMP
	// ------------------------------------------------------------

	if payload.Timestamp <= 0 {
		return errors.New("NAT4 timestamp is missing")
	}

	now := time.Now().UnixMilli()

	if absInt64(now-payload.Timestamp) >
		nat4MaxClockSkew.Milliseconds() {
		return errors.New(
			"NAT4 timestamp outside allowed clock skew",
		)
	}

	// ------------------------------------------------------------
	// NONCE
	// ------------------------------------------------------------

	if payload.Nonce == 0 {
		return errors.New("NAT4 nonce is missing")
	}

	// ------------------------------------------------------------
	// REQUEST-SPECIFIC VALIDATION
	// ------------------------------------------------------------

	if payload.Kind == nat4ProbeKindRequest {

		if payload.AttemptAt <= 0 {
			return errors.New(
				"NAT4 attempt time is missing",
			)
		}

		if payload.AttemptAt < now-nat4MaxClockSkew.Milliseconds() ||
			payload.AttemptAt > now+nat4MaxClockSkew.Milliseconds() {
			return errors.New(
				"NAT4 attempt time outside allowed clock skew",
			)
		}
	}

	// ------------------------------------------------------------
	// RESULT-SPECIFIC VALIDATION
	// ------------------------------------------------------------

	if payload.Kind == nat4ProbeKindResult {

		if payload.AttemptAt < 0 {
			return errors.New(
				"NAT4 result contains invalid attempt time",
			)
		}

		if payload.LatencyMs < 0 {
			return errors.New(
				"NAT4 result contains invalid latency",
			)
		}

		if !payload.Success &&
			strings.TrimSpace(payload.Error) == "" {
			return errors.New(
				"NAT4 failed result must contain an error",
			)
		}
	}

	return nil
}

// NAT4DialCandidate performs one TCP connection attempt.
//
// This function only measures transport connectivity. It does not replace
// the authenticated EXPLOSIVE session and does not establish peer identity.
func NAT4DialCandidate(
	ctx context.Context,
	address string,
	timeout time.Duration,
) NAT4ProbeResult {

	result := NAT4ProbeResult{
		Address:   strings.TrimSpace(address),
		StartedAt: time.Now(),
	}

	if result.Address == "" {
		result.Error = "empty NAT4 address"
		result.EndedAt = time.Now()
		return result
	}

	if timeout <= 0 {
		timeout = nat4DefaultProbeTimeout
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	var dialer net.Dialer

	conn, err := dialer.DialContext(
		probeCtx,
		"tcp",
		result.Address,
	)

	result.Latency = time.Since(start)
	result.EndedAt = time.Now()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	_ = conn.Close()

	result.Success = true

	return result
}

// NAT4Coordinator prevents duplicate coordinated attempts for the same peer.
type NAT4Coordinator struct {
	mu      sync.Mutex
	pending map[string]time.Time
}

func NewNAT4Coordinator() *NAT4Coordinator {
	return &NAT4Coordinator{
		pending: make(map[string]time.Time),
	}
}

func (c *NAT4Coordinator) begin(peerID string) bool {
	if c == nil {
		return false
	}

	peerID = strings.TrimSpace(peerID)

	if peerID == "" {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.pending[peerID]; exists {
		return false
	}

	c.pending[peerID] = time.Now()

	return true
}

func (c *NAT4Coordinator) end(peerID string) {
	if c == nil {
		return
	}

	c.mu.Lock()
	delete(c.pending, strings.TrimSpace(peerID))
	c.mu.Unlock()
}
