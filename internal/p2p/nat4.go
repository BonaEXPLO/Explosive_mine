package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
        "log"
	"strings"
	"sync"
	"time"
        "github.com/fxamacker/cbor/v2"
)

const (
	nat4DefaultProbeTimeout = 3 * time.Second
	nat4MaxProbeCandidates  = 8
	nat4ProbeDelay          = 250 * time.Millisecond
	nat4MaxClockSkew        = 30 * time.Second

	nat4TraversalTimeout = 12 * time.Second
	nat4StartLeadTime    = 1200 * time.Millisecond
)

const (
	nat4ProbeKindRequest = "REQUEST"
	nat4ProbeKindResult  = "RESULT"

	nat4TCPModeActive  = "ACTIVE"
	nat4TCPModePassive = "PASSIVE"
	nat4TCPModeSO      = "S-O"
)

const (
	nat4TraversalStatusConnected   = "DIRECT_CONNECTED"
	nat4TraversalStatusFailed      = "NAT_TRAVERSAL_FAILED"
	nat4TraversalStatusUnsupported = "NAT_TRAVERSAL_UNSUPPORTED"
	nat4TraversalStatusInvalid     = "NAT_TRAVERSAL_INVALID"
	nat4TraversalStatusExpired     = "NAT_TRAVERSAL_EXPIRED"
)

const (
	nat4TraversalKindRequest = "TRAVERSAL_REQUEST"
	nat4TraversalKindResult  = "TRAVERSAL_RESULT"
)

// -----------------------------------------------------------------------------
// PROBE
// -----------------------------------------------------------------------------

// NAT4ProbePayload contains public transport information used to coordinate
// a TCP connectivity attempt between two already authenticated peers.
//
// Peer identity is authenticated by the normal EXPLOSIVE envelope.
//
// No wallet secret, password, mnemonic, sacred word or private key is
// transported here.
type NAT4ProbePayload struct {
	PeerID       string `cbor:"peer_id"`
	Kind         string `cbor:"kind"`
	TargetAddr   string `cbor:"target_addr"`
	ObservedAddr string `cbor:"observed_addr,omitempty"`

	Timestamp int64  `cbor:"timestamp"`
	Nonce     uint64 `cbor:"nonce"`
	AttemptAt int64  `cbor:"attempt_at"`

	Success   bool   `cbor:"success"`
	LatencyMs int64  `cbor:"latency_ms,omitempty"`
	Error     string `cbor:"error,omitempty"`
}

// -----------------------------------------------------------------------------
// TRAVERSAL
// -----------------------------------------------------------------------------

// NAT4TraversalPayload coordinates a direct traversal attempt.
//
// Both peers use the same SessionID and coordinated StartAt value.
//
// IMPORTANT:
//
// This payload coordinates the attempt. It does not itself guarantee that
// the underlying mobile carrier NAT supports TCP simultaneous-open.
type NAT4TraversalPayload struct {
	PeerID    string `cbor:"peer_id"`
	SessionID uint64 `cbor:"session_id"`
	Kind      string `cbor:"kind"`

	LocalAddr  string `cbor:"local_addr"`
	RemoteAddr string `cbor:"remote_addr"`

	TCPMode string `cbor:"tcp_mode"`

	StartAt   int64  `cbor:"start_at"`
	Timestamp int64  `cbor:"timestamp"`
	Nonce     uint64 `cbor:"nonce"`

	Success   bool   `cbor:"success"`
	LatencyMs int64  `cbor:"latency_ms,omitempty"`
	Status    string `cbor:"status,omitempty"`
	Error     string `cbor:"error,omitempty"`
}

// -----------------------------------------------------------------------------
// RESULTS
// -----------------------------------------------------------------------------

type NAT4ProbeResult struct {
	Address   string
	Latency   time.Duration
	Success   bool
	Error     string
	StartedAt time.Time
	EndedAt   time.Time
}

type NAT4TraversalResult struct {
	SessionID  uint64
	LocalAddr  string
	RemoteAddr string

	Conn    net.Conn
	Latency time.Duration

	Status string
	Error  string

	StartedAt time.Time
	EndedAt   time.Time
}

// -----------------------------------------------------------------------------
// CONFIGURATION
// -----------------------------------------------------------------------------

type NAT4Config struct {
	ProbeTimeout     time.Duration
	AttemptDelay     time.Duration
	TraversalTimeout time.Duration
	StartLeadTime    time.Duration
}

func DefaultNAT4Config() NAT4Config {
	return NAT4Config{
		ProbeTimeout:     nat4DefaultProbeTimeout,
		AttemptDelay:     nat4ProbeDelay,
		TraversalTimeout: nat4TraversalTimeout,
		StartLeadTime:    nat4StartLeadTime,
	}
}

func (c NAT4Config) normalize() NAT4Config {
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = nat4DefaultProbeTimeout
	}

	if c.AttemptDelay < 0 {
		c.AttemptDelay = 0
	}

	if c.TraversalTimeout <= 0 {
		c.TraversalTimeout = nat4TraversalTimeout
	}

	if c.StartLeadTime <= 0 {
		c.StartLeadTime = nat4StartLeadTime
	}

	return c
}

// -----------------------------------------------------------------------------
// RANDOM IDENTIFIERS
// -----------------------------------------------------------------------------

func generateNAT4SessionID() uint64 {
	var b [8]byte

	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely fallback.
		id := uint64(time.Now().UnixNano())

		if id == 0 {
			return 1
		}

		return id
	}

	id := binary.BigEndian.Uint64(b[:])

	if id == 0 {
		return 1
	}

	return id
}

func generateNAT4Nonce() uint64 {
	return generateNAT4SessionID()
}

// -----------------------------------------------------------------------------
// ADDRESS VALIDATION
// -----------------------------------------------------------------------------

func validateNAT4Addr(address string) error {
	address = strings.TrimSpace(address)

	if address == "" {
		return errors.New("empty address")
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", address, err)
	}

	host = strings.TrimSpace(host)

	if host == "" {
		return errors.New("address host is empty")
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range: %d", port)
	}

	// Do not require ParseIP here.
	//
	// A future transport implementation may allow DNS names.
	// For the current mobile P2P path, actual TCP dialing remains
	// responsible for determining reachability.

	return nil
}

func parseNAT4TCPAddr(address string) (*net.TCPAddr, error) {
	address = strings.TrimSpace(address)

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP address: %w", err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP port: %w", err)
	}

	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("TCP port out of range: %d", port)
	}

	ip := net.ParseIP(host)

	if ip == nil {
		return nil, fmt.Errorf(
			"host %q is not a literal IP address",
			host,
		)
	}

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// -----------------------------------------------------------------------------
// PROBE VALIDATION
// -----------------------------------------------------------------------------

func ValidateNAT4ProbePayload(
	payload NAT4ProbePayload,
	expectedPeerID string,
) error {

	expectedPeerID = strings.TrimSpace(expectedPeerID)

	if expectedPeerID == "" {
		return errors.New("expected peer ID is empty")
	}

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

	if payload.Kind != nat4ProbeKindRequest &&
		payload.Kind != nat4ProbeKindResult {
		return errors.New("invalid NAT4 probe kind")
	}

	if err := validateNAT4Addr(payload.TargetAddr); err != nil {
		return fmt.Errorf(
			"invalid NAT4 target address: %w",
			err,
		)
	}

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

	if payload.Nonce == 0 {
		return errors.New("NAT4 nonce is missing")
	}

	if payload.Kind == nat4ProbeKindRequest {

		if payload.AttemptAt <= 0 {
			return errors.New(
				"NAT4 attempt time is missing",
			)
		}

		if absInt64(now-payload.AttemptAt) >
			nat4MaxClockSkew.Milliseconds() {
			return errors.New(
				"NAT4 attempt time outside allowed clock skew",
			)
		}
	}

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

// -----------------------------------------------------------------------------
// TRAVERSAL VALIDATION
// -----------------------------------------------------------------------------

func ValidateNAT4TraversalPayload(
	payload NAT4TraversalPayload,
	expectedPeerID string,
) error {

	expectedPeerID = strings.TrimSpace(expectedPeerID)

	if expectedPeerID == "" {
		return errors.New(
			"expected NAT4 traversal peer ID is empty",
		)
	}

	if strings.TrimSpace(payload.PeerID) != expectedPeerID {
		return errors.New(
			"NAT4 traversal peer identity mismatch",
		)
	}

	if payload.SessionID == 0 {
		return errors.New(
			"NAT4 traversal session ID is missing",
		)
	}

	switch payload.Kind {
	case nat4TraversalKindRequest:
	case nat4TraversalKindResult:
	default:
		return errors.New(
			"invalid NAT4 traversal message kind",
		)
	}

	switch payload.TCPMode {
	case nat4TCPModeActive:
	case nat4TCPModePassive:
	case nat4TCPModeSO:
	default:
		return errors.New(
			"invalid NAT4 TCP mode",
		)
	}

	if err := validateNAT4Addr(payload.LocalAddr); err != nil {
		return fmt.Errorf(
			"invalid NAT4 traversal local address: %w",
			err,
		)
	}

	if err := validateNAT4Addr(payload.RemoteAddr); err != nil {
		return fmt.Errorf(
			"invalid NAT4 traversal remote address: %w",
			err,
		)
	}

	if payload.StartAt <= 0 {
		return errors.New(
			"NAT4 traversal start time is missing",
		)
	}

	if payload.Timestamp <= 0 {
		return errors.New(
			"NAT4 traversal timestamp is missing",
		)
	}

	if payload.Nonce == 0 {
		return errors.New(
			"NAT4 traversal nonce is missing",
		)
	}

	now := time.Now().UnixMilli()

	if absInt64(now-payload.Timestamp) >
		nat4MaxClockSkew.Milliseconds() {
		return errors.New(
			"NAT4 traversal timestamp outside allowed clock skew",
		)
	}

	// A traversal should not remain pending for minutes/hours.
	if payload.StartAt <
		now-(nat4TraversalTimeout+nat4MaxClockSkew).Milliseconds() {

		return errors.New(
			"NAT4 traversal start time expired",
		)
	}

	if payload.StartAt >
		now+(nat4TraversalTimeout+nat4MaxClockSkew).Milliseconds() {

		return errors.New(
			"NAT4 traversal start time is too far in the future",
		)
	}

	if payload.Kind == nat4TraversalKindResult {

		if payload.LatencyMs < 0 {
			return errors.New(
				"NAT4 traversal result contains invalid latency",
			)
		}

		if strings.TrimSpace(payload.Status) == "" {
			return errors.New(
				"NAT4 traversal result status is missing",
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// NORMAL TCP CONNECTIVITY
// -----------------------------------------------------------------------------

// NAT4DialCandidate performs one ordinary TCP connectivity attempt.
//
// This is deliberately separate from simultaneous-open.
//
// It is useful for:
//   - IPv4 direct candidates
//   - IPv6 direct candidates
//   - reflexive candidates
//   - previously learned peer locators
//   - NAT2/NAT4 diagnostics
func NAT4DialCandidate(
	ctx context.Context,
	address string,
	timeout time.Duration,
) NAT4ProbeResult {

	result := NAT4ProbeResult{
		Address:   strings.TrimSpace(address),
		StartedAt: time.Now(),
	}

	if err := validateNAT4Addr(result.Address); err != nil {
		result.Error = err.Error()
		result.EndedAt = time.Now()
		return result
	}

	if timeout <= 0 {
		timeout = nat4DefaultProbeTimeout
	}

	if ctx == nil {
		ctx = context.Background()
	}

	probeCtx, cancel := context.WithTimeout(
		ctx,
		timeout,
	)
	defer cancel()

	start := time.Now()

	dialer := net.Dialer{}

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

// -----------------------------------------------------------------------------
// COORDINATED TCP ATTEMPT
// -----------------------------------------------------------------------------

// NAT4CoordinatedDial performs a coordinated direct TCP attempt.
//
// IMPORTANT:
//
// This implementation provides a portable Go-level coordinated TCP attempt.
//
// It does NOT claim that every Android/mobile carrier supports TCP
// simultaneous-open.
//
// If the operating system/network cannot establish the requested local
// binding, the result is reported as UNSUPPORTED/FAILED and the caller
// should continue with the next candidate or relay.
//
// This is intentional: false "worldwide success" would be dangerous for
// the P2P state machine.
func NAT4CoordinatedDial(
	ctx context.Context,
	localAddr string,
	remoteAddr string,
	startAt time.Time,
	timeout time.Duration,
) NAT4TraversalResult {

	result := NAT4TraversalResult{
		LocalAddr:  strings.TrimSpace(localAddr),
		RemoteAddr: strings.TrimSpace(remoteAddr),
		Status:     nat4TraversalStatusFailed,
		StartedAt:  time.Now(),
	}

	if err := validateNAT4Addr(result.LocalAddr); err != nil {
		result.Status = nat4TraversalStatusInvalid
		result.Error = fmt.Sprintf(
			"invalid local traversal address: %v",
			err,
		)
		result.EndedAt = time.Now()
		return result
	}

	if err := validateNAT4Addr(result.RemoteAddr); err != nil {
		result.Status = nat4TraversalStatusInvalid
		result.Error = fmt.Sprintf(
			"invalid remote traversal address: %v",
			err,
		)
		result.EndedAt = time.Now()
		return result
	}

	localTCP, err := parseNAT4TCPAddr(result.LocalAddr)
	if err != nil {
		result.Status = nat4TraversalStatusUnsupported
		result.Error = err.Error()
		result.EndedAt = time.Now()
		return result
	}

	if _, err := parseNAT4TCPAddr(result.RemoteAddr); err != nil {
		result.Status = nat4TraversalStatusUnsupported
		result.Error = err.Error()
		result.EndedAt = time.Now()
		return result
	}

	if timeout <= 0 {
		timeout = nat4TraversalTimeout
	}

	if ctx == nil {
		ctx = context.Background()
	}

	traversalCtx, cancel := context.WithTimeout(
		ctx,
		timeout,
	)
	defer cancel()

	// ------------------------------------------------------------------
	// COORDINATED START
	// ------------------------------------------------------------------

	wait := time.Until(startAt)

	if wait > 0 {

		timer := time.NewTimer(wait)

		select {

		case <-traversalCtx.Done():

			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			result.Status = nat4TraversalStatusFailed
			result.Error = traversalCtx.Err().Error()
			result.EndedAt = time.Now()

			return result

		case <-timer.C:
		}
	}

	// ------------------------------------------------------------------
	// LOCAL SOCKET
	// ------------------------------------------------------------------
	//
	// IMPORTANT:
	//
	// We preserve the complete local IP + port.
	//
	// This is required for any future platform-specific simultaneous-open
	// implementation and avoids the old IPv6/string-splitting bug.
	// ------------------------------------------------------------------

	dialer := net.Dialer{
		LocalAddr: localTCP,
		Timeout:   timeout,
	}

	start := time.Now()

	conn, err := dialer.DialContext(
		traversalCtx,
		"tcp",
		result.RemoteAddr,
	)

	result.Latency = time.Since(start)
	result.EndedAt = time.Now()

	if err != nil {

		if errors.Is(
			err,
			context.DeadlineExceeded,
		) {
			result.Status = nat4TraversalStatusFailed
		}

		result.Error = err.Error()

		return result
	}

	result.Conn = conn
	result.Status = nat4TraversalStatusConnected

	return result
}

// -----------------------------------------------------------------------------
// COORDINATOR
// -----------------------------------------------------------------------------

type NAT4Coordinator struct {
	mu      sync.Mutex
	pending map[string]time.Time
	results map[uint64]chan NAT4TraversalResult
}

func NewNAT4Coordinator() *NAT4Coordinator {
	return &NAT4Coordinator{
		pending: make(map[string]time.Time),
		results: make(map[uint64]chan NAT4TraversalResult),
	}
}

// begin prevents duplicate traversal attempts for the same peer.
//
// The peer identity is permanent. The coordinator uses the PeerID only
// to prevent concurrent NAT4 attempts for the same authenticated peer.
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

	now := time.Now()

	for id, started := range c.pending {
		if now.Sub(started) >
			nat4TraversalTimeout+nat4MaxClockSkew {
			delete(c.pending, id)
		}
	}

	if _, exists := c.pending[peerID]; exists {
		return false
	}

	c.pending[peerID] = now
	return true
}

func (c *NAT4Coordinator) end(peerID string) {
	if c == nil {
		return
	}

	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return
	}

	c.mu.Lock()
	delete(c.pending, peerID)
	c.mu.Unlock()
}

// registerResult creates a result channel for one NAT4 traversal session.
//
// SessionID is temporary transport state. It never represents peer identity.
func (c *NAT4Coordinator) registerResult(sessionID uint64) (<-chan NAT4TraversalResult, error) {
	if c == nil {
		return nil, errors.New("nil NAT4 coordinator")
	}

	if sessionID == 0 {
		return nil, errors.New("invalid NAT4 session ID")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.results[sessionID]; exists {
		return nil, errors.New("NAT4 session ID already registered")
	}

	ch := make(chan NAT4TraversalResult, 1)
	c.results[sessionID] = ch

	return ch, nil
}

// resolveResult delivers a traversal result to the exact waiting session.
func (c *NAT4Coordinator) resolveResult(sessionID uint64, result NAT4TraversalResult) bool {
	if c == nil || sessionID == 0 {
		return false
	}

	c.mu.Lock()

	ch, exists := c.results[sessionID]
	if exists {
		delete(c.results, sessionID)
	}

	c.mu.Unlock()

	if !exists {
		return false
	}

	select {
	case ch <- result:
	default:
	}

	return true
}

// cancelResult removes a pending traversal result channel.
func (c *NAT4Coordinator) cancelResult(sessionID uint64) {
	if c == nil || sessionID == 0 {
		return
	}

	c.mu.Lock()
	delete(c.results, sessionID)
	c.mu.Unlock()
}

// NAT4LocalCandidate selects a locally bindable candidate for TCP traversal.
//
// Only addresses actually owned by the local device are eligible as
// net.Dialer.LocalAddr. Reflexive and relay candidates are never used
// as LocalAddr because they are transport locators, not local interfaces.
func NAT4LocalCandidate(candidates []NATCandidate) (NATCandidate, error) {
	if len(candidates) == 0 {
		return NATCandidate{}, errors.New("no local NAT4 candidates available")
	}

	var best NATCandidate

	for _, candidate := range candidates {
		if !candidate.IsValid() {
			continue
		}

		switch candidate.Type {
		case NATCandidateLAN:
			if best.Type == 0 || best.Type != NATCandidateLAN {
				best = candidate
			}

		case NATCandidatePrivateIPv4:
			if best.Type == 0 {
				best = candidate
			}

		case NATCandidateIPv6:
			if best.Type == 0 {
				best = candidate
			}

		default:
			// Reflexive and relay candidates must never be bound locally.
			continue
		}
	}

	if !best.IsValid() {
		return NATCandidate{}, errors.New("no bindable local NAT4 candidate available")
	}

	return best, nil
}

// StartNAT4Traversal starts one coordinated NAT4 TCP traversal attempt.
//
// The authenticated Peer remains the sovereign session authority.
// NAT4 only coordinates a temporary transport attempt.
//
// PeerID is never replaced by an IP address, port, SessionID,
// NAT candidate, or network connection.
func (n *Node) StartNAT4Traversal(p *Peer) error {
	if n == nil {
		return errors.New("nil P2P node")
	}
	if p == nil {
		return errors.New("nil authenticated peer")
	}
	if !p.handshakeDone {
		return errors.New("NAT4 requires completed EXPLOSIVE handshake")
	}

	remotePeerID := strings.TrimSpace(string(p.ID()))
	if remotePeerID == "" {
		return errors.New("authenticated peer has no PeerID")
	}

	if n.nat4Coordinator == nil {
		return errors.New("NAT4 coordinator is not initialized")
	}

	if !n.nat4Coordinator.begin(remotePeerID) {
		return errors.New("NAT4 traversal already active for peer")
	}
	defer n.nat4Coordinator.end(remotePeerID)

	// ------------------------------------------------------------
	// 1. SELECT LOCAL BINDABLE CANDIDATE
	// ------------------------------------------------------------

	localCandidates := n.NATCandidates()

	localCandidate, err := NAT4LocalCandidate(localCandidates)
	if err != nil {
		return err
	}

	// ------------------------------------------------------------
	// 2. SELECT REMOTE TRANSPORT CANDIDATE
	// ------------------------------------------------------------

	remoteCandidates := p.RemoteNATCandidates()
	if len(remoteCandidates) == 0 {
		return errors.New(
			"authenticated peer has no remote NAT4 candidates",
		)
	}

	var remoteCandidate NATCandidate

	// NAT4 must only use remote candidates that represent
	// an explicitly usable TCP endpoint.
	//
	// Reflexive candidates are intentionally excluded here.
	// A STUN UDP observation does not prove that the same
	// public address and port are valid for TCP.
	//
	// Relay candidates are also excluded because NAT4 is a
	// direct TCP traversal mechanism. Relay fallback remains
	// under the existing Peer transport mechanisms.

	for _, candidate := range remoteCandidates {
		if !candidate.IsValid() {
			continue
		}

		switch candidate.Type {
		case NATCandidateLAN,
			NATCandidatePrivateIPv4,
			NATCandidateIPv6:

			remoteCandidate = candidate

		default:
			continue
		}

		if remoteCandidate.IsValid() {
			break
		}
	}

	if !remoteCandidate.IsValid() {
		return errors.New(
			"no direct remote NAT4 candidate available",
		)
	}

	localAddr := localCandidate.Addr()
	remoteAddr := remoteCandidate.Addr()

	if localAddr == "" || remoteAddr == "" {
		return errors.New("invalid NAT4 candidate addresses")
	}

	// ------------------------------------------------------------
	// 3. CREATE TEMPORARY NAT4 SESSION
	// ------------------------------------------------------------

	sessionID := secureRelayNonce()
	if sessionID == 0 {
		return errors.New("failed to generate NAT4 session ID")
	}

	resultCh, err := n.nat4Coordinator.registerResult(sessionID)
	if err != nil {
		return err
	}
	defer n.nat4Coordinator.cancelResult(sessionID)

	startTime := time.Now().Add(nat4StartLeadTime)
	startAt := startTime.UnixMilli()

	localPeerID := strings.TrimSpace(n.walletAddress)
	if localPeerID == "" {
		return errors.New("local wallet PeerID is not initialized")
	}

	request := NAT4TraversalPayload{
		PeerID:     localPeerID,
		SessionID:  sessionID,
		Kind:       nat4TraversalKindRequest,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		TCPMode:    nat4TCPModeSO,
		StartAt:    startAt,
		Timestamp:  time.Now().UnixMilli(),
		Nonce:      secureRelayNonce(),
		Success:    false,
		Status:     "",
	}

	// ------------------------------------------------------------
	// 4. SEND AUTHENTICATED TRAVERSAL REQUEST
	// ------------------------------------------------------------

	payload, err := cbor.Marshal(request)
	if err != nil {
		return fmt.Errorf(
			"encode NAT4 traversal request: %w",
			err,
		)
	}

	env, err := NewEnvelopeFromPayload(
		n.ProtocolVersion(),
		MsgTypeNAT4Traversal,
		payload,
	)
	if err != nil {
		return fmt.Errorf(
			"create NAT4 traversal envelope: %w",
			err,
		)
	}

	if err := p.SendEnvelope(env); err != nil {
		return fmt.Errorf(
			"send NAT4 traversal request: %w",
			err,
		)
	}

	log.Printf(
		"[p2p] NAT4 traversal started peer=%s session=%d local=%s remote=%s start_at=%d",
		remotePeerID,
		sessionID,
		localAddr,
		remoteAddr,
		startAt,
	)

	// ------------------------------------------------------------
	// 5. COORDINATED LOCAL TCP ATTEMPT
	// ------------------------------------------------------------

	ctx, cancel := context.WithTimeout(
		p.ctx,
		nat4TraversalTimeout,
	)
	defer cancel()

	localResultCh := make(chan NAT4TraversalResult, 1)

	go func() {
		result := NAT4CoordinatedDial(
			ctx,
			localAddr,
			remoteAddr,
			startTime,
			nat4TraversalTimeout,
		)

		select {
		case localResultCh <- result:
		default:
		}
	}()

	// ------------------------------------------------------------
	// 6. LOCAL TCP RESULT IS AUTHORITATIVE FOR THIS SIDE
	// ------------------------------------------------------------

	select {
	case localResult := <-localResultCh:

		if localResult.Conn != nil &&
			localResult.Status == nat4TraversalStatusConnected {

			newPeer := NewPeer(
				"",
				remoteAddr,
				n,
			)

			// Permanent identity remains the authenticated remote
			// PeerID. This field is only a transport/reconnect hint.
			newPeer.targetPeerID = p.ID()

			if err := newPeer.adoptNAT4Conn(
				localResult.Conn,
			); err != nil {
				return fmt.Errorf(
					"NAT4 TCP connected but Peer adoption failed: %w",
					err,
				)
			}

			log.Printf(
				"[p2p] NAT4 local TCP connected peer=%s session=%d remote=%s",
				remotePeerID,
				sessionID,
				remoteAddr,
			)

			// The new Peer now owns the connection.
			// NAT4 must not manipulate it anymore.
			return nil
		}

		// Local attempt failed. The remote result can still tell us
		// whether the other side reached its own TCP attempt.
		select {
		case remoteResult := <-resultCh:

			if remoteResult.Error != "" {
				return fmt.Errorf(
					"NAT4 traversal failed: %s",
					remoteResult.Error,
				)
			}

			return fmt.Errorf(
				"NAT4 traversal failed: status=%s",
				remoteResult.Status,
			)

		case <-ctx.Done():
			return fmt.Errorf(
				"NAT4 traversal failed for peer %s",
				remotePeerID,
			)
		}

	case <-ctx.Done():
		return fmt.Errorf(
			"NAT4 traversal timeout for peer %s",
			remotePeerID,
		)
	}
}
