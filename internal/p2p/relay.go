package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"explosive/internal/address"
	"github.com/fxamacker/cbor/v2"
)

const (
	// EXPLOSIVE relay protocol version.
	relayProtocolVersion uint16 = 1

	// Domain separator used for relay authentication signatures.
	relayAuthDomain = "EXPLOSIVE-RELAY-V1"

	// Maximum encoded relay frame size.
	relayMaxFrameSize = 4 * 1024 * 1024

	// Maximum opaque P2P payload transported through the relay.
	relayMaxDataSize = 4 * 1024 * 1024

	// Relay authentication must be recent.
	relayMaxClockSkew = 2 * time.Minute

	// Relay session idle timeout.
	relayIdleTimeout = 5 * time.Minute

	// Relay authentication timeout.
	relayAuthTimeout = 10 * time.Second

	// Maximum authenticated sessions.
	relayDefaultMaxSessions = 10000

	// Maximum queued outbound relay frames per session.
	relayDataQueueSize = 256
)

// ============================================================
// RELAY MESSAGE TYPES
// ============================================================

type relayMessageType uint8

const (
	relayMsgHello relayMessageType = iota + 1
	relayMsgHelloAck
	relayMsgOpen
	relayMsgOpenAck
	relayMsgOpenReject
	relayMsgData
	relayMsgClose
	relayMsgPing
	relayMsgPong
)

// relayFrame is the control protocol used between a node
// and a relay server.
//
// Payload is opaque when Type == relayMsgData.
// The relay never decodes EXPLOSIVE Envelope data.
type relayFrame struct {
	Version uint16           `cbor:"version"`
	Type    relayMessageType `cbor:"type"`

	SourcePeerID string `cbor:"source_peer_id,omitempty"`
	TargetPeerID string `cbor:"target_peer_id,omitempty"`

	Timestamp int64  `cbor:"timestamp"`
	Nonce     uint64 `cbor:"nonce"`

	Payload []byte `cbor:"payload,omitempty"`

	PubKey    []byte `cbor:"pub_key,omitempty"`
	Signature []byte `cbor:"signature,omitempty"`

	Error string `cbor:"error,omitempty"`
}

// ============================================================
// RELAY AUTHENTICATION
// ============================================================

// relayAuthPayload is what the node signs.
//
// The signature itself is intentionally excluded.
type relayAuthPayload struct {
	Domain    string `cbor:"domain"`
	Version   uint16 `cbor:"version"`
	PeerID    string `cbor:"peer_id"`
	Timestamp int64  `cbor:"timestamp"`
	Nonce     uint64 `cbor:"nonce"`
}

// buildRelayAuthMessage creates the exact bytes signed by a node.
func buildRelayAuthMessage(
	peerID string,
	timestamp int64,
	nonce uint64,
) ([]byte, error) {

	if peerID == "" {
		return nil, errors.New("empty relay peer ID")
	}

	if timestamp == 0 {
		return nil, errors.New("missing relay authentication timestamp")
	}

	if nonce == 0 {
		return nil, errors.New("missing relay authentication nonce")
	}

	payload := relayAuthPayload{
		Domain:    relayAuthDomain,
		Version:   relayProtocolVersion,
		PeerID:    peerID,
		Timestamp: timestamp,
		Nonce:     nonce,
	}

	return cbor.Marshal(payload)
}

// ============================================================
// RELAY SESSION
// ============================================================

type relaySession struct {
	peerID string

	conn net.Conn

	// sendQ contains already encoded relay frames.
	//
	// A single writer goroutine must consume this queue.
	// This prevents concurrent writes to the same TCP/TLS connection.
	sendQ chan []byte

	ctx    context.Context
	cancel context.CancelFunc

	lastSeenMu sync.RWMutex
	lastSeen   time.Time

	nonceMu sync.Mutex
	nonces  map[uint64]time.Time

	// Protects direct writes performed by exceptional control paths.
	writeMu sync.Mutex

	closeOnce sync.Once
}

func newRelaySession(
	parent context.Context,
	peerID string,
	conn net.Conn,
) *relaySession {

	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)

	return &relaySession{
		peerID:   peerID,
		conn:     conn,
		sendQ:    make(chan []byte, relayDataQueueSize),
		ctx:      ctx,
		cancel:   cancel,
		lastSeen: time.Now(),
		nonces:   make(map[uint64]time.Time),
	}
}

func (s *relaySession) touch() {
	if s == nil {
		return
	}

	s.lastSeenMu.Lock()
	s.lastSeen = time.Now()
	s.lastSeenMu.Unlock()
}

func (s *relaySession) idleFor() time.Duration {
	if s == nil {
		return relayIdleTimeout + time.Second
	}

	s.lastSeenMu.RLock()
	last := s.lastSeen
	s.lastSeenMu.RUnlock()

	if last.IsZero() {
		return relayIdleTimeout + time.Second
	}

	return time.Since(last)
}

// acceptNonce provides per-session replay protection.
//
// Nonces are scoped to the authenticated relay session.
// Old nonce entries are periodically removed.
func (s *relaySession) acceptNonce(nonce uint64) bool {
	if s == nil || nonce == 0 {
		return false
	}

	now := time.Now()

	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()

	for value, timestamp := range s.nonces {
		if now.Sub(timestamp) > relayMaxClockSkew {
			delete(s.nonces, value)
		}
	}

	if _, exists := s.nonces[nonce]; exists {
		return false
	}

	s.nonces[nonce] = now

	return true
}

// writeDirect performs one serialized direct frame write.
//
// Normal relay traffic should use sendQ and the dedicated writer
// goroutine. This method is reserved for exceptional paths such
// as authentication rejection before the normal writer exists.
func (s *relaySession) writeDirect(frame relayFrame) error {
	if s == nil {
		return errors.New("nil relay session")
	}

	if s.conn == nil {
		return errors.New("relay session connection is nil")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return writeRelayFrame(s.conn, frame)
}

func (s *relaySession) close() {
	if s == nil {
		return
	}

	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}

		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

// ============================================================
// RELAY REGISTRY
// ============================================================

// RelayRegistry maps authenticated PeerIDs to relay sessions.
//
// PeerID is the identity.
// IP address and TCP port are only transport locators.
type RelayRegistry struct {
	mu sync.RWMutex

	sessions map[string]*relaySession

	maxSessions int
}

func NewRelayRegistry(maxSessions int) *RelayRegistry {
	if maxSessions <= 0 {
		maxSessions = relayDefaultMaxSessions
	}

	return &RelayRegistry{
		sessions:    make(map[string]*relaySession),
		maxSessions: maxSessions,
	}
}

func (r *RelayRegistry) Count() int {
	if r == nil {
		return 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.sessions)
}

func (r *RelayRegistry) Get(
	peerID string,
) (*relaySession, bool) {

	if r == nil || peerID == "" {
		return nil, false
	}

	r.mu.RLock()
	session, ok := r.sessions[peerID]
	r.mu.RUnlock()

	return session, ok
}

func (r *RelayRegistry) Add(
	session *relaySession,
) error {

	if r == nil {
		return errors.New("nil relay registry")
	}

	if session == nil {
		return errors.New("nil relay session")
	}

	if session.peerID == "" {
		return errors.New("empty relay peer ID")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.sessions) >= r.maxSessions {
		if _, exists := r.sessions[session.peerID]; !exists {
			return errors.New("relay session capacity reached")
		}
	}

	old := r.sessions[session.peerID]

	r.sessions[session.peerID] = session

	// Only the old session is closed.
	// The new authenticated session remains authoritative.
	if old != nil && old != session {
		go old.close()
	}

	return nil
}

func (r *RelayRegistry) Remove(
	peerID string,
	session *relaySession,
) {
	if r == nil || peerID == "" {
		return
	}

	r.mu.Lock()

	current, exists := r.sessions[peerID]

	if exists &&
		(session == nil || current == session) {

		delete(r.sessions, peerID)
	}

	r.mu.Unlock()
}

// ============================================================
// RELAY WIRE FRAMING
// ============================================================

// writeRelayFrame writes:
//
//	4-byte big-endian frame length
//	CBOR relayFrame
//
// The length protects the receiver from unbounded allocations.
func writeRelayFrame(
	w io.Writer,
	frame relayFrame,
) error {

	if w == nil {
		return errors.New("nil relay writer")
	}

	if frame.Version == 0 {
		frame.Version = relayProtocolVersion
	}

	if err := validateRelayFrameForWrite(frame); err != nil {
		return err
	}

	payload, err := cbor.Marshal(frame)
	if err != nil {
		return fmt.Errorf(
			"relay frame encode failed: %w",
			err,
		)
	}

	if len(payload) == 0 {
		return errors.New("empty encoded relay frame")
	}

	if len(payload) > relayMaxFrameSize {
		return fmt.Errorf(
			"relay frame size exceeds maximum: %d > %d",
			len(payload),
			relayMaxFrameSize,
		)
	}

	var header [4]byte

	binary.BigEndian.PutUint32(
		header[:],
		uint32(len(payload)),
	)

	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf(
			"relay frame header write failed: %w",
			err,
		)
	}

	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf(
			"relay frame payload write failed: %w",
			err,
		)
	}

	return nil
}

func readRelayFrame(
	r io.Reader,
	maxSize int,
) (relayFrame, error) {

	if r == nil {
		return relayFrame{}, errors.New(
			"nil relay reader",
		)
	}

	if maxSize <= 0 ||
		maxSize > relayMaxFrameSize {

		maxSize = relayMaxFrameSize
	}

	var header [4]byte

	if _, err := io.ReadFull(
		r,
		header[:],
	); err != nil {
		return relayFrame{}, err
	}

	size := binary.BigEndian.Uint32(
		header[:],
	)

	if size == 0 {
		return relayFrame{}, errors.New(
			"empty relay frame",
		)
	}

	if size > uint32(maxSize) {
		return relayFrame{}, fmt.Errorf(
			"relay frame too large: %d > %d",
			size,
			maxSize,
		)
	}

	payload := make([]byte, int(size))

	if _, err := io.ReadFull(
		r,
		payload,
	); err != nil {
		return relayFrame{}, err
	}

	var frame relayFrame

	if err := cbor.Unmarshal(
		payload,
		&frame,
	); err != nil {
		return relayFrame{}, fmt.Errorf(
			"relay frame decode failed: %w",
			err,
		)
	}

	if err := validateRelayFrameForRead(frame); err != nil {
		return relayFrame{}, err
	}

	return frame, nil
}

// ============================================================
// RELAY FRAME VALIDATION
// ============================================================

func validateRelayFrameForWrite(
	frame relayFrame,
) error {

	if frame.Version != relayProtocolVersion {
		return fmt.Errorf(
			"unsupported relay protocol version: %d",
			frame.Version,
		)
	}

	switch frame.Type {
	case relayMsgHello,
		relayMsgHelloAck,
		relayMsgOpen,
		relayMsgOpenAck,
		relayMsgOpenReject,
		relayMsgData,
		relayMsgClose,
		relayMsgPing,
		relayMsgPong:

	default:
		return fmt.Errorf(
			"unknown relay message type: %d",
			frame.Type,
		)
	}

	if len(frame.Payload) > relayMaxDataSize {
		return fmt.Errorf(
			"relay payload too large: %d > %d",
			len(frame.Payload),
			relayMaxDataSize,
		)
	}

	if frame.Type == relayMsgData &&
		len(frame.Payload) == 0 {

		return errors.New(
			"relay data payload is empty",
		)
	}

	if frame.Type == relayMsgHello {
		if frame.SourcePeerID == "" {
			return errors.New(
				"relay hello source PeerID missing",
			)
		}

		if len(frame.PubKey) != ed25519.PublicKeySize {
			return errors.New(
				"relay hello public key invalid",
			)
		}

		if len(frame.Signature) != ed25519.SignatureSize {
			return errors.New(
				"relay hello signature invalid",
			)
		}
	}

	return nil
}

func validateRelayFrameForRead(
	frame relayFrame,
) error {

	if frame.Version != relayProtocolVersion {
		return fmt.Errorf(
			"unsupported relay protocol version: %d",
			frame.Version,
		)
	}

	switch frame.Type {
	case relayMsgHello,
		relayMsgHelloAck,
		relayMsgOpen,
		relayMsgOpenAck,
		relayMsgOpenReject,
		relayMsgData,
		relayMsgClose,
		relayMsgPing,
		relayMsgPong:

	default:
		return fmt.Errorf(
			"unknown relay message type: %d",
			frame.Type,
		)
	}

	if len(frame.Payload) > relayMaxDataSize {
		return fmt.Errorf(
			"relay payload too large: %d > %d",
			len(frame.Payload),
			relayMaxDataSize,
		)
	}

	if frame.Type == relayMsgData &&
		len(frame.Payload) == 0 {

		return errors.New(
			"relay data payload is empty",
		)
	}

	// Peer IDs are mandatory whenever the frame participates
	// in authenticated routing.
	switch frame.Type {
	case relayMsgOpen,
		relayMsgOpenAck,
		relayMsgOpenReject,
		relayMsgData,
		relayMsgClose:

		if frame.SourcePeerID == "" {
			return errors.New(
				"relay source PeerID missing",
			)
		}
	}

	return nil
}

// ============================================================
// RELAY HELLO VERIFICATION
// ============================================================

func verifyRelayHello(
	frame relayFrame,
) (string, error) {

	if frame.Type != relayMsgHello {
		return "", errors.New(
			"invalid relay hello type",
		)
	}

	if frame.Version != relayProtocolVersion {
		return "", fmt.Errorf(
			"unsupported relay protocol version: %d",
			frame.Version,
		)
	}

	if frame.SourcePeerID == "" {
		return "", errors.New(
			"relay hello PeerID missing",
		)
	}

	if len(frame.PubKey) != ed25519.PublicKeySize {
		return "", errors.New(
			"invalid relay wallet public key",
		)
	}

	if len(frame.Signature) != ed25519.SignatureSize {
		return "", errors.New(
			"invalid relay authentication signature",
		)
	}

	if frame.Timestamp == 0 {
		return "", errors.New(
			"relay hello timestamp missing",
		)
	}

	now := time.Now().UnixMilli()

	if diff := now - frame.Timestamp; diff > relayMaxClockSkew.Milliseconds() ||
		diff < -relayMaxClockSkew.Milliseconds() {

		return "", errors.New(
			"relay hello timestamp skew too large",
		)
	}

	if frame.Nonce == 0 {
		return "", errors.New(
			"relay hello nonce missing",
		)
	}

	message, err := buildRelayAuthMessage(
		frame.SourcePeerID,
		frame.Timestamp,
		frame.Nonce,
	)
	if err != nil {
		return "", err
	}

	publicKey := ed25519.PublicKey(
		append([]byte(nil), frame.PubKey...),
	)

	if !ed25519.Verify(
		publicKey,
		message,
		frame.Signature,
	) {
		return "", errors.New(
			"invalid relay authentication signature",
		)
	}

	// ------------------------------------------------------------------
	// CRYPTOGRAPHIC PEER ID BINDING
	// ------------------------------------------------------------------
	// The relay must never trust a caller-supplied PeerID by itself.
	//
	// The permanent EXPLOSIVE identity is derived from the wallet
	// public key. Therefore the PeerID declared in the relay HELLO
	// must exactly match the address derived from that public key.
	//
	// This prevents one wallet from registering another wallet's
	// PeerID
	// on the relay.
	//
	// The relay remains a transport layer only. It does not become
	// a blockchain authority.
	// ------------------------------------------------------------------
	derivedPeerID := address.GenerateEXPLOAddress(
		publicKey,
	)

	if derivedPeerID == "" {
		return "", errors.New(
			"failed to derive EXPLOSIVE PeerID from wallet public key",
		)
	}

	if frame.SourcePeerID != derivedPeerID {
		return "", fmt.Errorf(
			"relay PeerID does not match wallet public key: declared=%s derived=%s",
			frame.SourcePeerID,
			derivedPeerID,
		)
	}

	return derivedPeerID, nil
}

// ============================================================
// RELAY TIMESTAMP VALIDATION
// ============================================================

func validateRelayTimestamp(
	timestamp int64,
) error {

	if timestamp == 0 {
		return errors.New(
			"relay timestamp missing",
		)
	}

	now := time.Now().UnixMilli()

	diff := now - timestamp

	if diff > relayMaxClockSkew.Milliseconds() ||
		diff < -relayMaxClockSkew.Milliseconds() {

		return errors.New(
			"relay timestamp skew too large",
		)
	}

	return nil
}

// ============================================================
// RELAY NONCE
// ============================================================

func secureRelayNonce() uint64 {
	var raw [8]byte

	if _, err := rand.Read(raw[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}

	nonce := binary.BigEndian.Uint64(
		raw[:],
	)

	if nonce == 0 {
		nonce = 1
	}

	return nonce
}

// ============================================================
// RELAY DATA VALIDATION
// ============================================================

func validateRelayDataPayload(
	payload []byte,
) error {

	if len(payload) == 0 {
		return errors.New(
			"relay data payload is empty",
		)
	}

	if len(payload) > relayMaxDataSize {
		return fmt.Errorf(
			"relay data payload too large: %d > %d",
			len(payload),
			relayMaxDataSize,
		)
	}

	return nil
}

// ============================================================
// RELAY ERROR / TIMEOUT NORMALIZATION
// ============================================================

// osDeadlineExceeded normalizes platform-specific timeout
// errors without coupling relay code to a specific syscall.
func osDeadlineExceeded(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		return context.DeadlineExceeded
	}

	if netErr, ok := err.(net.Error); ok &&
		netErr.Timeout() {

		return context.DeadlineExceeded
	}

	return err
}
