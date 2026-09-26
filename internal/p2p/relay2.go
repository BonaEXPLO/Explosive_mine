package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ============================================================
// RELAY CLIENT
// ============================================================

type RelayClientConfig struct {
	TLSConfig *tls.Config

	RelayAddr string

	PeerID string

	WalletPublicKey ed25519.PublicKey

	WalletSigner func([]byte) ([]byte, error)

	DialTimeout time.Duration

	MaxFrameSize int
}

func (c RelayClientConfig) normalize() RelayClientConfig {
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}

	if c.MaxFrameSize <= 0 || c.MaxFrameSize > relayMaxFrameSize {
		c.MaxFrameSize = relayMaxFrameSize
	}

	return c
}

// RelayClient maintains one authenticated TLS connection
// to a relay server.
//
// IMPORTANT:
// There is exactly one reader goroutine for the relay
// connection. No other method reads directly from conn.
//
// Writes are serialized by writeMu.
type RelayClient struct {
	config RelayClientConfig

	conn net.Conn

	mu      sync.Mutex
	writeMu sync.Mutex

	connectMu sync.Mutex

	closed bool

	readerDone chan struct{}

	// tunnels maps remote PeerID -> local tunnel.
	//
	// There is at most one logical tunnel per remote PeerID
	// on a single relay client connection.
	tunnelsMu sync.RWMutex
	tunnels   map[string]*RelayTunnel

	// pendingOpen maps the OPEN nonce to the waiting
	// OpenTunnel caller.
	openMu      sync.Mutex
	pendingOpen map[uint64]chan relayFrame

	// incomingTunnels receives tunnels initiated by another
	// peer through the relay.
	//
	// The application can consume them with AcceptTunnel().
	incomingTunnels chan *RelayTunnel

	incomingOnce sync.Once
}

// NewRelayClient creates a relay client.
func NewRelayClient(
	config RelayClientConfig,
) (*RelayClient, error) {

	config = config.normalize()

	if config.TLSConfig == nil {
		return nil, errors.New(
			"relay client TLS configuration is required",
		)
	}

	if config.RelayAddr == "" {
		return nil, errors.New(
			"relay address is required",
		)
	}

	if config.PeerID == "" {
		return nil, errors.New(
			"relay PeerID is required",
		)
	}

	if len(config.WalletPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New(
			"invalid wallet public key",
		)
	}

	if config.WalletSigner == nil {
		return nil, errors.New(
			"wallet signer is required",
		)
	}

	return &RelayClient{
		config: config,

		tunnels: make(
			map[string]*RelayTunnel,
		),

		pendingOpen: make(
			map[uint64]chan relayFrame,
		),

		incomingTunnels: make(
			chan *RelayTunnel,
			64,
		),
	}, nil
}

// ============================================================
// CONNECT
// ============================================================

// Connect establishes and authenticates the relay connection.
//
// The relay reader loop starts only after HELLO_ACK has been
// successfully received.
//
// This guarantees that authentication reads never race with
// the normal relay reader.
func (c *RelayClient) Connect(ctx context.Context) error {
	if c == nil {
		return errors.New("nil relay client")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	c.connectMu.Lock()
	defer c.connectMu.Unlock()

	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()

		return errors.New(
			"relay client is closed",
		)
	}

	if c.conn != nil {
		c.mu.Unlock()

		return nil
	}

	c.mu.Unlock()

	dialer := &net.Dialer{
		Timeout: c.config.DialTimeout,
	}

	rawConn, err := dialer.DialContext(
		ctx,
		"tcp",
		c.config.RelayAddr,
	)
	if err != nil {
		return fmt.Errorf(
			"relay TCP connection failed: %w",
			err,
		)
	}

	tlsConfig := c.config.TLSConfig.Clone()

	tlsConn := tls.Client(
		rawConn,
		tlsConfig,
	)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()

		return fmt.Errorf(
			"relay TLS handshake failed: %w",
			err,
		)
	}

	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()

		_ = tlsConn.Close()

		return errors.New(
			"relay client is closed",
		)
	}

	readerDone := make(chan struct{})

	c.conn = tlsConn
	c.readerDone = readerDone

	c.mu.Unlock()

	if err := c.authenticate(tlsConn); err != nil {
		c.mu.Lock()

		if c.conn == tlsConn {
			c.conn = nil
		}

		if c.readerDone == readerDone {
			c.readerDone = nil
		}

		c.mu.Unlock()

		select {
		case <-readerDone:
		default:
			close(readerDone)
		}

		_ = tlsConn.Close()

		return err
	}

	go c.relayReadLoop(
		tlsConn,
		readerDone,
	)

	return nil
}

// ============================================================
// AUTHENTICATION
// ============================================================

// authenticate performs the relay HELLO/HELLO_ACK exchange.
//
// This function runs before relayReadLoop starts.
//
// Therefore it is the only function allowed to read the
// connection during authentication.
func (c *RelayClient) authenticate(
	conn net.Conn,
) error {

	if conn == nil {
		return errors.New(
			"relay connection is not available",
		)
	}

	timestamp := time.Now().UnixMilli()
	nonce := secureRelayNonce()

	message, err := buildRelayAuthMessage(
		c.config.PeerID,
		timestamp,
		nonce,
	)
	if err != nil {
		return fmt.Errorf(
			"relay authentication payload failed: %w",
			err,
		)
	}

	signature, err := c.config.WalletSigner(message)
	if err != nil {
		return fmt.Errorf(
			"relay authentication signature failed: %w",
			err,
		)
	}

	if len(signature) != ed25519.SignatureSize {
		return errors.New(
			"invalid relay authentication signature size",
		)
	}

	hello := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgHello,
		SourcePeerID: c.config.PeerID,
		Timestamp:    timestamp,
		Nonce:        nonce,
		PubKey:       append([]byte(nil), c.config.WalletPublicKey...),
		Signature:    append([]byte(nil), signature...),
	}

	if err := c.writeFrameOnConn(
		conn,
		hello,
	); err != nil {
		return fmt.Errorf(
			"relay HELLO failed: %w",
			err,
		)
	}

	_ = conn.SetReadDeadline(
		time.Now().Add(relayAuthTimeout),
	)

	ack, err := readRelayFrame(
		conn,
		c.config.MaxFrameSize,
	)

	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		return fmt.Errorf(
			"relay HELLO_ACK failed: %w",
			err,
		)
	}

	if ack.Type != relayMsgHelloAck {
		return fmt.Errorf(
			"unexpected relay authentication response: %d",
			ack.Type,
		)
	}

	if ack.Version != relayProtocolVersion {
		return errors.New(
			"relay authentication protocol version mismatch",
		)
	}

	if ack.SourcePeerID != c.config.PeerID {
		return errors.New(
			"relay authentication identity mismatch",
		)
	}

	if ack.Nonce == 0 {
		return errors.New(
			"relay authentication ACK nonce is missing",
		)
	}

	if err := validateRelayTimestamp(
		ack.Timestamp,
	); err != nil {
		return fmt.Errorf(
			"invalid relay authentication ACK timestamp: %w",
			err,
		)
	}

	return nil
}

// ============================================================
// WRITE
// ============================================================

// writeFrame serializes every relay write.
//
// Multiple goroutines may call this function concurrently,
// but only one can write a complete relay frame at a time.
func (c *RelayClient) writeFrame(
	frame relayFrame,
) error {

	if c == nil {
		return errors.New(
			"nil relay client",
		)
	}

	c.mu.Lock()

	conn := c.conn
	closed := c.closed

	c.mu.Unlock()

	if closed || conn == nil {
		return net.ErrClosed
	}

	return c.writeFrameOnConn(
		conn,
		frame,
	)
}

// writeFrameOnConn writes one complete frame to a supplied
// connection while respecting the client write lock.
func (c *RelayClient) writeFrameOnConn(
	conn net.Conn,
	frame relayFrame,
) error {

	if c == nil {
		return errors.New(
			"nil relay client",
		)
	}

	if conn == nil {
		return net.ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return writeRelayFrame(
		conn,
		frame,
	)
}

// ============================================================
// RELAY READER LOOP
// ============================================================

// relayReadLoop is the ONLY normal reader of the relay
// connection.
//
// All incoming relay frames are dispatched from here.
func (c *RelayClient) relayReadLoop(
	conn net.Conn,
	done chan struct{},
) {

	defer func() {

		select {
		case <-done:
		default:
			close(done)
		}

		c.handleRelayConnectionClosed(
			conn,
			done,
		)
	}()

	for {

		frame, err := readRelayFrame(
			conn,
			c.config.MaxFrameSize,
		)

		if err != nil {
			return
		}

		switch frame.Type {

		case relayMsgOpenAck,
			relayMsgOpenReject:

			c.dispatchOpenResponse(
				frame,
			)

		case relayMsgData:

			c.dispatchData(
				frame,
			)

		case relayMsgPing:

			c.handleRelayPing(
				conn,
				frame,
			)

		case relayMsgPong:
			// Keepalive response.

		case relayMsgClose:

			return

		default:
			// Ignore unsupported or unrelated relay control
			// frames. The relay server remains authoritative
			// for the relay control protocol.
		}
	}
}

// ============================================================
// CONNECTION SHUTDOWN
// ============================================================

// handleRelayConnectionClosed cleans up the client after
// the relay connection is lost.
//
// The supplied conn/done pair must still represent the
// currently active connection. This prevents an old reader
// goroutine from accidentally destroying a newer connection.
func (c *RelayClient) handleRelayConnectionClosed(
	conn net.Conn,
	done chan struct{},
) {

	c.mu.Lock()

	if c.conn != conn ||
		c.readerDone != done {

		c.mu.Unlock()

		return
	}

	c.conn = nil
	c.readerDone = nil

	c.mu.Unlock()

	_ = conn.Close()

	c.failPendingOpen(
		net.ErrClosed,
	)

	c.closeAllTunnels()
}

// ============================================================
// RELAY PING
// ============================================================

func (c *RelayClient) handleRelayPing(
	conn net.Conn,
	frame relayFrame,
) {

	if frame.SourcePeerID == "" {
		return
	}

	if frame.TargetPeerID != "" &&
		frame.TargetPeerID != c.config.PeerID {

		return
	}

	if frame.Nonce == 0 {
		return
	}

	if err := validateRelayTimestamp(
		frame.Timestamp,
	); err != nil {
		return
	}

	pong := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgPong,
		SourcePeerID: c.config.PeerID,
		TargetPeerID: frame.SourcePeerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        frame.Nonce,
	}

	_ = c.writeFrameOnConn(
		conn,
		pong,
	)
}

// ============================================================
// OPEN RESPONSE / INCOMING TUNNEL
// ============================================================

// dispatchOpenResponse handles:
//
// 1. OPEN_ACK for an outbound OpenTunnel() request.
//
// 2. OPEN_REJECT for an outbound OpenTunnel() request.
//
//  3. An unsolicited OPEN_ACK sent by the relay to the target
//     peer. This creates an incoming RelayTunnel.
//
// The relay server uses OPEN_ACK as the target notification
// because the current relay protocol has no separate
// OPEN_INCOMING message.
func (c *RelayClient) dispatchOpenResponse(
	frame relayFrame,
) {

	if c == nil {
		return
	}

	if frame.Nonce == 0 {
		return
	}

	if err := validateRelayTimestamp(
		frame.Timestamp,
	); err != nil {
		return
	}

	// --------------------------------------------------------
	// INCOMING TUNNEL
	// --------------------------------------------------------
	//
	// The target receives:
	//
	// SourcePeerID = initiating peer
	// TargetPeerID = this client
	//
	// This OPEN_ACK does not belong to a local pending OPEN.
	if frame.Type == relayMsgOpenAck &&
		frame.TargetPeerID == c.config.PeerID &&
		frame.SourcePeerID != "" &&
		frame.SourcePeerID != c.config.PeerID {

		c.acceptIncomingTunnel(
			frame.SourcePeerID,
		)

		return
	}

	// --------------------------------------------------------
	// OUTBOUND OPEN RESPONSE
	// --------------------------------------------------------

	c.openMu.Lock()

	ch, ok := c.pendingOpen[frame.Nonce]

	if ok {
		delete(
			c.pendingOpen,
			frame.Nonce,
		)
	}

	c.openMu.Unlock()

	if !ok {
		return
	}

	select {
	case ch <- frame:
	default:
	}
}

// acceptIncomingTunnel creates the local representation of
// an inbound relay tunnel.
//
// The relay server has already authenticated the source
// session and installed the route.
//
// No private wallet material is involved.
func (c *RelayClient) acceptIncomingTunnel(
	sourcePeerID string,
) {

	if c == nil ||
		sourcePeerID == "" ||
		sourcePeerID == c.config.PeerID {

		return
	}

	c.mu.Lock()

	if c.closed || c.conn == nil {
		c.mu.Unlock()

		return
	}

	c.mu.Unlock()

	c.tunnelsMu.Lock()

	existing := c.tunnels[sourcePeerID]

	if existing != nil &&
		!existing.isClosed() {

		c.tunnelsMu.Unlock()

		return
	}

	tunnel := newRelayTunnel(
		c,
		sourcePeerID,
	)

	c.tunnels[sourcePeerID] = tunnel

	c.tunnelsMu.Unlock()

	// Deliver the incoming tunnel to the application.
	//
	// Never block the relay reader indefinitely.
	select {
	case c.incomingTunnels <- tunnel:

	default:
		// No consumer is currently ready.
		//
		// The tunnel remains registered so DATA frames can
		// still be buffered temporarily. The application
		// can obtain it through AcceptTunnel().
	}
}

// ============================================================
// INCOMING TUNNEL API
// ============================================================

// AcceptTunnel waits for an incoming relay tunnel.
//
// The returned RelayTunnel behaves like a logical transport
// endpoint carrying opaque EXPLOSIVE P2P bytes.
func (c *RelayClient) AcceptTunnel(
	ctx context.Context,
) (*RelayTunnel, error) {

	if c == nil {
		return nil, errors.New(
			"nil relay client",
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()

	closed := c.closed

	c.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}

	select {

	case tunnel := <-c.incomingTunnels:

		if tunnel == nil {
			return nil, net.ErrClosed
		}

		if tunnel.isClosed() {
			return nil, net.ErrClosed
		}

		return tunnel, nil

	case <-ctx.Done():

		return nil, ctx.Err()
	}
}

// IncomingTunnels exposes the channel used for incoming
// relay tunnels.
//
// Applications may use either AcceptTunnel() or this channel.
// AcceptTunnel() is preferred because it supports context
// cancellation.
func (c *RelayClient) IncomingTunnels() <-chan *RelayTunnel {
	if c == nil {
		return nil
	}

	return c.incomingTunnels
}

// ============================================================
// DATA
// ============================================================

// dispatchData routes DATA frames to the corresponding
// relay tunnel.
//
// The actual EXPLOSIVE P2P bytes remain opaque to the relay
// layer.
//
// The EXPLOSIVE Peer.readLoop() will later perform:
//   - frame decoding
//   - envelope validation
//   - wallet signature verification
//   - replay protection
//   - block validation
//   - normal message dispatch
func (c *RelayClient) dispatchData(
	frame relayFrame,
) {

	if c == nil {
		return
	}

	if frame.SourcePeerID == "" {
		return
	}

	if frame.SourcePeerID == c.config.PeerID {
		return
	}

	if frame.TargetPeerID != c.config.PeerID {
		return
	}

	if len(frame.Payload) == 0 ||
		len(frame.Payload) > relayMaxDataSize {

		return
	}

	c.tunnelsMu.RLock()

	tunnel := c.tunnels[frame.SourcePeerID]

	c.tunnelsMu.RUnlock()

	if tunnel == nil {
		return
	}

	tunnel.enqueueData(
		append(
			[]byte(nil),
			frame.Payload...,
		),
	)
}

// ============================================================
// PENDING OPEN FAILURE
// ============================================================

// failPendingOpen wakes every waiting OpenTunnel() call.
func (c *RelayClient) failPendingOpen(
	err error,
) {

	if err == nil {
		err = net.ErrClosed
	}

	c.openMu.Lock()

	pending := c.pendingOpen

	c.pendingOpen = make(
		map[uint64]chan relayFrame,
	)

	c.openMu.Unlock()

	for _, ch := range pending {

		frame := relayFrame{
			Type:  relayMsgOpenReject,
			Error: err.Error(),
		}

		select {
		case ch <- frame:
		default:
		}
	}
}

// ============================================================
// OPEN TUNNEL
// ============================================================

// OpenTunnel asks the relay server to create a route from
// this client to targetPeerID.
//
// The target peer receives an incoming RelayTunnel through
// AcceptTunnel().
func (c *RelayClient) OpenTunnel(
	ctx context.Context,
	targetPeerID string,
) (*RelayTunnel, error) {

	if c == nil {
		return nil, errors.New(
			"nil relay client",
		)
	}

	if targetPeerID == "" {
		return nil, errors.New(
			"target PeerID is required",
		)
	}

	if targetPeerID == c.config.PeerID {
		return nil, errors.New(
			"relay target cannot be the local PeerID",
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Reuse an existing active tunnel when possible.
	c.tunnelsMu.RLock()

	existing := c.tunnels[targetPeerID]

	c.tunnelsMu.RUnlock()

	if existing != nil &&
		!existing.isClosed() {

		return existing, nil
	}

	c.mu.Lock()

	conn := c.conn
	closed := c.closed

	c.mu.Unlock()

	if closed || conn == nil {
		return nil, errors.New(
			"relay client is not connected",
		)
	}

	nonce := secureRelayNonce()

	responseCh := make(
		chan relayFrame,
		1,
	)

	c.openMu.Lock()

	if _, exists := c.pendingOpen[nonce]; exists {

		c.openMu.Unlock()

		return nil, errors.New(
			"relay OPEN nonce collision",
		)
	}

	c.pendingOpen[nonce] = responseCh

	c.openMu.Unlock()

	frame := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgOpen,
		SourcePeerID: c.config.PeerID,
		TargetPeerID: targetPeerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        nonce,
	}

	if err := c.writeFrame(frame); err != nil {

		c.openMu.Lock()

		delete(
			c.pendingOpen,
			nonce,
		)

		c.openMu.Unlock()

		return nil, fmt.Errorf(
			"relay OPEN failed: %w",
			err,
		)
	}

	var response relayFrame

	select {

	case <-ctx.Done():

		c.openMu.Lock()

		delete(
			c.pendingOpen,
			nonce,
		)

		c.openMu.Unlock()

		return nil, ctx.Err()

	case response = <-responseCh:
	}

	if response.Type == relayMsgOpenReject {

		if response.Error == "" {
			response.Error = "relay target rejected OPEN"
		}

		return nil, fmt.Errorf(
			"relay target rejected: %s",
			response.Error,
		)
	}

	if response.Type != relayMsgOpenAck {

		return nil, fmt.Errorf(
			"unexpected relay OPEN response: %d",
			response.Type,
		)
	}

	if response.SourcePeerID != c.config.PeerID {

		return nil, errors.New(
			"relay OPEN source identity mismatch",
		)
	}

	if response.TargetPeerID != targetPeerID {

		return nil, errors.New(
			"relay OPEN target identity mismatch",
		)
	}

	tunnel := newRelayTunnel(
		c,
		targetPeerID,
	)

	// Replace any stale/closed tunnel safely.
	c.tunnelsMu.Lock()

	oldTunnel := c.tunnels[targetPeerID]

	c.tunnels[targetPeerID] = tunnel

	c.tunnelsMu.Unlock()

	if oldTunnel != nil &&
		oldTunnel != tunnel {

		oldTunnel.Close()
	}

	return tunnel, nil
}

// ============================================================
// RELAY CLIENT CLOSE
// ============================================================

// Close permanently closes the RelayClient.
//
// After Close(), Connect() cannot be used again on the same
// RelayClient instance. Create a new RelayClient if a new
// authenticated lifecycle is required.
func (c *RelayClient) Close() {

	if c == nil {
		return
	}

	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()

		return
	}

	c.closed = true

	conn := c.conn
	c.conn = nil

	done := c.readerDone
	c.readerDone = nil

	c.mu.Unlock()

	if conn != nil {

		_ = c.writeFrameOnConn(
			conn,
			relayFrame{
				Version:      relayProtocolVersion,
				Type:         relayMsgClose,
				SourcePeerID: c.config.PeerID,
				Timestamp:    time.Now().UnixMilli(),
				Nonce:        secureRelayNonce(),
			},
		)

		_ = conn.Close()
	}

	if done != nil {

		select {

		case <-done:

		case <-time.After(
			2 * time.Second,
		):
		}
	}

	c.failPendingOpen(
		net.ErrClosed,
	)

	c.closeAllTunnels()

	c.closeIncomingChannel()
}

// closeIncomingChannel closes the incoming tunnel channel
// exactly once.
func (c *RelayClient) closeIncomingChannel() {

	if c == nil {
		return
	}

	c.incomingOnce.Do(func() {
		close(c.incomingTunnels)
	})
}

// ============================================================
// CLOSE ALL TUNNELS
// ============================================================

// closeAllTunnels closes every tunnel belonging to this
// relay client.
func (c *RelayClient) closeAllTunnels() {

	c.tunnelsMu.Lock()

	tunnels := make(
		[]*RelayTunnel,
		0,
		len(c.tunnels),
	)

	for peerID, tunnel := range c.tunnels {

		delete(
			c.tunnels,
			peerID,
		)

		if tunnel != nil {
			tunnels = append(
				tunnels,
				tunnel,
			)
		}
	}

	c.tunnelsMu.Unlock()

	for _, tunnel := range tunnels {
		tunnel.Close()
	}
}

// ============================================================
// RELAY TUNNEL
// ============================================================

// RelayTunnel is a logical bidirectional relay transport.
//
// It does NOT expose the underlying TCP/TLS socket.
//
// DATA payloads are opaque P2P bytes.
type RelayTunnel struct {
	client *RelayClient

	targetPeerID string

	readMu sync.Mutex

	dataCh chan []byte

	// done is closed when this logical tunnel is closed.
	//
	// dataCh is intentionally never closed while producers
	// may still exist. This prevents send-on-closed-channel
	// races.
	done chan struct{}

	closedMu sync.RWMutex
	closed   bool

	closeOnce sync.Once
}

// newRelayTunnel creates a new logical relay tunnel.
func newRelayTunnel(
	client *RelayClient,
	targetPeerID string,
) *RelayTunnel {

	return &RelayTunnel{
		client: client,

		targetPeerID: targetPeerID,

		dataCh: make(
			chan []byte,
			relayDataQueueSize,
		),

		done: make(
			chan struct{},
		),
	}
}

// isClosed reports whether this logical tunnel is closed.
func (t *RelayTunnel) isClosed() bool {

	if t == nil {
		return true
	}

	t.closedMu.RLock()

	closed := t.closed

	t.closedMu.RUnlock()

	return closed
}

// enqueueData delivers opaque P2P bytes to the tunnel.
//
// dataCh is never closed by RelayTunnel.Close(), therefore
// this function cannot panic because of a concurrent Close().
func (t *RelayTunnel) enqueueData(
	payload []byte,
) {

	if t == nil ||
		len(payload) == 0 {

		return
	}

	t.closedMu.RLock()

	closed := t.closed

	t.closedMu.RUnlock()

	if closed {
		return
	}

	data := append(
		[]byte(nil),
		payload...,
	)

	select {

	case t.dataCh <- data:

	default:
		// Drop data when the tunnel queue is full.
		//
		// This bounds memory usage and prevents the relay
		// reader from blocking indefinitely.
	}

}

// ============================================================
// TUNNEL WRITE
// ============================================================

// Write transports opaque P2P bytes to the target PeerID.
//
// These bytes are normally the exact framed bytes produced
// by the EXPLOSIVE P2P transport.
func (t *RelayTunnel) Write(
	payload []byte,
) error {

	if t == nil ||
		t.client == nil {

		return errors.New(
			"nil relay tunnel",
		)
	}

	if len(payload) == 0 {
		return nil
	}

	if len(payload) > relayMaxDataSize {

		return errors.New(
			"relay payload exceeds maximum size",
		)
	}

	if t.isClosed() {
		return net.ErrClosed
	}

	t.client.mu.Lock()

	clientClosed := t.client.closed
	conn := t.client.conn

	t.client.mu.Unlock()

	if clientClosed ||
		conn == nil {

		return net.ErrClosed
	}

	frame := relayFrame{
		Version: relayProtocolVersion,
		Type:    relayMsgData,

		SourcePeerID: t.client.config.PeerID,

		TargetPeerID: t.targetPeerID,

		Timestamp: time.Now().UnixMilli(),

		Nonce: secureRelayNonce(),

		Payload: append(
			[]byte(nil),
			payload...,
		),
	}

	return t.client.writeFrame(
		frame,
	)
}

// ============================================================
// TUNNEL READ
// ============================================================

// Read receives opaque P2P bytes from the target.
//
// IMPORTANT:
// Read never reads directly from the relay socket.
//
// The central relayReadLoop receives all relay frames and
// places DATA payloads into this tunnel's data channel.
func (t *RelayTunnel) Read() ([]byte, error) {

	if t == nil ||
		t.client == nil {

		return nil, errors.New(
			"nil relay tunnel",
		)
	}

	t.readMu.Lock()
	defer t.readMu.Unlock()

	for {

		// First check for already buffered data.
		select {

		case payload := <-t.dataCh:

			if len(payload) == 0 {
				continue
			}

			return payload, nil

		default:
		}

		if t.isClosed() {
			return nil, net.ErrClosed
		}

		select {

		case payload := <-t.dataCh:

			if len(payload) == 0 {
				continue
			}

			return payload, nil

		case <-t.done:

			return nil, net.ErrClosed

		case <-t.clientDone():

			return nil, net.ErrClosed
		}
	}
}

// clientDone returns the current relay connection's done
// channel.
//
// If no connection exists, it returns an already closed
// channel so Read() terminates immediately.
func (t *RelayTunnel) clientDone() <-chan struct{} {

	if t == nil ||
		t.client == nil {

		done := make(chan struct{})

		close(done)

		return done
	}

	t.client.mu.Lock()

	done := t.client.readerDone
	closed := t.client.closed

	t.client.mu.Unlock()

	if done != nil {
		return done
	}

	if closed {

		closedDone := make(chan struct{})

		close(closedDone)

		return closedDone
	}

	// No current connection.
	//
	// Do not immediately terminate a tunnel here if the
	// RelayClient itself is still alive: the application may
	// reconnect the relay client.
	wait := make(chan struct{})

	return wait
}

// ============================================================
// TUNNEL CLOSE
// ============================================================

// Close closes the logical tunnel.
//
// The relay client connection itself remains available for
// other tunnels.
//
// We intentionally do NOT send relayMsgClose here because
// relayMsgClose currently closes the entire relay session,
// not one logical route.
func (t *RelayTunnel) Close() {

	if t == nil {
		return
	}

	t.closeOnce.Do(func() {

		t.closedMu.Lock()

		t.closed = true

		t.closedMu.Unlock()

		close(t.done)

		if t.client != nil {

			t.client.removeTunnel(
				t.targetPeerID,
				t,
			)
		}
	})
}

// ============================================================
// REMOVE TUNNEL
// ============================================================

// removeTunnel removes exactly this tunnel instance.
func (c *RelayClient) removeTunnel(
	targetPeerID string,
	tunnel *RelayTunnel,
) {

	if c == nil ||
		tunnel == nil {

		return
	}

	c.tunnelsMu.Lock()
	defer c.tunnelsMu.Unlock()

	current := c.tunnels[targetPeerID]

	if current == tunnel {

		delete(
			c.tunnels,
			targetPeerID,
		)
	}
}
