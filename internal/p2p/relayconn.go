package p2p

import (
	"errors"
	"net"
	"sync"
	"time"
)

// relayNetConn adapts a RelayTunnel to the standard net.Conn interface.
//
// The P2P transport layer above this adapter remains unchanged:
// framing, handshake, wallet authentication, signatures, replay
// protection and blockchain synchronization continue to use the
// existing Peer read/write loops.
type relayNetConn struct {
	tunnel *RelayTunnel

	remoteAddr net.Addr
	localAddr  net.Addr

	// readMu protects buffered stream data and serializes calls to Read.
	readMu sync.Mutex
	buf    []byte

	// readCh receives opaque byte chunks from the relay tunnel.
	//
	// A single background reader is used instead of creating a new
	// goroutine for every Read call. This prevents goroutine buildup
	// when read deadlines expire.
	readCh chan relayReadResult

	readDone chan struct{}

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

type relayReadResult struct {
	data []byte
	err  error
}

type relayNetAddr struct {
	network string
	address string
}

func (a relayNetAddr) Network() string {
	return a.network
}

func (a relayNetAddr) String() string {
	return a.address
}

// newRelayNetConn creates a net.Conn-compatible adapter around a
// logical RelayTunnel.
//
// The relay itself remains opaque to the EXPLOSIVE P2P protocol.
func newRelayNetConn(
	tunnel *RelayTunnel,
	localPeerID string,
	remotePeerID string,
) *relayNetConn {

	c := &relayNetConn{
		tunnel: tunnel,

		localAddr: relayNetAddr{
			network: "explosive-relay",
			address: "relay://" + localPeerID,
		},

		remoteAddr: relayNetAddr{
			network: "explosive-relay",
			address: "relay://" + remotePeerID,
		},

		readCh: make(chan relayReadResult, 16),

		readDone: make(chan struct{}),

		closed: make(chan struct{}),
	}

	go c.readLoop()

	return c
}

// readLoop continuously consumes opaque bytes from RelayTunnel.
//
// Only this goroutine calls RelayTunnel.Read(). The public Read()
// method consumes already received chunks and applies net.Conn
// deadline semantics without creating additional goroutines.
func (c *relayNetConn) readLoop() {

	defer close(c.readDone)

	for {

		select {
		case <-c.closed:
			return

		default:
		}

		data, err := c.tunnel.Read()

		result := relayReadResult{
			data: data,
			err:  err,
		}

		select {

		case c.readCh <- result:

		case <-c.closed:
			return
		}

		if err != nil {
			return
		}
	}
}

// Read implements net.Conn.Read.
//
// RelayTunnel delivers arbitrary byte chunks. This adapter buffers
// those chunks so the caller sees normal stream-oriented net.Conn
// semantics.
func (c *relayNetConn) Read(p []byte) (int, error) {

	if c == nil || c.tunnel == nil {
		return 0, errors.New("nil relay connection")
	}

	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {

		// --------------------------------------------------------------
		// USE BUFFERED DATA FIRST
		// --------------------------------------------------------------

		if len(c.buf) > 0 {

			n := copy(p, c.buf)

			c.buf = c.buf[n:]

			return n, nil
		}

		// --------------------------------------------------------------
		// CHECK CLOSED STATE
		// --------------------------------------------------------------

		select {

		case <-c.closed:
			return 0, net.ErrClosed

		default:
		}

		// --------------------------------------------------------------
		// READ DEADLINE
		// --------------------------------------------------------------

		c.deadlineMu.RLock()

		deadline := c.readDeadline

		c.deadlineMu.RUnlock()

		var timer *time.Timer
		var timerCh <-chan time.Time

		if !deadline.IsZero() {

			remaining := time.Until(deadline)

			if remaining <= 0 {
				return 0, relayDeadlineExceededError{}
			}

			timer = time.NewTimer(remaining)
			timerCh = timer.C
		}

		// --------------------------------------------------------------
		// WAIT FOR RELAY DATA
		// --------------------------------------------------------------

		select {

		case result := <-c.readCh:

			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}

			if len(result.data) > 0 {

				c.buf = append(
					c.buf,
					result.data...,
				)

				continue
			}

			if result.err != nil {
				return 0, result.err
			}

		case <-c.closed:

			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}

			return 0, net.ErrClosed

		case <-timerCh:

			return 0, relayDeadlineExceededError{}
		}
	}
}

// Write implements net.Conn.Write.
func (c *relayNetConn) Write(p []byte) (int, error) {

	if c == nil || c.tunnel == nil {
		return 0, errors.New("nil relay connection")
	}

	if len(p) == 0 {
		return 0, nil
	}

	select {

	case <-c.closed:
		return 0, net.ErrClosed

	default:
	}

	// --------------------------------------------------------------
	// WRITE DEADLINE
	// --------------------------------------------------------------

	c.deadlineMu.RLock()

	deadline := c.writeDeadline

	c.deadlineMu.RUnlock()

	if !deadline.IsZero() &&
		!time.Now().Before(deadline) {

		return 0, relayDeadlineExceededError{}
	}

	// --------------------------------------------------------------
	// WRITE THROUGH RELAY
	// --------------------------------------------------------------

	if err := c.tunnel.Write(p); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close closes only this logical relay transport.
//
// It does not close the entire RelayClient connection.
func (c *relayNetConn) Close() error {

	if c == nil {
		return nil
	}

	c.closeOnce.Do(func() {

		close(c.closed)

		if c.tunnel != nil {
			c.tunnel.Close()
		}
	})

	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *relayNetConn) LocalAddr() net.Addr {

	if c == nil {
		return relayNetAddr{
			network: "explosive-relay",
			address: "relay://unknown",
		}
	}

	return c.localAddr
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *relayNetConn) RemoteAddr() net.Addr {

	if c == nil {
		return relayNetAddr{
			network: "explosive-relay",
			address: "relay://unknown",
		}
	}

	return c.remoteAddr
}

// SetDeadline implements net.Conn.SetDeadline.
func (c *relayNetConn) SetDeadline(t time.Time) error {

	c.deadlineMu.Lock()

	c.readDeadline = t
	c.writeDeadline = t

	c.deadlineMu.Unlock()

	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (c *relayNetConn) SetReadDeadline(t time.Time) error {

	c.deadlineMu.Lock()

	c.readDeadline = t

	c.deadlineMu.Unlock()

	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (c *relayNetConn) SetWriteDeadline(t time.Time) error {

	c.deadlineMu.Lock()

	c.writeDeadline = t

	c.deadlineMu.Unlock()

	return nil
}

// relayDeadlineExceededError implements the net.Error timeout contract.
//
// This keeps the relay adapter independent from platform-specific
// syscall errors while preserving standard Go timeout behavior.
type relayDeadlineExceededError struct{}

func (relayDeadlineExceededError) Error() string {
	return "i/o timeout"
}

func (relayDeadlineExceededError) Timeout() bool {
	return true
}

func (relayDeadlineExceededError) Temporary() bool {
	return true
}

var _ net.Conn = (*relayNetConn)(nil)
