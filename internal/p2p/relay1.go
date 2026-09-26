package p2p

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// RELAY SERVER
// ============================================================

type RelayServerConfig struct {
	TLSConfig *tls.Config

	MaxSessions int

	IdleTimeout time.Duration

	MaxFrameSize int
}

func DefaultRelayServerConfig() RelayServerConfig {
	return RelayServerConfig{
		MaxSessions:  relayDefaultMaxSessions,
		IdleTimeout: relayIdleTimeout,
		MaxFrameSize: relayMaxFrameSize,
	}
}

func (c RelayServerConfig) normalize() RelayServerConfig {
	if c.MaxSessions <= 0 {
		c.MaxSessions = relayDefaultMaxSessions
	}

	if c.IdleTimeout <= 0 {
		c.IdleTimeout = relayIdleTimeout
	}

	if c.MaxFrameSize <= 0 ||
		c.MaxFrameSize > relayMaxFrameSize {
		c.MaxFrameSize = relayMaxFrameSize
	}

	return c
}

// relayRoute identifies one authenticated relay path.
//
// A route is directional:
//
//	source -> target
//
// When an OPEN is accepted, the server installs both:
//
//	source -> target
//	target -> source
//
// This allows opaque DATA to flow in both directions.
type relayRoute struct {
	source string
	target string
}

type RelayServer struct {
	config RelayServerConfig

	registry *RelayRegistry

	listener net.Listener

	ctx    context.Context
	cancel context.CancelFunc

	wg sync.WaitGroup

	// --------------------------------------------------------
	// Active authenticated routes.
	// --------------------------------------------------------

	routesMu sync.RWMutex
	routes   map[relayRoute]struct{}

	closeOnce sync.Once
}

func NewRelayServer(
	config RelayServerConfig,
) *RelayServer {

	config = config.normalize()

	return &RelayServer{
		config:   config,
		registry: NewRelayRegistry(config.MaxSessions),
		routes:   make(map[relayRoute]struct{}),
	}
}

func (s *RelayServer) Registry() *RelayRegistry {
	if s == nil {
		return nil
	}

	return s.registry
}

// ============================================================
// ROUTE MANAGEMENT
// ============================================================

func (s *RelayServer) addRoute(
	source string,
	target string,
) {
	if s == nil ||
		source == "" ||
		target == "" ||
		source == target {

		return
	}

	s.routesMu.Lock()

	s.routes[relayRoute{
		source: source,
		target: target,
	}] = struct{}{}

	s.routesMu.Unlock()
}

func (s *RelayServer) removeRoute(
	source string,
	target string,
) {
	if s == nil ||
		source == "" ||
		target == "" {

		return
	}

	s.routesMu.Lock()

	delete(
		s.routes,
		relayRoute{
			source: source,
			target: target,
		},
	)

	s.routesMu.Unlock()
}

func (s *RelayServer) hasRoute(
	source string,
	target string,
) bool {
	if s == nil ||
		source == "" ||
		target == "" {

		return false
	}

	s.routesMu.RLock()

	_, ok := s.routes[relayRoute{
		source: source,
		target: target,
	}]

	s.routesMu.RUnlock()

	return ok
}

func (s *RelayServer) removeRoutesForPeer(
	peerID string,
) {
	if s == nil || peerID == "" {
		return
	}

	s.routesMu.Lock()

	for route := range s.routes {
		if route.source == peerID ||
			route.target == peerID {

			delete(
				s.routes,
				route,
			)
		}
	}

	s.routesMu.Unlock()
}

// ============================================================
// LISTEN / SERVE
// ============================================================

func (s *RelayServer) ListenAndServe(
	ctx context.Context,
	listenAddr string,
) error {

	if s == nil {
		return errors.New(
			"nil relay server",
		)
	}

	if s.config.TLSConfig == nil {
		return errors.New(
			"relay TLS configuration is required",
		)
	}

	if listenAddr == "" {
		return errors.New(
			"relay listen address is empty",
		)
	}

	if ctx == nil {
		ctx = context.Background()
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	ln, err := tls.Listen(
		"tcp",
		listenAddr,
		s.config.TLSConfig,
	)
	if err != nil {
		return fmt.Errorf(
			"relay TLS listen failed: %w",
			err,
		)
	}

	s.listener = ln

	// Make sure cancellation of the parent context
	// also unblocks Accept().
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		select {
		case <-s.ctx.Done():
			_ = ln.Close()

		case <-time.After(365 * 24 * time.Hour):
			// Defensive fallback.
		}
	}()

	log.Printf(
		"[relay] listening on %s",
		listenAddr,
	)

	for {
		conn, err := ln.Accept()

		if err != nil {
			select {
			case <-s.ctx.Done():
				s.closeAllSessions()
				return nil

			default:
			}

			if errors.Is(
				err,
				net.ErrClosed,
			) {
				s.closeAllSessions()
				return nil
			}

			log.Printf(
				"[relay] accept error: %v",
				err,
			)

			continue
		}

		s.wg.Add(1)

		go func(c net.Conn) {
			defer s.wg.Done()

			s.handleConnection(c)
		}(conn)
	}
}

// ============================================================
// SERVER CLOSE
// ============================================================

func (s *RelayServer) Close() {
	if s == nil {
		return
	}

	s.closeOnce.Do(func() {

		if s.cancel != nil {
			s.cancel()
		}

		if s.listener != nil {
			_ = s.listener.Close()
		}

		s.closeAllSessions()

		s.wg.Wait()
	})
}

func (s *RelayServer) closeAllSessions() {
	if s == nil ||
		s.registry == nil {

		return
	}

	s.registry.mu.RLock()

	sessions := make(
		[]*relaySession,
		0,
		len(s.registry.sessions),
	)

	for _, session := range s.registry.sessions {
		sessions = append(
			sessions,
			session,
		)
	}

	s.registry.mu.RUnlock()

	for _, session := range sessions {
		if session != nil {
			session.close()
		}
	}
}

// ============================================================
// CONNECTION HANDLER
// ============================================================

func (s *RelayServer) handleConnection(
	conn net.Conn,
) {
	if conn == nil {
		return
	}

	ctx := s.ctx

	if ctx == nil {
		ctx = context.Background()
	}

	// --------------------------------------------------------
	// 1. Relay authentication
	// --------------------------------------------------------

	if err := conn.SetDeadline(
		time.Now().Add(relayAuthTimeout),
	); err != nil {
		_ = conn.Close()
		return
	}

	frame, err := readRelayFrame(
		conn,
		s.config.MaxFrameSize,
	)
	if err != nil {
		_ = conn.Close()

		log.Printf(
			"[relay] authentication frame failed: %v",
			err,
		)

		return
	}

	if frame.Type != relayMsgHello {
		_ = conn.Close()

		log.Printf(
			"[relay] first message was not HELLO",
		)

		return
	}

	peerID, err := verifyRelayHello(frame)
	if err != nil {
		_ = conn.Close()

		log.Printf(
			"[relay] rejected relay client: %v",
			err,
		)

		return
	}

	// --------------------------------------------------------
	// 2. Create authenticated session
	// --------------------------------------------------------

	session := newRelaySession(
		ctx,
		peerID,
		conn,
	)

	// The HELLO nonce must not be reusable.
	if !session.acceptNonce(frame.Nonce) {
		session.close()

		log.Printf(
			"[relay] rejected replayed HELLO PeerID=%s",
			peerID,
		)

		return
	}

	if err := s.registry.Add(
		session,
	); err != nil {

		_ = writeRelayFrame(
			conn,
			relayFrame{
				Version:   relayProtocolVersion,
				Type:      relayMsgOpenReject,
				Timestamp: time.Now().UnixMilli(),
				Nonce:     secureRelayNonce(),
				Error:     err.Error(),
			},
		)

		session.close()

		return
	}

	// --------------------------------------------------------
	// 3. Authentication is complete.
	// --------------------------------------------------------

	if err := conn.SetDeadline(
		time.Time{},
	); err != nil {
		s.registry.Remove(
			peerID,
			session,
		)

		session.close()

		return
	}

	log.Printf(
		"[relay] authenticated PeerID=%s",
		peerID,
	)

	// --------------------------------------------------------
	// 4. Start the single session writer.
	// --------------------------------------------------------

	startRelaySessionWriter(
		session,
	)

	// --------------------------------------------------------
	// 5. HELLO_ACK
	// --------------------------------------------------------

	ack := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgHelloAck,
		SourcePeerID: peerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        secureRelayNonce(),
	}

	if err := relayServerWrite(
		session,
		ack,
	); err != nil {

		s.registry.Remove(
			peerID,
			session,
		)

		session.close()

		return
	}

	// --------------------------------------------------------
	// 6. Session cleanup.
	// --------------------------------------------------------

	defer func() {

		s.removeRoutesForPeer(
			peerID,
		)

		s.registry.Remove(
			peerID,
			session,
		)

		session.close()

		log.Printf(
			"[relay] session closed PeerID=%s",
			peerID,
		)
	}()

	// --------------------------------------------------------
	// 7. Main session loop.
	// --------------------------------------------------------

	for {
		select {
		case <-session.ctx.Done():
			return

		default:
		}

		if session.idleFor() >
			s.config.IdleTimeout {

			log.Printf(
				"[relay] idle timeout PeerID=%s",
				peerID,
			)

			return
		}

		if err := conn.SetReadDeadline(
			time.Now().Add(60 * time.Second),
		); err != nil {
			return
		}

		frame, err := readRelayFrame(
			conn,
			s.config.MaxFrameSize,
		)

		if err != nil {

			if errors.Is(
				err,
				net.ErrClosed,
			) ||
				errors.Is(
					err,
					io.EOF,
				) {

				return
			}

			if isRelayTimeout(err) {
				continue
			}

			log.Printf(
				"[relay] read error PeerID=%s: %v",
				peerID,
				err,
			)

			return
		}

		session.touch()

		// ----------------------------------------------------
		// Every authenticated control frame must carry the
		// authenticated session identity.
		// ----------------------------------------------------

		switch frame.Type {

		case relayMsgHello:
			// HELLO is allowed only once.
			log.Printf(
				"[relay] duplicate HELLO PeerID=%s",
				peerID,
			)

			return

		case relayMsgOpen:

			if frame.SourcePeerID != peerID {
				log.Printf(
					"[relay] OPEN source identity mismatch PeerID=%s",
					peerID,
				)

				return
			}

			s.handleOpen(
				session,
				frame,
			)

		case relayMsgData:

			if frame.SourcePeerID != peerID {
				log.Printf(
					"[relay] DATA source identity mismatch PeerID=%s",
					peerID,
				)

				return
			}

			s.handleData(
				session,
				frame,
			)

		case relayMsgClose:

			if frame.SourcePeerID != "" &&
				frame.SourcePeerID != peerID {

				log.Printf(
					"[relay] CLOSE source identity mismatch PeerID=%s",
					peerID,
				)

				return
			}

			return

		case relayMsgPing:

			if frame.Nonce == 0 {
				log.Printf(
					"[relay] PING without nonce PeerID=%s",
					peerID,
				)

				continue
			}

			if !session.acceptNonce(
				frame.Nonce,
			) {
				log.Printf(
					"[relay] replayed PING PeerID=%s",
					peerID,
				)

				continue
			}

			_ = relayServerWrite(
				session,
				relayFrame{
					Version:      relayProtocolVersion,
					Type:         relayMsgPong,
					SourcePeerID: peerID,
					Timestamp:    time.Now().UnixMilli(),
					Nonce:        frame.Nonce,
				},
			)

		case relayMsgPong:
			// PONG is a response to a previously sent PING.
			// No forwarding is required.

		case relayMsgHelloAck,
			relayMsgOpenAck,
			relayMsgOpenReject:

			// These are server-generated control messages.
			// A normal authenticated client must never inject
			// them into the server.
			log.Printf(
				"[relay] invalid client control message type=%d PeerID=%s",
				frame.Type,
				peerID,
			)

		default:

			log.Printf(
				"[relay] unsupported message type=%d PeerID=%s",
				frame.Type,
				peerID,
			)
		}
	}
}

// ============================================================
// OPEN / TUNNEL ESTABLISHMENT
// ============================================================

func (s *RelayServer) handleOpen(
	source *relaySession,
	frame relayFrame,
) {
	if s == nil ||
		source == nil {

		return
	}

	// --------------------------------------------------------
	// Source identity.
	// --------------------------------------------------------

	if frame.SourcePeerID != source.peerID {
		s.rejectOpen(
			source,
			frame,
			"source PeerID does not match authenticated session",
		)

		return
	}

	// --------------------------------------------------------
	// Timestamp.
	// --------------------------------------------------------

	if err := validateRelayTimestamp(
		frame.Timestamp,
	); err != nil {

		s.rejectOpen(
			source,
			frame,
			err.Error(),
		)

		return
	}

	// --------------------------------------------------------
	// Nonce.
	// --------------------------------------------------------

	if frame.Nonce == 0 {
		s.rejectOpen(
			source,
			frame,
			"OPEN nonce is missing",
		)

		return
	}

	if !source.acceptNonce(
		frame.Nonce,
	) {
		s.rejectOpen(
			source,
			frame,
			"OPEN nonce replay detected",
		)

		return
	}

	// --------------------------------------------------------
	// Target.
	// --------------------------------------------------------

	if frame.TargetPeerID == "" {
		s.rejectOpen(
			source,
			frame,
			"target peer ID is empty",
		)

		return
	}

	// --------------------------------------------------------
	// A client cannot open a tunnel to itself.
	// --------------------------------------------------------

	if frame.TargetPeerID ==
		source.peerID {

		s.rejectOpen(
			source,
			frame,
			"cannot open relay tunnel to self",
		)

		return
	}

	// --------------------------------------------------------
	// Target must be authenticated on this relay.
	// --------------------------------------------------------

	target, ok := s.registry.Get(
		frame.TargetPeerID,
	)

	if !ok || target == nil {
		s.rejectOpen(
			source,
			frame,
			"target peer is not connected to this relay",
		)

		return
	}

	// --------------------------------------------------------
	// Install both directions.
	// --------------------------------------------------------

	s.addRoute(
		source.peerID,
		target.peerID,
	)

	s.addRoute(
		target.peerID,
		source.peerID,
	)

	// --------------------------------------------------------
	// ACK source.
	// --------------------------------------------------------

	accept := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgOpenAck,
		SourcePeerID: source.peerID,
		TargetPeerID: target.peerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        frame.Nonce,
	}

	if err := relayServerWrite(
		source,
		accept,
	); err != nil {

		s.removeRoute(
			source.peerID,
			target.peerID,
		)

		s.removeRoute(
			target.peerID,
			source.peerID,
		)

		return
	}

	// --------------------------------------------------------
	// Notify target.
	//
	// relay2.go will interpret this unsolicited OPEN_ACK as
	// an incoming relay tunnel notification.
	// --------------------------------------------------------

	targetNotice := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgOpenAck,
		SourcePeerID: source.peerID,
		TargetPeerID: target.peerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        frame.Nonce,
	}

	if err := relayServerWrite(
		target,
		targetNotice,
	); err != nil {

		log.Printf(
			"[relay] target notification failed %s -> %s: %v",
			source.peerID,
			target.peerID,
			err,
		)

		s.removeRoute(
			source.peerID,
			target.peerID,
		)

		s.removeRoute(
			target.peerID,
			source.peerID,
		)

		return
	}

	log.Printf(
		"[relay] route established %s <-> %s",
		source.peerID,
		target.peerID,
	)
}

func (s *RelayServer) rejectOpen(
	source *relaySession,
	frame relayFrame,
	reason string,
) {
	if source == nil {
		return
	}

	_ = relayServerWrite(
		source,
		relayFrame{
			Version:      relayProtocolVersion,
			Type:         relayMsgOpenReject,
			SourcePeerID: source.peerID,
			TargetPeerID: frame.TargetPeerID,
			Timestamp:    time.Now().UnixMilli(),
			Nonce:        frame.Nonce,
			Error:        reason,
		},
	)
}

// ============================================================
// DATA FORWARDING
// ============================================================

func (s *RelayServer) handleData(
	source *relaySession,
	frame relayFrame,
) {
	if s == nil ||
		source == nil {

		return
	}

	// --------------------------------------------------------
	// Source identity.
	// --------------------------------------------------------

	if frame.SourcePeerID != source.peerID {
		log.Printf(
			"[relay] DATA source identity mismatch PeerID=%s",
			source.peerID,
		)

		return
	}

	// --------------------------------------------------------
	// Timestamp.
	// --------------------------------------------------------

	if err := validateRelayTimestamp(
		frame.Timestamp,
	); err != nil {

		log.Printf(
			"[relay] invalid DATA timestamp PeerID=%s: %v",
			source.peerID,
			err,
		)

		return
	}

	// --------------------------------------------------------
	// Target.
	// --------------------------------------------------------

	if frame.TargetPeerID == "" {
		log.Printf(
			"[relay] DATA target missing PeerID=%s",
			source.peerID,
		)

		return
	}

	// --------------------------------------------------------
	// Nonce.
	// --------------------------------------------------------

	if frame.Nonce == 0 {
		log.Printf(
			"[relay] DATA nonce missing PeerID=%s",
			source.peerID,
		)

		return
	}

	if !source.acceptNonce(
		frame.Nonce,
	) {
		log.Printf(
			"[relay] DATA nonce replay PeerID=%s",
			source.peerID,
		)

		return
	}

	// --------------------------------------------------------
	// Payload.
	// --------------------------------------------------------

	if err := validateRelayDataPayload(
		frame.Payload,
	); err != nil {

		log.Printf(
			"[relay] invalid DATA PeerID=%s: %v",
			source.peerID,
			err,
		)

		return
	}

	// --------------------------------------------------------
	// Route authorization.
	//
	// This is important:
	// an authenticated client cannot simply inject DATA toward
	// any arbitrary PeerID. An OPEN must have established the
	// route first.
	// --------------------------------------------------------

	if !s.hasRoute(
		source.peerID,
		frame.TargetPeerID,
	) {

		log.Printf(
			"[relay] DATA without established route %s -> %s",
			source.peerID,
			frame.TargetPeerID,
		)

		return
	}

	// --------------------------------------------------------
	// Target session.
	// --------------------------------------------------------

	target, ok := s.registry.Get(
		frame.TargetPeerID,
	)

	if !ok || target == nil {

		s.removeRoute(
			source.peerID,
			frame.TargetPeerID,
		)

		s.removeRoute(
			frame.TargetPeerID,
			source.peerID,
		)

		_ = relayServerWrite(
			source,
			relayFrame{
				Version:      relayProtocolVersion,
				Type:         relayMsgOpenReject,
				SourcePeerID: source.peerID,
				TargetPeerID: frame.TargetPeerID,
				Timestamp:    time.Now().UnixMilli(),
				Nonce:        frame.Nonce,
				Error:        "target peer is no longer connected",
			},
		)

		return
	}

	if target == source {
		return
	}

	// --------------------------------------------------------
	// IMPORTANT:
	//
	// The relay forwards the EXPLOSIVE P2P bytes opaquely.
	//
	// It does NOT:
	//
	// - decode EXPLOSIVE Envelope
	// - modify wallet signatures
	// - modify wallet identity
	// - inspect transactions
	// - inspect blocks
	// - validate DailyPoW
	//
	// The destination Peer.readLoop() performs the normal
	// EXPLOSIVE validation.
	// --------------------------------------------------------

	forward := relayFrame{
		Version:      relayProtocolVersion,
		Type:         relayMsgData,
		SourcePeerID: source.peerID,
		TargetPeerID: target.peerID,
		Timestamp:    time.Now().UnixMilli(),
		Nonce:        secureRelayNonce(),
		Payload:      append(
			[]byte(nil),
			frame.Payload...,
		),
	}

	if err := relayServerWrite(
		target,
		forward,
	); err != nil {

		log.Printf(
			"[relay] forwarding error %s -> %s: %v",
			source.peerID,
			target.peerID,
			err,
		)

		target.close()

		return
	}

	target.touch()
}

// ============================================================
// RELAY SESSION WRITER
// ============================================================

// relayServerWrite serializes all writes to one relay session.
//
// Every normal server-generated frame enters sendQ.
// Exactly one writer goroutine consumes sendQ.
func relayServerWrite(
	session *relaySession,
	frame relayFrame,
) error {
	if session == nil {
		return errors.New(
			"nil relay session",
		)
	}

	if session.ctx == nil {
		return errors.New(
			"relay session context is nil",
		)
	}

	data, err := encodeRelayFrame(
		frame,
	)
	if err != nil {
		return fmt.Errorf(
			"encode relay frame: %w",
			err,
		)
	}

	if len(data) < 5 {
		return errors.New(
			"encoded relay frame is empty",
		)
	}

	if len(data)-4 > relayMaxFrameSize {
		return fmt.Errorf(
			"relay frame exceeds maximum size: %d",
			len(data)-4,
		)
	}

	select {
	case session.sendQ <- data:
		session.touch()
		return nil

	case <-session.ctx.Done():
		return net.ErrClosed

	default:
		return errors.New(
			"relay session outbound queue is full",
		)
	}
}

// ============================================================
// SESSION WRITER
// ============================================================

func startRelaySessionWriter(
	session *relaySession,
) {
	if session == nil {
		return
	}

	go func() {

		for {
			select {

			case <-session.ctx.Done():
				return

			case data, ok := <-session.sendQ:

				if !ok {
					return
				}

				if len(data) < 5 {
					session.close()
					return
				}

				if len(data)-4 > relayMaxFrameSize {
					session.close()
					return
				}

				session.writeMu.Lock()

				_, err := session.conn.Write(
					data,
				)

				session.writeMu.Unlock()

				if err != nil {
					session.close()
					return
				}

				session.touch()
			}
		}
	}()
}

// ============================================================
// RELAY FRAME ENCODING
// ============================================================

// encodeRelayFrame produces the same wire format as
// writeRelayFrame() in relay.go:
//
//	4-byte big-endian size
//	CBOR relayFrame
//
// The returned []byte is placed directly into relaySession.sendQ.
func encodeRelayFrame(
	frame relayFrame,
) ([]byte, error) {

	if frame.Version == 0 {
		frame.Version = relayProtocolVersion
	}

	if frame.Version != relayProtocolVersion {
		return nil, fmt.Errorf(
			"unsupported relay protocol version: %d",
			frame.Version,
		)
	}

	payload, err := cbor.Marshal(
		frame,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"relay frame CBOR encoding failed: %w",
			err,
		)
	}

	if len(payload) == 0 {
		return nil, errors.New(
			"empty relay frame",
		)
	}

	if len(payload) > relayMaxFrameSize {
		return nil, fmt.Errorf(
			"relay frame too large: %d > %d",
			len(payload),
			relayMaxFrameSize,
		)
	}

	result := make(
		[]byte,
		4+len(payload),
	)

	binary.BigEndian.PutUint32(
		result[:4],
		uint32(len(payload)),
	)

	copy(
		result[4:],
		payload,
	)

	return result, nil
}

// ============================================================
// TIMEOUT HELPER
// ============================================================

func isRelayTimeout(
	err error,
) bool {
	if err == nil {
		return false
	}

	var netErr net.Error

	if errors.As(
		err,
		&netErr,
	) {
		return netErr.Timeout()
	}

	return false
}
