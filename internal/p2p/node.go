// internal/p2p/node.go
package p2p

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"explosive/internal/ledger"
)

/* =========================
   PAYLOAD (UTILISÉ POUR P2P DISCOVERY)
   ========================= */

// ✔ UTILE : utilisé pour échange de peers (Bootstrap / discovery)
type PeersPayload struct {
	Addrs []string
}

/* =========================
   CONFIG
   ========================= */

type NodeConfig struct {
	ListenAddr              string
	DialTimeout             time.Duration
	ConnReadTimeout         time.Duration
	ConnWriteTimeout        time.Duration
	FlushInterval           time.Duration
	PeerDialPeriod          time.Duration
	MaxPeers                int
	SendQueueSize           int
	MaxMsgSize              int
	ProtocolName            string
	ProtocolVer             string
	MaxIncomingQueue        int
	AcceptWorkers           int
	MaxBroadcastFanout      int
	RequireSignedMessages   bool
	PeerEvictionTimeout     time.Duration
	PeerInvalidMsgThreshold int
	RequireStrictBlockSig   bool
	RequireSignedTx         bool
	IsSeedNode              bool
}

/* =========================
   INTERNAL TYPES
   ========================= */

type incomingMsg struct {
	peer *Peer
	env  *Envelope
}

type Node struct {
	id              PeerID
	listenAddr      string
	networkID       string
	userAgent       string
	protocolVersion uint16
	config          NodeConfig

	ln         net.Listener
	tlsConfig  *tls.Config
	peerShards []peerShard
	numShards  int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	inboundCh chan *incomingMsg

	handlerMux sync.RWMutex
	handlers   map[MessageType]func(*Peer, *Envelope)

	Ledger *ledger.Ledger

	// ------------------------------------------------------------------
	// WALLET PUBLIC IDENTITY
	// ------------------------------------------------------------------
	// The wallet address and public key are public identity data.
	// Private keys, passwords, mnemonics and sacred words must never
	// be stored here or transmitted through P2P.
	walletIdentityMu sync.RWMutex
	walletAddress    string
	walletPublicKey  []byte

	// ------------------------------------------------------------------
	// WALLET SIGNER
	// ------------------------------------------------------------------
	// The P2P node never stores a private key or wallet password.
	// Signing is delegated to the wallet layer through this callback.
	//
	// The callback receives data to sign and returns the Ed25519
	// signature. Private key handling remains entirely outside P2P.
	walletSignerMu sync.RWMutex
	walletSigner   func([]byte) ([]byte, error)

	Peers      []*Peer
	PeersMutex sync.RWMutex

	// ------------------------------------------------------------------
	// TLS IDENTITY CACHE
	// ------------------------------------------------------------------
	tlsPeerCache sync.Map

	// ------------------------------------------------------------------
	// METRICS
	// ------------------------------------------------------------------
	metricsMu          sync.Mutex
	numInvalidMessages int

	GlobalMetrics     MetricsPayload
	CachedMetrics     MetricsData
	cachedMetricsOnce bool

	// ------------------------------------------------------------------
	// ANTI-REPLAY SYSTEM
	// ------------------------------------------------------------------
	seenNonces       sync.Map
	seenNoncesMutex  sync.Mutex
	lastNonceCleanup time.Time

	// ------------------------------------------------------------------
	// NONCE TRACKING (ANTI-REPLAY / ANTI-SPAM)
	// ------------------------------------------------------------------
	nonceCount map[string]int // per-nonce tracking
	nonceTotal int64          // global counter
	nonceMu    sync.Mutex

	// ------------------------------------------------------------------
	// ANTI-SPAM / RATE LIMITING (NODE-LEVEL)
	// ------------------------------------------------------------------
	peerLastMsg   sync.Map // map[PeerID]time.Time
	peerSpamScore sync.Map // map[PeerID]int
	rateLimitMu   sync.Mutex

	// ------------------------------------------------------------------
	// PEER IP TRACKING (ANTI-SYBIL / CLUSTER DETECTION)
	// ------------------------------------------------------------------
	peerIPMutex sync.RWMutex

	// map[ip]count
	peerIPCount map[string]int

	// map[peerID]time (last seen per peer)
	peerLastSeen sync.Map

	// map[peerID]int reputation score
	peerReputation sync.Map
}

// This design maintains full decentralization (no central CA required) while providing
// confidentiality, integrity, and strong resistance to network-level attacks and throttling.

func NewNode(listenAddr, networkID, userAgent string, minerID string, sacredWords []string) (*Node, error) {

	// --- Normalize listen address (dual-stack safe) ---
	listenAddr = normalizeListenAddr(listenAddr, 8443)

	// --- Generate deterministic TLS certificate ---
	tlsCert, err := generateDeterministicTLSCert(minerID, sacredWords)
	if err != nil {
		return nil, err
	}

	// --- Stable Node ID derived from TLS public key ---
	pub, ok := tlsCert.Leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("TLS certificate public key is not Ed25519")
	}

	id := PeerID(hex.EncodeToString(pub))

	// --- Create Node instance ---
	n := &Node{}

	// --- Anti-replay / nonce tracking init ---
	n.nonceCount = make(map[string]int)

	// --- Anti-Sybil / IP tracking init ---
	n.peerIPCount = make(map[string]int)

	// --- TLS configuration ---
	n.tlsConfig = n.setupTLSConfig(tlsCert)

	// --- Node configuration ---
	cfg := NodeConfig{
		ListenAddr:       listenAddr,
		DialTimeout:      60 * time.Second,
		ConnReadTimeout:  90 * time.Second,
		ConnWriteTimeout: 90 * time.Second,
		FlushInterval:    500 * time.Millisecond,
		PeerDialPeriod:   30 * time.Second,

		MaxPeers:      80,
		SendQueueSize: 32,
		MaxMsgSize:    384 * 1024,

		ProtocolName: "explosive-p2p",
		ProtocolVer:  "1.0",

		MaxIncomingQueue:   64,
		AcceptWorkers:      2,
		MaxBroadcastFanout: 14,

		RequireSignedMessages: true,
		RequireStrictBlockSig: true,
		RequireSignedTx:       true,

		PeerEvictionTimeout:     25 * time.Minute,
		PeerInvalidMsgThreshold: 4,
	}

	// --- Context lifecycle ---
	ctx, cancel := context.WithCancel(context.Background())

	// --- Peer sharding ---
	shards := make([]peerShard, 64)

	for i := range shards {
		shards[i] = peerShard{
			peers: make(map[PeerID]*Peer),
		}
	}

	// --- Assign core fields ---
	n.id = id
	n.listenAddr = listenAddr
	n.networkID = networkID
	n.userAgent = userAgent
	n.config = cfg

	// 🔐 CRITICAL FIX
	// Prevent handshake Version=0
	n.protocolVersion = CurrentProtocolVersion

	n.peerShards = shards
	n.numShards = len(shards)

	n.ctx = ctx
	n.cancel = cancel

	// --- Channels & handlers ---
	n.inboundCh = make(chan *incomingMsg, 1024)

	n.handlers = make(map[MessageType]func(*Peer, *Envelope))

	// --- Critical state initialization ---
	n.cachedMetricsOnce = false
	n.lastNonceCleanup = time.Now()

	log.Printf(
		"[p2p] protocol initialized: version=%d nodeID=%s",
		n.protocolVersion,
		n.id,
	)

	// --- Register protocol handlers ---
	n.registerDefaultHandlers()
	go n.processIncoming()

	return n, nil
}

func (n *Node) SetWalletIdentity(walletAddress string, publicKey []byte) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	walletAddress = strings.TrimSpace(walletAddress)
	if walletAddress == "" {
		return errors.New("wallet address is empty")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid wallet public key size: got %d, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}

	// Copy the public key so callers cannot mutate node identity
	// through the original byte slice.
	pubCopy := make([]byte, len(publicKey))
	copy(pubCopy, publicKey)

	n.walletIdentityMu.Lock()
	n.walletAddress = walletAddress
	n.walletPublicKey = pubCopy
	n.walletIdentityMu.Unlock()

	return nil
}

// SetWalletSigner configures the local wallet signing callback.
//
// SECURITY:
//   - The P2P node does not receive or store a private key.
//   - The P2P node does not receive or store a wallet password.
//   - The wallet layer remains responsible for secure key handling.
//   - Only the signing callback is retained by the node.
func (n *Node) SetWalletSigner(signer func([]byte) ([]byte, error)) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	if signer == nil {
		return errors.New("wallet signer is nil")
	}

	n.walletSignerMu.Lock()
	n.walletSigner = signer
	n.walletSignerMu.Unlock()

	return nil
}

// signWalletData delegates signing to the configured wallet signer.
//
// The private key never enters the P2P package.
func (n *Node) signWalletData(data []byte) ([]byte, error) {
	if n == nil {
		return nil, errors.New("nil P2P node")
	}

	if len(data) == 0 {
		return nil, errors.New("data to sign is empty")
	}

	n.walletSignerMu.RLock()
	signer := n.walletSigner
	n.walletSignerMu.RUnlock()

	if signer == nil {
		return nil, errors.New("wallet signer is not configured")
	}

	signature, err := signer(data)
	if err != nil {
		return nil, fmt.Errorf("wallet signing failed: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid wallet signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	// Copy the result so the callback cannot mutate the returned
	// signature after this function returns.
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	return sigCopy, nil
}

// normalizeListenAddr converts the provided listen address into a dual-stack compatible format.
//
// The function ensures the node binds to a single socket capable of accepting both IPv4 and IPv6
// connections by preferring the "[::]:port" format when possible. This leverages Go's native
// dual-stack support without requiring separate listeners.
//
// - Empty address → "[::]:defaultPort"
// - Port-only (e.g. ":8443") → "[::]:8443"
// - Already valid IPv6 or IPv4 address → returned unchanged
func normalizeListenAddr(addr string, defaultPort int) string {
	if addr == "" {
		return fmt.Sprintf("[::]:%d", defaultPort)
	}

	// Port only → dual stack
	if !strings.Contains(addr, ":") {
		return fmt.Sprintf("[::]:%s", addr)
	}

	return addr
}

// generateDeterministicTLSCert creates a self-signed Ed25519 TLS certificate.
//
// If a valid miner identity is provided (walletID + exactly 4 sacred words),
// a deterministic *sub-key* is derived specifically for TLS usage.
func generateDeterministicTLSCert(walletID string, words []string) (tls.Certificate, error) {

	var priv ed25519.PrivateKey

	if walletID != "" && len(words) == 4 {
		seed := sha256.Sum256([]byte(walletID + "|" + strings.Join(words, " ") + "|TLS_V1"))
		priv = ed25519.NewKeyFromSeed(seed[:])
	} else {
		_, p, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		priv = p
	}

	now := time.Now()

	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		Subject: pkix.Name{
			CommonName: walletID,
		},
	}

	certDER, err := x509.CreateCertificate(
		cryptorand.Reader,
		&template,
		&template,
		priv.Public(),
		priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 🔥 CRITICAL FIX: parse Leaf
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])

	return cert, nil
}

// sha256Sum computes the SHA-256 hash of a string and returns the raw bytes
func sha256Sum(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}

// Start launches the P2P node with full TLS encryption and dual-stack IPv4/IPv6 listening.
//
// It uses the pre-generated tlsConfig from NewNode (deterministic or random self-signed Ed25519 certificate)
// to create a secure TLS listener. All inbound connections are automatically upgraded to TLS.
//
// The rest of the node lifecycle (accept loop, message processing, watchdog, bootstrap, etc.)
// remains unchanged and works transparently over the encrypted tls.Listener.
func (n *Node) Start() error {
	if n.listenAddr == "" {
		return errors.New("listen address not set")
	}

	if n.tlsConfig == nil {
		return errors.New("TLS configuration missing - node must be created with TLS support")
	}

	// Create a TLS listener using the deterministic or fallback certificate
	ln, err := tls.Listen("tcp", n.listenAddr, n.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener on %s: %w", n.listenAddr, err)
	}
	n.ln = ln

	log.Printf("p2p: 🔒 Secure TLS node listening on %s (id=%s, dual-stack IPv4/IPv6)", n.listenAddr, n.id)
	log.Printf("p2p: TLS certificate subject: CN=%s (deterministic V3 identity)",
		n.tlsConfig.Certificates[0].Leaf.Subject.CommonName)

	// --- Accept incoming encrypted connections ---
	n.wg.Add(1)
	go n.acceptLoop()

	// --- Process inbound messages ---
	n.wg.Add(1)

	// --- Watchdog: peer eviction + periodic block sync ---
	n.wg.Add(1)
	go n.watchdogLoop()

	// --- Bootstrap: connect to seed nodes over TLS ---
	n.Bootstrap()

	// --- Automatic peer reconnection loop ---
	n.wg.Add(1)
	go n.PeerReconnectLoop()

	return nil
}

// Stop gracefully stops the node.
func (n *Node) Stop() {
	n.cancel()
	if n.ln != nil {
		_ = n.ln.Close()
	}
	// take snapshot of peers and close to avoid locking during Close which may call back
	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		for _, p := range sh.peers {
			p.Close()
		}
		sh.mu.RUnlock()
	}
	n.wg.Wait()
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	connCh := make(chan net.Conn, n.config.MaxIncomingQueue)

	// Start worker goroutines to process incoming connections
	for i := 0; i < n.config.AcceptWorkers; i++ {
		n.wg.Add(1)
		go n.connWorker(connCh)
	}

	for {
		conn, err := n.ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				// Node is shutting down — exit gracefully
				return
			default:
				log.Printf("[p2p] ⚠️ Accept error: %v", err)
				continue
			}
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("[p2p] ⚡ New incoming TCP connection from %s", remoteAddr)

		// Enforce global maximum peer limit
		currentPeers := n.PeerCount()
		if currentPeers >= n.config.MaxPeers {
			log.Printf("[p2p] ⚠️ Max peers reached (%d/%d) — rejecting connection from %s",
				currentPeers, n.config.MaxPeers, remoteAddr)
			_ = conn.Close()
			continue
		}

		// Queue the connection for processing (non-blocking)
		select {
		case connCh <- conn:
			// Successfully queued
		default:
			log.Printf("[p2p] ⚠️ Incoming queue full — dropping connection from %s", remoteAddr)
			_ = conn.Close()
		}
	}
}

func (n *Node) connWorker(ch <-chan net.Conn) {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case conn := <-ch:
			n.handleNewConnection(conn)
		}
	}
}

// handleNewConnection processes an incoming TCP connection from a remote peer.
// It initializes the Peer object, starts the read/write loops, registers the peer internally,
// and proactively sends our handshake with a randomized jitter delay to complete the
// bidirectional handshake process reliably in a fully decentralized mobile environment.
//
// This is critical for pure P2P networks without central servers: both inbound and outbound
// connections must complete a mutual handshake to establish trust and protocol compatibility.
func (n *Node) handleNewConnection(conn net.Conn) {

	// Write deadline only.
	// Read deadlines are managed dynamically inside readLoop().
	_ = conn.SetWriteDeadline(
		time.Now().Add(n.config.ConnWriteTimeout),
	)

	peerAddr := conn.RemoteAddr().String()

	// IMPORTANT:
	// Never assign a temporary identity here.
	// The real PeerID must be established only
	// after TLS validation + successful handshake.
	p := NewPeer("", peerAddr, n)

	p.mu.Lock()
	p.conn = conn
	p.connected = true
	p.lastSeen = time.Now()
	p.mu.Unlock()

	// Start peer lifecycle workers.
	p.wg.Add(2)

	go p.readLoop()
	go p.writeLoop()

	// Send handshake with randomized jitter
	// to reduce simultaneous handshake collisions.
	go func() {

		delay :=
			time.Duration(
				100+rand.Intn(500),
			) * time.Millisecond

		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {

		case <-n.ctx.Done():
			return

		case <-timer.C:

			log.Printf(
				"[p2p] 🚀 Sending inbound handshake to %s",
				peerAddr,
			)

			if err := p.sendHandshake(); err != nil {

				log.Printf(
					"[p2p] ❌ inbound handshake failed: %v",
					err,
				)

				p.Close()

				return
			}
		}
	}()
}

func (n *Node) addPeer(p *Peer) {
	if p == nil || p.id == "" {
		return
	}

	sh := n.shard(p.id)

	// Check peer limit without holding the target shard lock.
	// PeerCount() acquires read locks on all shards.
	currentCount := n.PeerCount()

	sh.mu.Lock()

	// Re-check whether this peer already exists.
	_, alreadyExists := sh.peers[p.id]

	if !alreadyExists && currentCount >= n.config.MaxPeers {
		sh.mu.Unlock()

		log.Printf("[p2p] ⚠️ Peer limit exceeded (%d/%d) — rejecting peer %s (%s)",
			currentCount, n.config.MaxPeers, p.id, p.addr)

		p.Close()
		return
	}

	oldPeer, exists := sh.peers[p.id]
	sh.peers[p.id] = p

	sh.mu.Unlock()

	n.PeersMutex.Lock()

	replaced := false
	for i, peer := range n.Peers {
		if peer.id == p.id {
			n.Peers[i] = p
			replaced = true
			break
		}
	}

	if !replaced {
		n.Peers = append(n.Peers, p)
	}

	n.PeersMutex.Unlock()

	newTotal := n.PeerCount()

	if exists && oldPeer != p {
		log.Printf(
			"[p2p] ♻️ Peer updated: id=%s addr=%s (total connected peers: %d)",
			p.id, p.addr, newTotal,
		)
	} else if !exists {
		log.Printf(
			"[p2p] 🌱 New peer successfully added: id=%s addr=%s (total connected peers: %d)",
			p.id, p.addr, newTotal,
		)
	}
}

// Connect dials a remote peer.
// Enhanced with randomized handshake jitter delay on outbound connections
// to prevent simultaneous handshake collisions in mutual connections.
func (n *Node) Connect(addr string) (*Peer, error) {

	p := NewPeer("", addr, n)

	if err := p.Connect(); err != nil {
		return nil, err
	}

	return p, nil
}

// PeerCount returns the total number of peers across shards.
func (n *Node) PeerCount() int {
	total := 0
	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		total += len(sh.peers)
		sh.mu.RUnlock()
	}
	return total
}

func (n *Node) setupTLSConfig(tlsCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},

		// === CORRECTION PRINCIPALE ===
		MinVersion: tls.VersionTLS12, // Autorise TLS 1.2 + 1.3
		MaxVersion: tls.VersionTLS13,

		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},

		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},

		PreferServerCipherSuites: true,
		InsecureSkipVerify:       true, // On garde pour le moment (self-signed)

		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing certificate")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			// Expiration check
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("certificate expired or not yet valid")
			}

			// Key type enforcement
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("only ed25519 allowed")
			}

			// Extract peer identity
			peerID := PeerID(hex.EncodeToString(pub))
			n.tlsPeerCache.Store(string(peerID), time.Now())

			return nil
		},
	}
}

func (n *Node) processIncoming() {
	for {
		select {

		case <-n.ctx.Done():
			return

		case msg := <-n.inboundCh:

			if msg == nil || msg.peer == nil || msg.env == nil {
				continue
			}

			n.handlerMux.RLock()
			handler, ok := n.handlers[msg.env.Type]
			n.handlerMux.RUnlock()

			if !ok {
				log.Printf(
					"[p2p] no handler registered for %s",
					msg.env.Type,
				)
				continue
			}

			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf(
							"[p2p] handler panic type=%s err=%v",
							msg.env.Type,
							r,
						)
					}
				}()

				handler(msg.peer, msg.env)
			}()
		}
	}
}
