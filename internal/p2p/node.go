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
	"explosive/internal/address"
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

// PeerAnnouncement describes a publicly shareable network locator
// belonging to a permanent peer identity.
//
// No private key, password, mnemonic or sacred word is ever included.
type PeerAnnouncement struct {
	PeerID    PeerID `cbor:"peer_id"`
	Address   string `cbor:"address"`
	Network   string `cbor:"network,omitempty"`
	Source    string `cbor:"source,omitempty"`
	LastSeen  int64  `cbor:"last_seen,omitempty"`
	ExpiresAt int64  `cbor:"expires_at,omitempty"`
}

// PeersPayload contains public peer locators learned through discovery.
//
// The legacy Addrs field is intentionally retained for protocol compatibility
// with older EXPLOSIVE nodes.
type PeersPayload struct {
	Addrs []string           `cbor:"addrs,omitempty"`
	Peers []PeerAnnouncement `cbor:"peers,omitempty"`
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
	// BLOCKCHAIN SYNCHRONIZATION STATE
	// ------------------------------------------------------------------
	// Only one ledger synchronization session may run at a time.
	// Block exchange remains asynchronous through GETBLOCKSRANGE
	// and BLOCKSRESPONSE messages.
	syncMu      sync.Mutex
	syncRunning bool
	syncPeer    *Peer
	syncTarget  uint64

	// ------------------------------------------------------------------
	// WALLET PUBLIC IDENTITY
	// ------------------------------------------------------------------
	// The wallet address and public key are public identity data.
	// Private keys, passwords, mnemonics and sacred words must never
	// be stored here or transmitted through P2P.
	walletIdentityMu sync.RWMutex
	walletAddress    string
	walletPublicKey  []byte
	identityReady    bool

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

	// ------------------------------------------------------------------
	// MINER PUBLIC IDENTITY
	// ------------------------------------------------------------------
	// Miner identity is separate from wallet identity.
	// MinerID is normally the same public EXPLO address as the wallet,
	// but MinerPublicKey is a distinct Ed25519 key derived from the
	// miner identity credentials.
	minerIdentityMu sync.RWMutex
	minerID         string
	minerPublicKey  []byte

	// ------------------------------------------------------------------
	// MINER SIGNER
	// ------------------------------------------------------------------
	// The P2P node never stores miner private keys or sacred words.
	// Miner signing is delegated to the ledger/miner layer through
	// this callback.
	minerSignerMu sync.RWMutex
	minerSigner   func([]byte) ([]byte, error)

	Peers      []*Peer
	PeersMutex sync.RWMutex

	// ------------------------------------------------------------------
	// DURABLE KNOWN PEERS
	// ------------------------------------------------------------------
	// Peers contains only currently active network sessions.
	// knownPeers survives session disconnects and stores the latest
	// authenticated locator required to create a new session.
	//
	// Peer identity is permanent.
	// Network sessions are temporary.
	// ------------------------------------------------------------------

	knownPeersMu sync.RWMutex
	knownPeers   map[PeerID]string

	// ------------------------------------------------------------------
	// PEER DISCOVERY
	// ------------------------------------------------------------------
	// Discovery stores temporary network locators for permanent peer
	// identities. It is separate from active network sessions.
	Discovery *PeerDiscovery

	// ------------------------------------------------------------------
	// LOCAL NETWORK CANDIDATES
	// ------------------------------------------------------------------
	// NAT candidates are temporary transport locators.
	//
	// They are never used as permanent peer identity.
	// PeerID remains equal to the authenticated wallet address.
	natCandidatesMu sync.RWMutex
	natCandidates   []NATCandidate

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

	// ------------------------------------------------------------------
	// TRANSPORT ADDRESS
	// ------------------------------------------------------------------
	// The listen address is a network locator only.
	// It is never used as the permanent node identity.
	listenAddr = normalizeListenAddr(listenAddr, 8443)

	// ------------------------------------------------------------------
	// TLS TRANSPORT IDENTITY
	// ------------------------------------------------------------------
	// TLS is used to secure the transport session.
	//
	// It must NOT determine the permanent EXPLOSIVE PeerID.
	//
	// The permanent PeerID is established later from the authenticated
	// wallet identity through SetWalletIdentity().
	//
	// Miner credentials are intentionally not used to derive the TLS
	// transport identity.
	_ = minerID
	_ = sacredWords

	tlsCert, err := generateDeterministicTLSCert("", nil)
	if err != nil {
		return nil, err
	}

	// ------------------------------------------------------------------
	// CREATE NODE
	// ------------------------------------------------------------------
	n := &Node{}

	// ------------------------------------------------------------------
	// ANTI-REPLAY / NONCE TRACKING
	// ------------------------------------------------------------------
	n.nonceCount = make(map[string]int)

	// ------------------------------------------------------------------
	// ANTI-SYBIL / IP TRACKING
	// ------------------------------------------------------------------
	n.peerIPCount = make(map[string]int)

	// ------------------------------------------------------------------
	// DURABLE PEER DISCOVERY
	// ------------------------------------------------------------------
	// Discovery stores temporary network locators belonging to permanent
	// peer identities.
	n.knownPeers = make(map[PeerID]string)
	n.Discovery = NewPeerDiscovery()

	// ------------------------------------------------------------------
	// NAT / NETWORK CANDIDATES
	// ------------------------------------------------------------------
	// The candidate list contains only temporary network locators.
	// It does not contain wallet secrets or permanent peer identity.
	n.natCandidates = make([]NATCandidate, 0, 8)

	// ------------------------------------------------------------------
	// TLS CONFIGURATION
	// ------------------------------------------------------------------
	n.tlsConfig = n.setupTLSConfig(tlsCert)

	// ------------------------------------------------------------------
	// NODE CONFIGURATION
	// ------------------------------------------------------------------
	cfg := NodeConfig{
		ListenAddr:       listenAddr,
		DialTimeout:      60 * time.Second,
		ConnReadTimeout:  90 * time.Second,
		ConnWriteTimeout: 2 * time.Minute,
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

	// ------------------------------------------------------------------
	// CONTEXT LIFECYCLE
	// ------------------------------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())

	// ------------------------------------------------------------------
	// PEER SHARDING
	// ------------------------------------------------------------------
	shards := make([]peerShard, 64)

	for i := range shards {
		shards[i] = peerShard{
			peers: make(map[PeerID]*Peer),
		}
	}

	// ------------------------------------------------------------------
	// CORE NODE STATE
	// ------------------------------------------------------------------
	// IMPORTANT:
	//
	// n.id intentionally starts empty.
	//
	// The permanent PeerID is assigned only after the wallet has been
	// authenticated through SetWalletIdentity().
	n.id = ""

	n.listenAddr = listenAddr
	n.networkID = networkID
	n.userAgent = userAgent
	n.config = cfg

	// ------------------------------------------------------------------
	// PROTOCOL VERSION
	// ------------------------------------------------------------------
	n.protocolVersion = CurrentProtocolVersion

	n.peerShards = shards
	n.numShards = len(shards)

	n.ctx = ctx
	n.cancel = cancel

	// ------------------------------------------------------------------
	// CHANNELS & HANDLERS
	// ------------------------------------------------------------------
	n.inboundCh = make(chan *incomingMsg, 1024)

	n.handlers = make(map[MessageType]func(*Peer, *Envelope))

	// ------------------------------------------------------------------
	// CRITICAL STATE INITIALIZATION
	// ------------------------------------------------------------------
	n.cachedMetricsOnce = false
	n.lastNonceCleanup = time.Now()

	log.Printf(
		"[p2p] transport initialized: version=%d identity=pending",
		n.protocolVersion,
	)

	// ------------------------------------------------------------------
	// REGISTER PROTOCOL HANDLERS
	// ------------------------------------------------------------------
	n.registerDefaultHandlers()
	go n.processIncoming()

	return n, nil
}

func (n *Node) SetWalletIdentity(walletAddress string, publicKey []byte) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	walletAddress = strings.ToLower(strings.TrimSpace(walletAddress))

	if walletAddress == "" {
		return errors.New("wallet address is empty")
	}

	if !address.IsValidEXPLOAddress(walletAddress) {
		return errors.New("invalid EXPLO wallet address")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid wallet public key size: got %d, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}

	// The wallet address must be cryptographically derived
	// from the supplied Ed25519 public key.
	expectedAddress := address.GenerateEXPLOAddress(
		ed25519.PublicKey(publicKey),
	)

	if !strings.EqualFold(expectedAddress, walletAddress) {
		return errors.New(
			"wallet identity mismatch: address does not match public key",
		)
	}

	// Copy the public key so callers cannot mutate node identity
	// through the original byte slice.
	pubCopy := make([]byte, len(publicKey))
	copy(pubCopy, publicKey)

	n.walletIdentityMu.Lock()
	defer n.walletIdentityMu.Unlock()

	// A permanent wallet identity must never be silently replaced.
	if n.identityReady {
		if !strings.EqualFold(n.walletAddress, walletAddress) {
			return errors.New(
				"permanent wallet identity cannot be changed",
			)
		}

		if !ed25519.PublicKey(n.walletPublicKey).Equal(
			ed25519.PublicKey(pubCopy),
		) {
			return errors.New(
				"permanent wallet public key cannot be changed",
			)
		}

		return nil
	}

	n.walletAddress = walletAddress
	n.walletPublicKey = pubCopy

	// The wallet address is the permanent EXPLOSIVE
	// network identity of this node.
	n.id = PeerID(walletAddress)

	n.identityReady = true

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

// SetMinerIdentity configures the public miner identity used by P2P.
//
// SECURITY:
//   - Only the MinerID and public key are stored.
//   - Sacred words are never stored in the P2P node.
//   - The miner private key never enters the P2P package.
func (n *Node) SetMinerIdentity(
	minerID string,
	publicKey []byte,
) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	minerID = strings.TrimSpace(minerID)

	if minerID == "" {
		return errors.New("miner ID is empty")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid miner public key size: got %d, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}

	pubCopy := make([]byte, len(publicKey))
	copy(pubCopy, publicKey)

	n.minerIdentityMu.Lock()
	n.minerID = minerID
	n.minerPublicKey = pubCopy
	n.minerIdentityMu.Unlock()

	return nil
}

// SetMinerSigner configures the local miner signing callback.
//
// SECURITY:
//   - The P2P node does not receive or store the miner private key.
//   - The P2P node does not receive or store sacred words.
//   - The miner layer remains responsible for secure key derivation.
func (n *Node) SetMinerSigner(
	signer func([]byte) ([]byte, error),
) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	if signer == nil {
		return errors.New("miner signer is nil")
	}

	n.minerSignerMu.Lock()
	n.minerSigner = signer
	n.minerSignerMu.Unlock()

	return nil
}

// getMinerIdentity returns a defensive copy of the public miner identity.
func (n *Node) getMinerIdentity() (string, []byte) {
	if n == nil {
		return "", nil
	}

	n.minerIdentityMu.RLock()
	defer n.minerIdentityMu.RUnlock()

	minerID := n.minerID

	var pubCopy []byte
	if len(n.minerPublicKey) > 0 {
		pubCopy = make([]byte, len(n.minerPublicKey))
		copy(pubCopy, n.minerPublicKey)
	}

	return minerID, pubCopy
}

// signMinerData delegates signing to the configured miner signer.
//
// The miner private key and sacred words never enter the P2P package.
func (n *Node) signMinerData(data []byte) ([]byte, error) {
	if n == nil {
		return nil, errors.New("nil P2P node")
	}

	if len(data) == 0 {
		return nil, errors.New("data to sign is empty")
	}

	n.minerSignerMu.RLock()
	signer := n.minerSigner
	n.minerSignerMu.RUnlock()

	if signer == nil {
		return nil, errors.New("miner signer is not configured")
	}

	signature, err := signer(data)
	if err != nil {
		return nil, fmt.Errorf("miner signing failed: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid miner signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

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

func (n *Node) Start() error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	// ------------------------------------------------------------------
	// PERMANENT WALLET IDENTITY
	// ------------------------------------------------------------------
	// A P2P node must never start without a verified wallet identity.
	//
	// The permanent PeerID is established by SetWalletIdentity().
	// TLS is only the secure transport layer.
	n.walletIdentityMu.RLock()
	identityReady := n.identityReady
	walletAddress := n.walletAddress
	walletPublicKey := len(n.walletPublicKey)
	peerID := n.id
	n.walletIdentityMu.RUnlock()

	if !identityReady {
		return errors.New(
			"wallet identity is not configured; call SetWalletIdentity before Start",
		)
	}

	if walletAddress == "" {
		return errors.New(
			"wallet identity is incomplete: wallet address is empty",
		)
	}

	if walletPublicKey != ed25519.PublicKeySize {
		return errors.New(
			"wallet identity is incomplete: wallet public key is missing",
		)
	}

	if peerID == "" {
		return errors.New(
			"permanent PeerID is not initialized",
		)
	}

	if !strings.EqualFold(string(peerID), walletAddress) {
		return errors.New(
			"permanent PeerID does not match wallet address",
		)
	}

	// ------------------------------------------------------------------
	// LISTEN ADDRESS
	// ------------------------------------------------------------------
	if strings.TrimSpace(n.listenAddr) == "" {
		return errors.New("listen address not set")
	}

	// ------------------------------------------------------------------
	// TLS TRANSPORT
	// ------------------------------------------------------------------
	if n.tlsConfig == nil {
		return errors.New(
			"TLS configuration missing - node must be created with TLS support",
		)
	}

	// ------------------------------------------------------------------
	// PREVENT DOUBLE START
	// ------------------------------------------------------------------
	if n.ln != nil {
		return errors.New("P2P node is already started")
	}
	// ------------------------------------------------------------------
	// DISCOVER LOCAL NETWORK CANDIDATES
	// ------------------------------------------------------------------
	// Discover the network paths currently available on this device.
	//
	// Failure to discover a local candidate must not prevent the P2P node
	// from starting. The existing TLS + EXPLOSIVE HANDSHAKE transport
	// remains authoritative.
	if err := n.refreshNATCandidates(); err != nil {
		log.Printf(
			"[p2p] ⚠️ local network candidate discovery unavailable: %v",
			err,
		)
	}

	// ------------------------------------------------------------------
	// CREATE SECURE TLS LISTENER
	// ------------------------------------------------------------------
	ln, err := tls.Listen("tcp", n.listenAddr, n.tlsConfig)
	if err != nil {
		return fmt.Errorf(
			"failed to start TLS listener on %s: %w",
			n.listenAddr,
			err,
		)
	}

	n.ln = ln

	log.Printf(
		"[p2p] 🔒 Secure TLS node listening on %s (peerID=%s)",
		n.listenAddr,
		n.id,
	)

	if len(n.tlsConfig.Certificates) > 0 &&
		n.tlsConfig.Certificates[0].Leaf != nil {

		log.Printf(
			"[p2p] TLS transport certificate subject: CN=%s",
			n.tlsConfig.Certificates[0].Leaf.Subject.CommonName,
		)
	}

	// ------------------------------------------------------------------
	// ACCEPT INCOMING CONNECTIONS
	// ------------------------------------------------------------------
	n.wg.Add(1)
	go n.acceptLoop()

	// ------------------------------------------------------------------
	// WATCHDOG
	// ------------------------------------------------------------------
	n.wg.Add(1)
	go n.watchdogLoop()

	// ------------------------------------------------------------------
	// BOOTSTRAP
	// ------------------------------------------------------------------
	n.Bootstrap()

	// ------------------------------------------------------------------
	// AUTOMATIC PEER RECONNECTION
	// ------------------------------------------------------------------
	n.wg.Add(1)
	go n.PeerReconnectLoop()

	return nil
}

// Stop gracefully stops the node.
func (n *Node) Stop() {
	if n == nil {
		return
	}

	// ------------------------------------------------------------------
	// CANCEL NODE CONTEXT
	// ------------------------------------------------------------------
	if n.cancel != nil {
		n.cancel()
	}

	// ------------------------------------------------------------------
	// CLOSE LISTENER
	// ------------------------------------------------------------------
	if n.ln != nil {
		_ = n.ln.Close()
		n.ln = nil
	}

	// ------------------------------------------------------------------
	// CLOSE ACTIVE PEER SESSIONS
	// ------------------------------------------------------------------
	for i := range n.peerShards {
		sh := &n.peerShards[i]

		sh.mu.RLock()

		peers := make([]*Peer, 0, len(sh.peers))

		for _, p := range sh.peers {
			if p != nil {
				peers = append(peers, p)
			}
		}

		sh.mu.RUnlock()

		for _, p := range peers {
			p.Close()
		}
	}

	// ------------------------------------------------------------------
	// WAIT FOR NODE WORKERS
	// ------------------------------------------------------------------
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

// addPeer registers the authenticated peer session.
//
// A Peer represents one connection session. If the same peer identity
// reconnects, the new authenticated session replaces the old session.
// The old session is closed only after all node locks are released.
//
// Disconnect handlers must remove only the exact session pointer they
// belong to. This prevents an old connection from accidentally removing
// a newer connection for the same peer identity.
func (n *Node) addPeer(p *Peer) {
	if n == nil || p == nil {
		return
	}

	p.mu.RLock()
	peerID := p.id
	peerAddr := p.addr
	p.mu.RUnlock()

	if peerID == "" {
		log.Printf("[p2p] ❌ cannot add peer with empty identity")
		p.Close()
		return
	}

	sh := n.shard(peerID)

	// ------------------------------------------------------------
	// 1. Check the peer limit.
	// ------------------------------------------------------------

	currentCount := n.PeerCount()

	// ------------------------------------------------------------
	// 2. Replace the session inside the shard.
	// ------------------------------------------------------------

	sh.mu.Lock()

	oldPeer, exists := sh.peers[peerID]

	if !exists && currentCount >= n.config.MaxPeers {
		sh.mu.Unlock()

		log.Printf(
			"[p2p] ⚠️ Peer limit exceeded (%d/%d) — rejecting peer %s (%s)",
			currentCount,
			n.config.MaxPeers,
			peerID,
			peerAddr,
		)

		p.Close()
		return
	}

	// The newly authenticated session becomes authoritative.
	sh.peers[peerID] = p

	sh.mu.Unlock()

	// ------------------------------------------------------------
	// 3. Update the global active-session list.
	// ------------------------------------------------------------

	n.PeersMutex.Lock()

	replaced := false

	for i := 0; i < len(n.Peers); i++ {
		existing := n.Peers[i]

		if existing == nil {
			continue
		}

		existing.mu.RLock()
		existingID := existing.id
		existing.mu.RUnlock()

		if existingID == peerID {
			n.Peers[i] = p
			replaced = true
			break
		}
	}

	if !replaced {
		n.Peers = append(n.Peers, p)
	}

	n.PeersMutex.Unlock()

	// ------------------------------------------------------------
	// 4. Close the previous session AFTER releasing all locks.
	// ------------------------------------------------------------

	if exists && oldPeer != nil && oldPeer != p {
		log.Printf(
			"[p2p] ♻️ Replacing old peer session: id=%s old=%s new=%s",
			peerID,
			oldPeer.addr,
			peerAddr,
		)

		// Close() is intentionally non-blocking.
		//
		// The old session's disconnect handler will only remove the
		// exact old Peer pointer. It cannot remove the new session.
		oldPeer.Close()
	}

	// ------------------------------------------------------------
	// 5. Update activity/reputation bookkeeping.
	// ------------------------------------------------------------

	now := time.Now()

	n.peerLastSeen.Store(peerID, now)

	if _, exists := n.peerReputation.Load(peerID); !exists {
		n.peerReputation.Store(peerID, 0)
	}

	// ------------------------------------------------------------
	// 6. Log the resulting active session.
	// ------------------------------------------------------------

	newTotal := n.PeerCount()

	if exists && oldPeer != nil && oldPeer != p {
		log.Printf(
			"[p2p] ♻️ Peer session replaced: id=%s addr=%s (total connected peers: %d)",
			peerID,
			peerAddr,
			newTotal,
		)
	} else if !exists {
		log.Printf(
			"[p2p] 🌱 New peer successfully added: id=%s addr=%s (total connected peers: %d)",
			peerID,
			peerAddr,
			newTotal,
		)
	} else {
		log.Printf(
			"[p2p] 🔄 Peer session refreshed: id=%s addr=%s (total connected peers: %d)",
			peerID,
			peerAddr,
			newTotal,
		)
	}
}

// Connect dials a remote peer using a network locator.
//
// The address is only a temporary network locator.
// It is NOT treated as the peer's permanent identity.
//
// Permanent peer identity is established only after the
// EXPLOSIVE handshake verifies the remote wallet identity.
func (n *Node) Connect(addr string) (*Peer, error) {
	if n == nil {
		return nil, errors.New("nil P2P node")
	}

	addr = strings.TrimSpace(addr)

	if addr == "" {
		return nil, errors.New("peer address is empty")
	}

	if n.ctx == nil {
		return nil, errors.New("P2P node context is not initialized")
	}

	select {
	case <-n.ctx.Done():
		return nil, errors.New("P2P node is stopped")
	default:
	}

	// ------------------------------------------------------------------
	// VALIDATE NETWORK LOCATOR
	// ------------------------------------------------------------------
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid peer network locator %q: %w",
			addr,
			err,
		)
	}

	if strings.TrimSpace(host) == "" {
		return nil, errors.New("peer locator host is empty")
	}

	if strings.TrimSpace(port) == "" {
		return nil, errors.New("peer locator port is empty")
	}

	// ------------------------------------------------------------------
	// CREATE A NEW SESSION
	// ------------------------------------------------------------------
	//
	// A locator identifies where we should try to connect.
	// It does not identify the peer itself.
	//
	// Every connection attempt gets a fresh Peer session.
	p := NewPeer("", addr, n)

	if p == nil {
		return nil, errors.New("failed to create peer session")
	}

	// ------------------------------------------------------------------
	// CONNECT
	// ------------------------------------------------------------------
	if err := p.Connect(); err != nil {
		p.Close()

		return nil, fmt.Errorf(
			"failed to connect to peer locator %s: %w",
			addr,
			err,
		)
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
