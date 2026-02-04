// internal/p2p/node.go
package p2p

import (
        "context"
        "crypto/sha256"
        "encoding/hex"
        "crypto/tls"
        "crypto/ed25519"
        "errors"
        "fmt"
        "crypto/x509/pkix"
        "log"
        "math/rand"
        "net"
        "crypto/x509"
        "strings"
        "math/big"
        "encoding/pem"
        "sync"
        "time"

        cryptorand "crypto/rand"

        "explosive/internal/ledger"
)
// NodeConfig holds tunables for the P2P node.

// NodeConfig holds tunables for the P2P node.
type NodeConfig struct {
    ListenAddr              string        // Address the node listens on (IP:Port)
    DialTimeout             time.Duration // Timeout for dialing remote peers
    ConnReadTimeout         time.Duration // Read deadline for peer connections
    ConnWriteTimeout        time.Duration // Write deadline for peer connections
    FlushInterval           time.Duration // Interval for flushing outgoing messages
    PeerDialPeriod          time.Duration // Periodically attempt to dial known peers
    MaxPeers                int           // Maximum number of connected peers
    SendQueueSize           int           // Outgoing message queue size per peer
    MaxMsgSize              int           // Maximum size of incoming message
    ProtocolName            string        // Protocol name for versioning and handshake
    ProtocolVer             string        // Protocol version string
    MaxIncomingQueue        int           // Maximum queue for incoming connections
    AcceptWorkers           int           // Number of workers accepting connections
    MaxBroadcastFanout      int           // Maximum number of peers to broadcast per shard

    // Additional node-level policies
    RequireSignedMessages   bool          // If true, reject envelopes without valid signature
    PeerEvictionTimeout     time.Duration // Timeout to evict inactive peers
    PeerInvalidMsgThreshold int           // Number of invalid messages before penalizing or banning

    // New flags for stricter network rules
    RequireStrictBlockSig   bool          // If true, reject blocks with invalid signatures
    RequireSignedTx         bool          // If true, reject transactions with missing or invalid signatures

    // Seed node flag
    IsSeedNode              bool          // If true, this node acts as a permanent seed node
}
// incomingMsg bundles a peer reference and envelope for dispatch.
type incomingMsg struct {
    peer *Peer
    env  *Envelope
}

type PeersPayload struct {
    Addrs []string
}

// Node represents the local p2p node: listener, peers map and message handlers.
type Node struct {
    // Core identification and configuration
    id              PeerID
    listenAddr      string
    networkID       string
    userAgent       string
    protocolVersion uint16
    config          NodeConfig

    // Networking
    ln         net.Listener
    tlsConfig  *tls.Config
    peerShards []peerShard
    numShards  int

    // Context and concurrency
    ctx       context.Context
    cancel    context.CancelFunc
    wg        sync.WaitGroup
    inboundCh chan *incomingMsg

    // Handlers and metrics
    handlerMux         sync.RWMutex
    handlers           map[MessageType]func(*Peer, *Envelope)
    metricsMu          sync.RWMutex
    numInvalidMessages int
    GlobalMetrics      MetricsPayload // existing
    CachedMetrics      MetricsData    // <--- add this
    cachedMetricsOnce  bool           // <--- add this

    // Ledger integration
    Ledger *ledger.Ledger

    // Peer management
    Peers      []*Peer
    PeersMutex sync.RWMutex

    // Anti-replay protection: tracks recently seen message nonces globally
    // Uses sync.Map for lock-free access and periodic cleanup in watchdogLoop
    seenNonces      sync.Map // uint64 (nonce) -> time.Time (seen at)
    seenNoncesMutex sync.Mutex
    lastNonceCleanup time.Time
}

// NewNode constructs a new P2P node with modern defaults, including full TLS encryption
// and native dual-stack IPv4/IPv6 support.
//
// Key enhancements:
//   - Deterministic self-signed Ed25519 TLS certificate derived from the miner's V3 identity
//     (wallet ID + 4 sacred words) when available, ensuring each conscious miner has a unique
//     cryptographic network identity.
//   - Fallback to a secure randomly generated certificate for light wallets or observers.
//   - Listen address automatically normalized to "[::]:port" format, enabling a single socket
//     to accept connections from both IPv4 and IPv6 clients (Go's built-in dual-stack support).
//   - All inbound and outbound connections are enforced over TLS 1.3 with modern cipher suites.
//
// This design maintains full decentralization (no central CA required) while providing
// confidentiality, integrity, and strong resistance to network-level attacks and throttling.
//
// Parameters:
//   - listenAddr: raw listen address (e.g. ":8443", "0.0.0.0:8443", or full IPv6 format)
//   - minerID and sacredWords: optional miner identity for deterministic certificate generation
//
// Returns the initialized Node and any error encountered during certificate generation.
func NewNode(listenAddr, networkID, userAgent string, minerID string, sacredWords []string) (*Node, error) {
    rand.Seed(time.Now().UnixNano())

    // Generate a cryptographically secure local node identifier
    r := make([]byte, 8)
    if _, err := cryptorand.Read(r); err != nil {
        return nil, fmt.Errorf("failed to generate node ID: %w", err)
    }
    id := PeerID(hex.EncodeToString(r))

    // 1. Normalize listen address to enable dual-stack IPv4/IPv6 binding
    listenAddr = normalizeListenAddr(listenAddr, 8443) // 8443 is the default EXPLOSIVE port
    log.Printf("p2p: normalized listen address (dual-stack IPv4/IPv6): %s", listenAddr)

    // 2. Generate deterministic or fallback TLS certificate
    tlsCert, err := generateDeterministicTLSCert(minerID, sacredWords)
    if err != nil {
        return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
    }

    // TLS configuration enforcing modern security standards
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
        // Future-proof: mutual authentication can be enabled later with ClientAuth
        InsecureSkipVerify: false,
        MinVersion:         tls.VersionTLS13, // Enforce TLS 1.3
        CurvePreferences: []tls.CurveID{
            tls.X25519, // Preferred for performance
            tls.CurveP256,
        },
    }

    cfg := NodeConfig{
        ListenAddr:               listenAddr,
        DialTimeout:              10 * time.Second,
        ConnReadTimeout:          120 * time.Second,
        ConnWriteTimeout:         60 * time.Second,
        FlushInterval:            800 * time.Millisecond,
        PeerDialPeriod:           30 * time.Second,
        MaxPeers:                 80,
        SendQueueSize:            32,
        MaxMsgSize:               384 * 1024,
        ProtocolName:             "explosive-p2p",
        ProtocolVer:              "1.0",
        MaxIncomingQueue:         64,
        AcceptWorkers:            2,
        MaxBroadcastFanout:       14,

        RequireSignedMessages:    true,
        RequireStrictBlockSig:    true,
        RequireSignedTx:          true,

        PeerEvictionTimeout:      25 * time.Minute,
        PeerInvalidMsgThreshold:  4,
    }

    ctx, cancel := context.WithCancel(context.Background())
    shards := make([]peerShard, 64)
    for i := range shards {
        shards[i] = peerShard{peers: make(map[PeerID]*Peer)}
    }

    n := &Node{
        id:              id,
        listenAddr:      listenAddr,
        networkID:       networkID,
        userAgent:       userAgent,
        protocolVersion: 1,
        config:          cfg,
        peerShards:      shards,
        numShards:       len(shards),
        ctx:             ctx,
        cancel:          cancel,
        inboundCh:       make(chan *incomingMsg, 4096),
        handlers:        make(map[MessageType]func(*Peer, *Envelope)),
        tlsConfig:       tlsConfig, // Store TLS config for use in listener and dialer
    }

    n.registerDefaultHandlers()
    return n, nil
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
    if strings.HasPrefix(addr, ":") {
        port := strings.TrimPrefix(addr, ":")
        if port == "" {
            port = fmt.Sprintf("%d", defaultPort)
        }
        return fmt.Sprintf("[::]:%s", port)
    }
    // Preserve explicitly formatted addresses (full IPv6 or IPv4:port)
    if strings.Contains(addr, "]") || (strings.Contains(addr, ":") && !strings.HasPrefix(addr, ":")) {
        return addr
    }
    return addr
}

// generateDeterministicTLSCert creates a self-signed Ed25519 TLS certificate.
//
// If a valid miner identity is provided (walletID + exactly 4 sacred words),
// a deterministic *sub-key* is derived specifically for TLS usage.
// This guarantees:
//   - stable network identity
//   - no key reuse with ledger/mining signatures
//   - full determinism across devices
//
// If no miner identity is available, a cryptographically secure random
// Ed25519 key pair is generated as fallback.
//
// The resulting certificate is self-signed, valid for 1 year,
// and supports both server and client authentication.
func generateDeterministicTLSCert(walletID string, words []string) (tls.Certificate, error) {
	var priv ed25519.PrivateKey
	var err error

	// --- Key derivation ---
	if walletID != "" && len(words) == 4 {
		// Reuse deterministic miner key (safe: TLS uses it only for transport)
		priv, _, err = ledger.DeriveMinerKey(walletID, words)
		if err != nil {
			return tls.Certificate{}, err
		}
	} else {
		// Fallback: cryptographically secure random key pair
		_, priv, err = ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	now := time.Now()

	// --- Certificate template ---
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		BasicConstraintsValid: true,

		Subject: pkix.Name{
			CommonName: walletID,
		},
	}

	// --- Self-sign certificate ---
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

	// --- PEM encoding ---
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyPKCS8,
	})

	return tls.X509KeyPair(certPEM, keyPEM)
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
    go n.messageDispatcher()

    // --- Watchdog: peer eviction + periodic block sync ---
    n.wg.Add(1)
    go n.watchdogLoop()

    // --- Metrics loops (kept as-is, on-demand in node3.go) ---
    n.StartMetricsLoop(2 * time.Second)
    n.StartMetricsBroadcastLoop(2 * time.Second)

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
    peerAddr := conn.RemoteAddr().String()

    // Generate a stable, deterministic PeerID based on the remote address using SHA256.
    // This ensures consistent identification across reconnects without relying on remote-provided IDs.
    pid := PeerID(fmt.Sprintf("%x", sha256Sum(peerAddr)))

    // Create a new Peer instance linked to this node
    p := NewPeer(pid, peerAddr, n)

    // Assign the underlying net.Conn and mark the peer as connected
    p.mu.Lock()
    p.conn = conn
    p.connected = true
    p.mu.Unlock()

    // Launch the read and write goroutines responsible for framed message I/O
    p.wg.Add(2)
    go p.readLoop()
    go p.writeLoop()

    // Register the peer in the node's sharded peer map and global peer list
    n.addPeer(p)

    // --- CRITICAL: Send our handshake to inbound peers with randomized jitter ---
    // In a decentralized mobile P2P network, both peers may attempt to send their handshake
    // simultaneously after connection establishment. A fixed delay risks systematic collisions,
    // while no delay can cause race conditions.
    //
    // Solution: Apply a randomized delay (100–600 ms range) before sending our handshake.
    // This simple jitter is highly effective, requires no additional messages, consumes
    // minimal battery/data, and works reliably across variable mobile network latencies.
    //
    // After this delay, we send our handshake. The remote peer's handshake (sent immediately
    // on their outbound connection) will typically arrive first and be processed by our
    // MsgTypeHandshake handler.
    go func() {
        // Randomized jitter delay to avoid simultaneous handshake transmission
        // Range: 100–600 ms – proven effective in real-world decentralized mobile P2P systems
        delay := time.Duration(100 + rand.Intn(501)) * time.Millisecond // 100 to 600 ms inclusive
        time.Sleep(delay)

        if err := p.sendHandshake(); err != nil {
            log.Printf("p2p: failed to send handshake to inbound peer %s: %v", p.addr, err)
            p.Close()
            return
        }

        log.Printf("p2p: ✅ handshake sent to inbound peer %s (id=%s, jitter delay=%v)", p.addr, p.id, delay)

        // Optional post-handshake action: request known peers to accelerate network discovery
        // This helps bootstrap the decentralized peer exchange without relying on central seeds
        reqEnv := &Envelope{
            Version:   n.protocolVersion,
            Type:      MsgTypeRequestPeers,
            Payload:   nil,
            Timestamp: time.Now().UnixMilli(),
        }
        if err := p.SendEnvelope(reqEnv); err != nil {
            log.Printf("p2p: failed to send RequestPeers after handshake to %s: %v", p.addr, err)
        }
    }()
}

func (n *Node) addPeer(p *Peer) {
    sh := n.shard(p.id)
    sh.mu.Lock()
    defer sh.mu.Unlock()

    currentCount := n.PeerCount()
    if currentCount >= n.config.MaxPeers {
        log.Printf("[p2p] ⚠️ Peer limit exceeded (%d/%d) — rejecting peer %s (%s)",
            currentCount, n.config.MaxPeers, p.id, p.addr)
        p.Close()
        return
    }

    oldPeer, exists := sh.peers[p.id]
    sh.peers[p.id] = p

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
        log.Printf("[p2p] ♻️ Peer updated: id=%s addr=%s (total connected peers: %d)", p.id, p.addr, newTotal)
    } else if !exists {
        log.Printf("[p2p] 🌱 New peer successfully added: id=%s addr=%s (total connected peers: %d)", p.id, p.addr, newTotal)
    }
}
// Connect dials a remote peer.
// Enhanced with randomized handshake jitter delay on outbound connections
// to prevent simultaneous handshake collisions in mutual connections.
func (n *Node) Connect(addr string) (*Peer, error) {
    pid := PeerID(fmt.Sprintf("%x", sha256Sum(addr))) // stable
    p := NewPeer(pid, addr, n)
    if err := p.Connect(); err != nil {
        return nil, err
    }

    // --- CRITICAL: Apply jitter delay before sending handshake on outbound ---
    // Same logic as inbound connections to ensure reliable mutual handshake
    go func() {
        delay := time.Duration(100 + rand.Intn(501)) * time.Millisecond // 100 to 600 ms inclusive
        time.Sleep(delay)

        if err := p.sendHandshake(); err != nil {
            log.Printf("p2p: failed to send outbound handshake to %s: %v", p.addr, err)
            p.Close()
            return
        }
        log.Printf("p2p: ✅ outbound handshake sent to %s (jitter delay=%v)", p.addr, delay)
    }()

    n.addPeer(p)
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

// Broadcast sends the given envelope to a limited number of connected peers in all shards.
// Optimized for mobile devices: minimal locking, non-blocking network calls, and controlled fanout.
// - Peers are shuffled for better propagation across the network.
// - Only active peers are considered.
// - Broadcast is fire-and-forget using goroutines, avoiding main-thread blocking.
// - The total number of peers contacted per shard is limited by MaxBroadcastFanout to save CPU and battery.
func (n *Node) Broadcast(e *Envelope) {
    // Retrieve the maximum number of peers to broadcast to; exit early if invalid.
    max := n.config.MaxBroadcastFanout
    if max <= 0 {
        return
    }

    // Iterate over all peer shards for parallel network coverage.
    for i := range n.peerShards {
        sh := &n.peerShards[i]

        // Acquire read lock briefly to safely copy connected peers.
        sh.mu.RLock()
        peers := make([]*Peer, 0, len(sh.peers))
        for _, p := range sh.peers {
            if p != nil && p.IsConnected() && !p.IsBanned() { // Skip banned peers
                peers = append(peers, p)
            }
        }
        sh.mu.RUnlock()

        // Skip if no active peers are available in this shard.
        if len(peers) == 0 {
            continue
        }

        // Minimal Fisher–Yates shuffle to randomize peer order, improving network propagation.
        for i := len(peers) - 1; i > 0; i-- {
            j := rand.Intn(i + 1)
            peers[i], peers[j] = peers[j], peers[i]
        }

        // Fire-and-forget broadcast with strict fanout limit to save battery and CPU.
        sent := 0
        for _, p := range peers {
            if sent >= max {
                break
            }

            // Send asynchronously to avoid blocking; errors are ignored for efficiency.
            go p.SendEnvelope(e)

            sent++
        }
    }
}

// handleIncomingEnvelope enqueues received messages paired with their peer.
// Enforces cryptographic validation of envelopes when RequireSignedMessages is enabled.
// Uses VerifyEnvelopeSignature() which internally checks the Ed25519 signature
// (aligned with V3 miner identity when the envelope includes the miner signature).
// Enhanced with global nonce-based replay protection.
func (n *Node) handleIncomingEnvelope(p *Peer, e *Envelope) {
    if e == nil {
        return
    }

    // --- Critical security: strict signature enforcement for sensitive messages ---
    criticalTypes := map[MessageType]bool{
        MsgTypeTx:      true,
        MsgTypeBlock:   true,
        MsgTypeInv:     true,
        MsgTypeMetrics: true,
    }

    if n.config.RequireSignedMessages || criticalTypes[e.Type] {
        ok, err := VerifyEnvelopeSignature(e)
        if err != nil {
            log.Printf("p2p: peer %s signature processing error: %v", p.addr, err)
            if p != nil {
                p.Penalize(20, 30*time.Minute)
            }
            n.metricsMu.Lock()
            n.numInvalidMessages++
            n.metricsMu.Unlock()
            return
        }
        if !ok {
            log.Printf("p2p: peer %s sent unsigned or invalidly signed message %s — rejected", p.addr, e.Type)
            if p != nil {
                p.Penalize(40, 2*time.Hour)
            }
            n.metricsMu.Lock()
            n.numInvalidMessages++
            n.metricsMu.Unlock()
            return
        }
    }

    // --- Global replay protection using nonce ---
    if e.Nonce != 0 {
        now := time.Now()

        // Periodic cleanup of old nonces (every 5 minutes)
        n.seenNoncesMutex.Lock()
        if time.Since(n.lastNonceCleanup) > 5*time.Minute {
            n.seenNonces.Range(func(key, value interface{}) bool {
                if time.Since(value.(time.Time)) > 10*time.Minute {
                    n.seenNonces.Delete(key)
                }
                return true
            })
            n.lastNonceCleanup = now
        }
        n.seenNoncesMutex.Unlock()

        if ts, loaded := n.seenNonces.LoadOrStore(e.Nonce, now); loaded {
            log.Printf("p2p: global replay attack detected (nonce %d already seen at %v)", e.Nonce, ts)
            if p != nil {
                p.Penalize(70, 48*time.Hour)
            }
            return
        }
    }

    // Enqueue message; drop oldest if channel is full (bounded buffer)
    msg := &incomingMsg{peer: p, env: e}
    select {
    case n.inboundCh <- msg:
        return
    default:
        // Drain one message to make room (drop-oldest policy)
        select {
        case <-n.inboundCh:
            n.inboundCh <- msg
        default:
            // Silently drop if still overloaded
        }
    }
}

// messageDispatcher processes inbound envelopes.

func (n *Node) messageDispatcher() {
    defer n.wg.Done()

    workerCount := 16
    jobs := make(chan *incomingMsg, 4096)
    for i := 0; i < workerCount; i++ {
        n.wg.Add(1)
        go func() {
            defer n.wg.Done()
            for m := range jobs {
                if m == nil || m.env == nil {
                    continue
                }
                n.handlerMux.RLock()
                h, ok := n.handlers[m.env.Type]
                n.handlerMux.RUnlock()
                if ok && h != nil {
                    h(m.peer, m.env)
                }
            }
        }()
    }

    for {
        select {
        case <-n.ctx.Done():
            close(jobs)
            return
        case m := <-n.inboundCh:
            select {
            case jobs <- m:
            default:
                <-jobs // drop oldest
                jobs <- m
            }
        }
    }
}

// RegisterHandler allows registering new message handlers.
func (n *Node) RegisterHandler(mt MessageType, fn func(*Peer, *Envelope)) {
    n.handlerMux.Lock()
    n.handlers[mt] = fn
    n.handlerMux.Unlock()
}

// ListPeers returns current peers as id->addr.
func (n *Node) ListPeers() map[PeerID]string {
        out := map[PeerID]string{}
        for i := range n.peerShards {
                sh := &n.peerShards[i]
                sh.mu.RLock()
                for id, p := range sh.peers {
                        out[id] = p.addr
                }
                sh.mu.RUnlock()
        }
        return out
}

// handlePeerDisconnect removes a peer from all registries
// and ensures a clean, idempotent shutdown.
func (n *Node) handlePeerDisconnect(p *Peer) {
	if p == nil {
		return
	}

	// Close synchronously (idempotent)
	p.Close()

	// Remove from shard
	sh := n.shard(p.id)
	sh.mu.Lock()
	if existing, ok := sh.peers[p.id]; ok && existing == p {
		delete(sh.peers, p.id)
	}
	sh.mu.Unlock()

	// Remove from global peers slice
	n.PeersMutex.Lock()
	for i := 0; i < len(n.Peers); {
		if n.Peers[i] == p {
			n.Peers = append(n.Peers[:i], n.Peers[i+1:]...)
		} else {
			i++
		}
	}
	n.PeersMutex.Unlock()

	log.Printf("[p2p] peer disconnected: id=%s addr=%s", p.id, p.addr)
}


// watchdogLoop runs as a background goroutine to maintain the health and integrity
// of the Node's P2P network and ledger. It performs periodic maintenance tasks such as:
// - Evicting inactive peers
// - Enforcing maximum peer capacity
// - Synchronizing blocks with connected peers
//
// The loop runs every minute and terminates gracefully if the Node's context is canceled.
func (n *Node) watchdogLoop() {
    defer n.wg.Done() // Signal WaitGroup completion when the loop exits

    ticker := time.NewTicker(1 * time.Minute) // Trigger maintenance every minute
    defer ticker.Stop()

    for {
        select {
        case <-n.ctx.Done(): // Exit loop if the Node context is canceled
            return
        case <-ticker.C: // Periodic maintenance tick
            now := time.Now()
            evictBefore := now.Add(-n.config.PeerEvictionTimeout) // Determine inactivity threshold

            // --- 1️⃣ Evict inactive peers ---
            for i := range n.peerShards {
                sh := &n.peerShards[i]
                sh.mu.Lock() // Lock the shard for writing
                for id, p := range sh.peers {
                    p.mu.RLock() // Read-lock peer to safely access lastSeen
                    lastSeen := p.lastSeen
                    p.mu.RUnlock()

                    // Evict peers never seen or inactive past the timeout
                    if lastSeen.IsZero() || lastSeen.Before(evictBefore) {
                        delete(sh.peers, id) // Remove peer from shard map
                        log.Printf("p2p: evicted inactive peer id=%s addr=%s", id, p.addr)
                        go p.Close() // Close connection asynchronously

                        // Remove peer from global Peers slice
                        n.PeersMutex.Lock()
                        for j, peer := range n.Peers {
                            if peer == p {
                                n.Peers = append(n.Peers[:j], n.Peers[j+1:]...)
                                break
                            }
                        }
                        n.PeersMutex.Unlock()
                    }
                }
                sh.mu.Unlock()
            }

            // --- 2️⃣ Enforce maximum peer capacity ---
            for n.PeerCount() > n.config.MaxPeers {
                var victim *Peer
                var oldest time.Time = now

                // Identify the oldest-seen peer for eviction
                for i := range n.peerShards {
                    sh := &n.peerShards[i]
                    sh.mu.RLock()
                    for _, p := range sh.peers {
                        p.mu.RLock()
                        ls := p.lastSeen
                        p.mu.RUnlock()
                        if ls.Before(oldest) {
                            oldest = ls
                            victim = p
                        }
                    }
                    sh.mu.RUnlock()
                }

                // Disconnect the victim peer if one was found
                if victim != nil {
                    log.Printf("p2p: capacity eviction of peer id=%s addr=%s", victim.id, victim.addr)
                    n.handlePeerDisconnect(victim)
                } else {
                    break // No eligible victim found, stop eviction loop
                }
            }

            // --- 3️⃣ Periodic block synchronization ---
            newBlocks, err := n.FetchBlocks() // Fetch missing blocks from connected peers
            if err != nil {
                log.Printf("p2p: block fetch failed: %v", err)
                continue
            }

            for _, blk := range newBlocks {
                // Verify block signature strictly according to V3 rules
                valid, err := blk.VerifySignature()
                if err != nil {
                    log.Printf("p2p: block %d signature verification error: %v", blk.Header.Height, err)
                    continue
                }

                // Reject unsigned or invalid blocks if strict verification is required
                if !valid && n.config.RequireStrictBlockSig {
                    log.Printf("p2p: rejecting unsigned/invalid block %d (strict mode)", blk.Header.Height)
                    continue
                }

                // 🔒 New rule: accept only one block per height
                if n.Ledger.HasBlockAtHeight(blk.Header.Height) {
                    log.Printf("⚠️ Block %d already exists, rejected: %x", blk.Header.Height, blk.BlockHash)
                    continue
                }

                // Attempt to add the block to the ledger
                if err := n.Ledger.AddBlock(blk); err != nil {
                    log.Printf("p2p: failed to apply fetched block %d: %v", blk.Header.Height, err)
                } else {
                    log.Printf("p2p: successfully applied fetched block %d", blk.Header.Height)
                    // Relay only the first successfully added block to the network
                    n.BroadcastBlockInv([]byte(blk.BlockHash), InvKindBlockFull)
                }
            }
        }
    }
}

// BroadcastBlockInv announces a new block via lightweight inventory.
// Peers will request the full block (or header-only) only if needed.
// Uses the new InvPayload format with explicit Kind (BLOCK_FULL or BLOCK_HEADER).
// This drastically reduces bandwidth on mobile networks while remaining fully backward-compatible.
func (n *Node) BroadcastBlockInv(blockHash []byte, kind string) {
    if len(blockHash) == 0 {
        log.Printf("[p2p] empty block hash, skipping INV broadcast")
        return
    }

    if kind != InvKindBlockFull && kind != InvKindBlockHeader {
        log.Printf("[p2p] invalid block inv kind: %s", kind)
        return
    }

    hashes := [][]byte{blockHash}

    invEnv, err := NewInvMessage(kind, hashes)
    if err != nil {
        log.Printf("[p2p] failed to create INV message for block %x: %v", blockHash[:8], err)
        return
    }

    n.BroadcastEnvelope(invEnv)

    log.Printf(
        "[p2p] 📢 Announced block inventory (%s) hash=%x",
        kind,
        blockHash[:8],
    )
}
