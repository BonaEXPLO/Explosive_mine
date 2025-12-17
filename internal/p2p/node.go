// internal/p2p/node.go
package p2p

import (
        "context"
        "crypto/sha256"
        "encoding/hex"
        "errors"
        "fmt"
        "log"
        "math/rand"
        "net"
        "strings"
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
}

// NewNode constructs a Node with reasonable defaults.
// Updated defaults to enforce V3 security from genesis: strict block and message signing.
func NewNode(listenAddr, networkID, userAgent string) *Node {
    // Seed non-cryptographic RNG
    rand.Seed(time.Now().UnixNano())

    // Generate secure local Node ID
    r := make([]byte, 8)
    _, _ = cryptorand.Read(r)
    id := PeerID(hex.EncodeToString(r))

    // Force IPv4 bind for broad compatibility
    if strings.HasPrefix(listenAddr, ":") {
        listenAddr = "0.0.0.0" + listenAddr
        log.Printf("p2p: forcing IPv4 bind for listening: %s", listenAddr)
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

        // V3-aligned security defaults (non-negotiable on mainnet)
        RequireSignedMessages:    true,
        RequireStrictBlockSig:    true,  // Enforce valid Ed25519 miner signature on all new blocks
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
    }

    n.registerDefaultHandlers()
    return n
}

// sha256Sum computes the SHA-256 hash of a string and returns the raw bytes
func sha256Sum(s string) []byte {
    h := sha256.New()
    h.Write([]byte(s))
    return h.Sum(nil)
}

func (n *Node) Start() error {
    if n.listenAddr == "" {
        return errors.New("listen address not set")
    }

    ln, err := net.Listen("tcp", n.listenAddr)
    if err != nil {
        return fmt.Errorf("listen error: %w", err)
    }
    n.ln = ln
    log.Printf("p2p: node listening on %s (id=%s)", n.listenAddr, n.id)

    // --- accept connections ---
    n.wg.Add(1)
    go n.acceptLoop()

    // --- process inbound messages ---
    n.wg.Add(1)
    go n.messageDispatcher()

    // --- watchdog for peer eviction + block fetch ---
    n.wg.Add(1)
    go n.watchdogLoop()

    // --- metrics update loop (in-memory, thread-safe) ---
    n.StartMetricsLoop(2 * time.Second)

    // --- metrics broadcast loop (P2P) ---
    n.StartMetricsBroadcastLoop(2 * time.Second)

    // --- bootstrap initial peers ---
    n.Bootstrap()

    // --- auto reconnect loop ---
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
        _ = p.SendEnvelope(&Envelope{
            Version:   n.protocolVersion,
            Type:      MsgTypeAck,
            Payload:   nil,
            Timestamp: time.Now().UnixMilli(),
        })
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
func (n *Node) Connect(addr string) (*Peer, error) {
    pid := PeerID(fmt.Sprintf("%x", sha256Sum(addr))) // stable
    p := NewPeer(pid, addr, n)
    if err := p.Connect(); err != nil {
        return nil, err
    }
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
            if p != nil && p.IsConnected() {
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
func (n *Node) handleIncomingEnvelope(p *Peer, e *Envelope) {
    if e == nil {
        return
    }

    // --- Security: Enforce signed envelopes (V3-compatible) ---
    if n.config.RequireSignedMessages {
        ok, err := VerifyEnvelopeSignature(e)
        if err != nil || !ok {
            // Invalid or missing signature → penalize peer
            if p != nil {
                p.Penalize(1, 0)
                if p.errCount >= n.config.PeerInvalidMsgThreshold {
                    p.Penalize(0, 5*time.Minute)
                    log.Printf("p2p: temporary ban of peer %s for repeated invalid signatures", p.addr)
                }
            }
            n.metricsMu.Lock()
            n.numInvalidMessages++
            n.metricsMu.Unlock()
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

// handlePeerDisconnect removes a peer from the shard where it was registered,
// logs the event and triggers asynchronous cleanup of the peer resources.
func (n *Node) handlePeerDisconnect(p *Peer) {
    if p == nil {
        return
    }

    sh := n.shard(p.id)
    sh.mu.Lock()
    if existing, ok := sh.peers[p.id]; ok && existing == p {
        delete(sh.peers, p.id)
    }
    sh.mu.Unlock()

    n.PeersMutex.Lock()
    filtered := n.Peers[:0]
    for _, peer := range n.Peers {
        if peer != p {
            filtered = append(filtered, peer)
        }
    }
    n.Peers = filtered
    n.PeersMutex.Unlock()

    log.Printf("[p2p] peer disconnected: id=%s addr=%s", p.id, p.addr)
    go p.Close()
}


// watchdogLoop periodically evicts inactive peers, enforces capacity, and fetches new blocks.
// Updated to use strict block signature verification aligned with ledger.Block.VerifySignature().
// Only accepts blocks with valid Ed25519 miner signature (or legacy if explicitly allowed).
func (n *Node) watchdogLoop() {
    defer n.wg.Done()
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-n.ctx.Done():
            return
        case <-ticker.C:
            now := time.Now()
            evictBefore := now.Add(-n.config.PeerEvictionTimeout)

            // --- 1️⃣ Evict inactive peers ---
            for i := range n.peerShards {
                sh := &n.peerShards[i]
                sh.mu.Lock()
                for id, p := range sh.peers {
                    p.mu.RLock()
                    lastSeen := p.lastSeen
                    p.mu.RUnlock()
                    if lastSeen.IsZero() || lastSeen.Before(evictBefore) {
                        delete(sh.peers, id)
                        log.Printf("p2p: evicted inactive peer id=%s addr=%s", id, p.addr)
                        go p.Close()

                        // Remove from global Peers slice
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
                if victim != nil {
                    log.Printf("p2p: capacity eviction of peer id=%s addr=%s", victim.id, victim.addr)
                    n.handlePeerDisconnect(victim)
                } else {
                    break
                }
            }

            // --- 3️⃣ Periodic block synchronization ---
            // Fetch missing blocks from random connected peers
            newBlocks, err := n.FetchBlocks()
            if err != nil {
                log.Printf("p2p: block fetch failed: %v", err)
                continue
            }

            for _, blk := range newBlocks {
                // Strict V3-compatible signature verification (backward compatible with legacy blocks)
                valid, err := blk.VerifySignature()
                if err != nil {
                    log.Printf("p2p: block %d signature verification error: %v", blk.Header.Height, err)
                    continue
                }
                if !valid && n.config.RequireStrictBlockSig {
                    log.Printf("p2p: rejecting unsigned/invalid block %d (strict mode)", blk.Header.Height)
                    continue
                }

                if err := n.Ledger.AddBlock(blk); err != nil {
                    log.Printf("p2p: failed to apply fetched block %d: %v", blk.Header.Height, err)
                } else {
                    log.Printf("p2p: successfully applied fetched block %d", blk.Header.Height)
                }
            }
        }
    }
}
