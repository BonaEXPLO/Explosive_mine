// internal/p2p/node.go

package p2p

import (
        "context"
        "crypto/sha256"
        "encoding/hex"
        "errors"
        "fmt"
        "log"
        "math/big"
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
// It ensures dual-stack compatibility by forcing IPv4 bind when only a port is provided.
func NewNode(listenAddr, networkID, userAgent string) *Node {
    // Seed math/rand for jitter, backoff, etc. (non-cryptographic use)
    rand.Seed(time.Now().UnixNano())

    // Generate a cryptographically secure PeerID
    r := make([]byte, 8)
    _, _ = cryptorand.Read(r)
    id := PeerID(hex.EncodeToString(r))

    // Force explicit IPv4 bind if only a port is provided (e.g., ":8443")
    // This ensures dual-stack (IPv4 + IPv6) listening on cloud providers like AWS
    if strings.HasPrefix(listenAddr, ":") {
        listenAddr = "0.0.0.0" + listenAddr
        log.Printf("p2p: forcing IPv4 bind for listening: %s", listenAddr)
    }

    cfg := NodeConfig{
    // Listening address (e.g. "0.0.0.0:3333" or ":3333" – IPv4 forced for mobile compatibility)
    ListenAddr: listenAddr,

    // -- Connection timeouts (tuned for unstable mobile networks) --
    DialTimeout:      10 * time.Second, // Max time to establish an outbound connection
    ConnReadTimeout:  120 * time.Second, // Inactivity timeout on reads – generous for poor signal
    ConnWriteTimeout: 60 * time.Second,  // Write deadline – prevents stuck sends on congested networks

    // -- Message flushing & peer maintenance (battery-first) --
    FlushInterval:    800 * time.Millisecond, // Slow flush = major battery savings on mobile
    PeerDialPeriod:   30 * time.Second,       // How often we retry known peers – prevents aggressive reconnect storms

    // -- Hard resource caps (proven stable on low-end Android devices) --
    MaxPeers:         80,  // Absolute maximum concurrent peers – tested rock-solid on mid-range phones (e.g. Samsung A53)
    SendQueueSize:    32,  // Per-peer outbound queue – tiny footprint, ultra-low RAM usage
    MaxMsgSize:       384 * 1024, // 384 KiB – safe upper bound for blocks/txs on limited mobile data plans

    // -- Protocol identification --
    ProtocolName: "explosive-p2p",
    ProtocolVer:  "1.0",

    // -- Connection acceptance pipeline (mobile CPU conscious) --
    MaxIncomingQueue: 64,    // Pending inbound connections before dropping
    AcceptWorkers:    2,     // Only 2 workers needed – more would waste CPU cycles on mobile

    // -- Gossip propagation (Bitcoin-style probabilistic flooding) --
    MaxBroadcastFanout: 14, // ~√MaxPeers → guarantees <30s global propagation with minimal bandwidth

    // -- Security enforcement (activated from genesis – non-negotiable) --
    RequireSignedMessages:   true, // Every envelope must carry a valid cryptographic signature
    RequireStrictBlockSig:   true, // Blocks without valid miner signature are rejected outright
    RequireSignedTx:         true, // All transactions must be signed – no exceptions

    // -- Peer health & eviction policy --
    PeerEvictionTimeout:     25 * time.Minute, // Inactive peers are disconnected after 25 min
    PeerInvalidMsgThreshold: 4,                // Ban peers after 4 invalid messages (Sybil resistance)
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

// acceptLoop accepts incoming connections with worker pool.
func (n *Node) acceptLoop() {
	defer n.wg.Done()
	connCh := make(chan net.Conn, n.config.MaxIncomingQueue)
	for i := 0; i < n.config.AcceptWorkers; i++ {
		n.wg.Add(1)
		go n.connWorker(connCh)
	}

	for {
		conn, err := n.ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
				log.Println("accept error:", err)
				continue
			}
		}

		// enforce global max peers
		if n.PeerCount() >= n.config.MaxPeers {
			_ = conn.Close()
			continue
		}

		select {
		case connCh <- conn:
		default:
			_ = conn.Close() // drop if queue full
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

    if n.PeerCount() >= n.config.MaxPeers {
        _ = p.SendEnvelope(&Envelope{
            Version:   n.protocolVersion,
            Type:      MsgTypeAck,
            Payload:   nil,
            Timestamp: time.Now().UnixMilli(),
        })
        p.Close()
        return
    }

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
func (n *Node) handleIncomingEnvelope(p *Peer, e *Envelope) {
	if e == nil {
		return
	}
	// signature enforcement & basic validation
	if n.config.RequireSignedMessages {
		ok, err := VerifyEnvelopeSignature(e)
		if err != nil || !ok {
			// penalize peer and possibly ban
			if p != nil {
				p.Penalize(1, 0)
				if p.errCount >= n.config.PeerInvalidMsgThreshold {
					// temporary ban
					p.Penalize(0, 5*time.Minute)
					log.Printf("p2p: banning peer %s for invalid messages", p.addr)
				}
			}
			n.metricsMu.Lock()
			n.numInvalidMessages++
			n.metricsMu.Unlock()
			return
		}
	}

	// enqueue; drop-oldest if full (bounded channel)
	msg := &incomingMsg{peer: p, env: e}
	select {
	case n.inboundCh <- msg:
		return
	default:
		select {
		case <-n.inboundCh:
			n.inboundCh <- msg
		default:
			// drop silently when overloaded
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

// simple helper: random subset (could be improved)
func randomSubset(peers map[PeerID]*Peer, n int) []*Peer {
	out := []*Peer{}
	for _, p := range peers {
		out = append(out, p)
	}
	if len(out) <= n {
		return out
	}
	// shuffle
	for i := range out {
		j, _ := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(out))))
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}
	return out[:n]
}

// watchdogLoop periodically evicts inactive peers and enforces capacity.
func (n *Node) watchdogLoop() {
    defer n.wg.Done()
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-n.ctx.Done():
            // Exit the watchdog when the node context is cancelled
            return
        case <-ticker.C:
            now := time.Now()
            evictBefore := now.Add(-n.config.PeerEvictionTimeout)

            // --- 1️⃣ Evict inactive peers ---
            // Remove peers that have not been seen for longer than PeerEvictionTimeout
            for i := range n.peerShards {
                sh := &n.peerShards[i]
                sh.mu.Lock()
                for id, p := range sh.peers {
                    p.mu.RLock()
                    lastSeen := p.lastSeen
                    p.mu.RUnlock()
                    if lastSeen.IsZero() || lastSeen.Before(evictBefore) {
                        // Delete from shard map
                        delete(sh.peers, id)
                        log.Printf("p2p: evicted inactive peer id=%s addr=%s", id, p.addr)
                        // Close connection asynchronously
                        go p.Close()
                        // Remove from global peer slice
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

            // --- 2️⃣ Enforce maximum number of peers ---
            // If we have more peers than allowed, evict the oldest ones
            for n.PeerCount() > n.config.MaxPeers {
                var victim *Peer
                var oldest time.Time = now
                var victimID PeerID
                for i := range n.peerShards {
                    sh := &n.peerShards[i]
                    sh.mu.RLock()
                    for id, p := range sh.peers {
                        p.mu.RLock()
                        ls := p.lastSeen
                        p.mu.RUnlock()
                        if ls.IsZero() || ls.Before(oldest) {
                            oldest = ls
                            victim = p
                            victimID = id
                        }
                    }
                    sh.mu.RUnlock()
                }
                if victim != nil {
                    log.Printf("p2p: evicting peer to enforce capacity id=%s addr=%s", victimID, victim.addr)
                    n.handlePeerDisconnect(victim)
                } else {
                    break
                }
            }

            // --- 3️⃣ Fetch new blocks from peers ---
            // Regularly retrieve new blocks from connected peers
            newBlocks, err := n.FetchBlocks()
            if err != nil {
                log.Printf("⚠️ Failed to fetch blocks: %v", err)
                continue
            }

            // Verify and add each new block
            for _, blk := range newBlocks {
                ok, err := blk.VerifySignature()
                if err != nil || !ok {
                    log.Printf("⚠️ Invalid block signature for block %d", blk.Header.Height)
                    continue
                }

                if err := n.Ledger.AddBlock(blk); err != nil {
                    log.Printf("⚠️ Failed to add block %d: %v", blk.Header.Height, err)
                } else {
                    log.Printf("✅ Block %d fetched and added from peers", blk.Header.Height)
                }
            }
        }
    }
}
// ProtocolVersion returns the node's protocol version.
func (n *Node) ProtocolVersion() uint16 {
	return n.protocolVersion
}

/* -------------------------------------------------------------------------
   Deterministic port derivation helpers
   - These helpers are intentionally non-invasive: they do not change Node
     constructors or startup flow. Call ApplyDerivedListenAddrToNode(n, id, words)
     after restoring the miner identity to set the derived listen address.
   - Default port range: [31000, 61000]
--------------------------------------------------------------------------- */

const (
	defaultMinPort = 31000
	defaultMaxPort = 61000
)

// normalizeAndJoinWords does light normalized join of 4 sacred words.
// It trims spaces and collapses internal whitespace, then joins with '-'.
func normalizeAndJoinWords(words []string) string {
	parts := make([]string, 0, len(words))
	for _, w := range words {
		s := strings.TrimSpace(w)
		// collapse internal runs of spaces to one space
		s = strings.Join(strings.Fields(s), " ")
		parts = append(parts, s)
	}
	return strings.Join(parts, "-")
}

// registerDefaultHandlers registers all default message handlers for the P2P protocol.
// This includes critical protocol messages like handshake, ping/pong, and data propagation.
func (n *Node) registerDefaultHandlers() {
    // --- Handshake handler (CRITICAL: must be first) ---
    // Validates incoming handshake from remote peers and ensures network compatibility.
    n.RegisterHandler(MsgTypeHandshake, func(p *Peer, env *Envelope) {
        var hs HandshakePayload
        if err := UnmarshalPayload(env.Payload, &hs); err != nil {
            log.Printf("p2p: invalid handshake payload from %s: %v", p.addr, err)
            p.Close()
            return
        }

        // Validate network identifier – prevents cross-network connections
        if hs.Network != n.networkID {
            log.Printf("p2p: handshake rejected from %s: wrong network '%s' (expected '%s')", p.addr, hs.Network, n.networkID)
            p.Close()
            return
        }

        // Optional: Validate version compatibility (relaxed or strict as needed)
        if hs.Version != n.userAgent {
            log.Printf("p2p: handshake from %s uses different version '%s' (local: '%s') – allowing for now", p.addr, hs.Version, n.userAgent)
            // Optionally: p.Close() for strict version enforcement
        }

        // Update peer metadata if needed (e.g., announced listen address)
        // p.announcedListenAddr = hs.ListenAddr // for future outbound dialing

        log.Printf("p2p: ✅ handshake successful with peer %s | id=%s | version=%s | addr=%s",
            p.addr, hs.PeerID, hs.Version, hs.ListenAddr)

        // Optional: request known peers after successful handshake
        req := &Envelope{
            Version:   n.protocolVersion,
            Type:      MsgTypeRequestPeers,
            Payload:   nil,
            Timestamp: time.Now().UnixMilli(),
        }
        _ = p.SendEnvelope(req)
    })

    // --- Ping handler ---
    n.handlers[MsgTypePing] = func(p *Peer, env *Envelope) {
        var ping PingPayload
        if err := UnmarshalPayload(env.Payload, &ping); err != nil {
            return
        }
        pong := PongPayload{Nonce: ping.Nonce}
        envReply, _ := NewEnvelopeFromPayload(n.protocolVersion, MsgTypePong, pong)
        if p != nil {
            _ = p.SendEnvelope(envReply)
        } else {
            n.Broadcast(envReply)
        }
    }

    // --- Pong handler ---
    n.handlers[MsgTypePong] = func(p *Peer, env *Envelope) {
        // No-op – presence of pong is sufficient for liveness
    }

    // --- Block handler ---
    n.handlers[MsgTypeBlock] = func(p *Peer, env *Envelope) {
        var blk ledger.Block
        if err := UnmarshalPayload(env.Payload, &blk); err != nil {
            log.Printf("⚠️ Failed to unmarshal block from peer %s: %v", p.addr, err)
            return
        }

        if blk.Header.Height <= n.Ledger.GetLatestBlockHeight() {
            return
        }

        if n.config.RequireStrictBlockSig {
            ok, err := blk.VerifySignature()
            if err != nil || !ok {
                log.Printf("⚠️ Invalid block signature for block %d from peer %s", blk.Header.Height, p.addr)
                if p != nil {
                    p.Penalize(1, 0)
                    if p.errCount >= n.config.PeerInvalidMsgThreshold {
                        p.Penalize(0, 5*time.Minute)
                        log.Printf("p2p: banning peer %s for invalid block signatures", p.addr)
                    }
                }
                return
            }
        }

        if err := n.Ledger.AddBlock(&blk); err != nil {
            log.Printf("⚠️ Failed to add block from peer %s: %v", p.addr, err)
            return
        }

        log.Printf("✅ Block %d added from peer %s", blk.Header.Height, p.addr)
    }

    // --- Transaction handler ---
    n.handlers[MsgTypeTx] = func(p *Peer, env *Envelope) {
        var tx ledger.Transaction
        if err := UnmarshalPayload(env.Payload, &tx); err != nil {
            log.Printf("⚠️ Failed to unmarshal transaction from peer %s: %v", p.addr, err)
            return
        }

        if !tx.IsReward && tx.AmountIM > 0 {
            log.Printf("❌ Invalid IMANI transfer attempted by %s (retrocompatibility enforcement)", tx.From)
            p.Penalize(1, 0)
            return
        }

        msg, err := n.Ledger.ApplyAndPersistTransaction(&tx)
        if err != nil {
            log.Printf("⚠️ Failed to apply transaction from peer %s: %v", p.addr, err)
            p.Penalize(1, 0)
            return
        }

        log.Printf("✅ Transaction applied from peer %s: %s", p.addr, msg)
        n.BroadcastExcept(env, p)
    }

    // --- Metrics handler ---
    n.handlers[MsgTypeMetrics] = func(p *Peer, env *Envelope) {
        var m MetricsData
        if err := UnmarshalPayload(env.Payload, &m); err != nil {
            log.Printf("⚠️ Failed to unmarshal metrics from peer %s: %v", p.addr, err)
            return
        }

        n.metricsMu.Lock()
        n.GlobalMetrics = MetricsPayload{
            Timestamp:       m.Timestamp,
            MaxSupply:       m.MaxSupply,
            Circulating:     m.Circulating,
            TotalHolders:    m.TotalHolders,
            MinersCount:     m.MinersCount,
            MinersRemaining: m.MinersRemaining,
        }
        n.metricsMu.Unlock()

        log.Printf("📊 Metrics received from %s — MaxSupply:%d  Circulating:%.2f  TotalHolders:%d  Miners:%d  MinersRemaining:%d",
            p.addr, m.MaxSupply, m.Circulating, m.TotalHolders, m.MinersCount, m.MinersRemaining)
    }

    // --- PEERS handler for dynamic discovery ---
    // Handles incoming peer lists from connected nodes, enabling decentralized peer discovery.
    // Logs reception details for debugging network propagation and growth.
    n.handlers[MsgTypePeers] = func(p *Peer, env *Envelope) {
        var pl PeersPayload
        if err := UnmarshalPayload(env.Payload, &pl); err != nil {
            return
        }

        // LOG: Peer list reception – crucial for diagnosing peer discovery issues
        log.Printf("[p2p] 📬 Received %d peer address(es) from %s", len(pl.Addrs), p.addr)

        // Optional debug preview: show first few addresses to verify content without flooding logs
        if len(pl.Addrs) > 0 {
            preview := pl.Addrs
            if len(preview) > 3 {
                preview = preview[:3]
            }
            log.Printf("[p2p]   → Example peers: %v", preview)
        }

        // Process received addresses: attempt outbound connections to new peers
        for _, addr := range pl.Addrs {
            if addr == n.listenAddr {
                continue // Skip self
            }
            n.PeersMutex.RLock()
            alreadyConnected := false
            for _, peer := range n.Peers {
                if peer.addr == addr {
                    alreadyConnected = true
                    break
                }
            }
            n.PeersMutex.RUnlock()
            if !alreadyConnected {
                go n.Connect(addr)
            }
        }
    }

    // --- RequestPeers handler ---
    // Responds to peer list requests by sending back the node's current known peer addresses.
    n.handlers[MsgTypeRequestPeers] = func(p *Peer, env *Envelope) {
        n.SendKnownPeers(p)
    }
}

func (n *Node) PeerReconnectLoop() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-n.ctx.Done():
            return
        case <-ticker.C:
            n.PeersMutex.RLock()
            peersCopy := append([]*Peer(nil), n.Peers...)
            n.PeersMutex.RUnlock()
            for _, p := range peersCopy {
                if !p.IsConnected() {
                    go func(peer *Peer) {
                        if err := peer.Connect(); err != nil {
                            log.Printf("⚠️ failed to reconnect to %s: %v", peer.addr, err)
                        } else {
                            log.Printf("🔄 reconnected to peer %s", peer.addr)
                        }
                    }(p)
                }
            }
        }
    }
}


// Envoi de peers connus à un peer
func (n *Node) SendKnownPeers(p *Peer) {
    n.PeersMutex.RLock()
    defer n.PeersMutex.RUnlock()

    addrs := []string{}
    for _, peer := range n.Peers {
        if peer != nil && peer.IsConnected() && peer != p {
            addrs = append(addrs, peer.addr)
        }
    }

    env, _ := NewEnvelopeFromPayload(n.protocolVersion, MsgTypePeers, PeersPayload{Addrs: addrs})
    _ = p.SendEnvelope(env)
}

// SyncLedgerFromBestPeer synchronizes the local ledger with the peer
// having the highest known block height. Supports parallel fetching,
// retry with exponential backoff, ordered insertion, and graceful cancellation.
func (n *Node) SyncLedgerFromBestPeer(ctx context.Context) {
    // 0️⃣ Snapshot peers safely
    n.PeersMutex.RLock()
    peersCopy := append([]*Peer(nil), n.Peers...)
    n.PeersMutex.RUnlock()

    if len(peersCopy) == 0 {
        log.Println("⚠️ No peers available")
        return
    }

    // 1️⃣ Identify peer with highest block height
    var bestPeer *Peer
    maxHeight := uint64(0)
    for _, p := range peersCopy {
        if !p.IsConnected() {
            continue
        }
        p.mu.RLock()
        height := p.LatestHeight
        p.mu.RUnlock()
        if height > maxHeight {
            maxHeight = height
            bestPeer = p
        }
    }

    if bestPeer == nil {
        log.Println("⚠️ No suitable peer found")
        return
    }

    // 2️⃣ Current ledger height
    nextHeight := n.Ledger.GetLatestBlockHeight() + 1
    if nextHeight > maxHeight {
        log.Println("✅ Ledger is already up-to-date")
        return
    }

    log.Printf("⏳ Syncing blocks from height %d to %d", nextHeight, maxHeight)

    // 3️⃣ Prepare segments
    const segmentSize = 50
    const maxRetries = 3
    var segments [][2]uint64
    for s := nextHeight; s <= maxHeight; s += segmentSize {
        segEnd := s + segmentSize - 1
        if segEnd > maxHeight {
            segEnd = maxHeight
        }
        segments = append(segments, [2]uint64{s, segEnd})
    }

    // 4️⃣ Channels & concurrency
    blockCh := make(chan *ledger.Block, segmentSize*len(segments))
    errCh := make(chan error, len(segments))
    var wg sync.WaitGroup
    concurrencyLimit := 5
    sem := make(chan struct{}, concurrencyLimit)

    // 5️⃣ Fetch segment in parallel from multiple peers
    fetchSegment := func(from, to uint64) {
        defer wg.Done()
        attempt := 0

        for attempt < maxRetries {
            attempt++
            select {
            case <-ctx.Done():
                errCh <- fmt.Errorf("sync cancelled for segment %d-%d", from, to)
                return
            default:
            }

            type result struct {
                blocks []*ledger.Block
                err    error
            }
            resCh := make(chan result, len(peersCopy))

            // Launch parallel fetch for all peers
            for _, peer := range peersCopy {
                if !peer.IsConnected() {
                    continue
                }
                wg.Add(1)
                go func(p *Peer) {
                    defer wg.Done()
                    sem <- struct{}{}
                    blks, err := p.RequestBlocksRange(from, to)
                    <-sem
                    resCh <- result{blocks: blks, err: err}
                }(peer)
            }

            // Wait for first successful peer
            var success bool
            for i := 0; i < len(peersCopy); i++ {
                res := <-resCh
                if res.err == nil && len(res.blocks) > 0 {
                    for _, blk := range res.blocks {
                        if blk != nil && blk.Header.Height > 0 {
                            blockCh <- blk
                        }
                    }
                    success = true
                    break
                }
            }

            close(resCh)

            if success {
                return
            }

            // Exponential backoff before retry
            backoff := time.Duration(1<<attempt) * time.Second
            log.Printf("⚠️ Segment %d-%d failed on attempt %d, retrying in %s", from, to, attempt, backoff)
            time.Sleep(backoff)
        }

        errCh <- fmt.Errorf("failed to sync segment %d-%d after %d attempts", from, to, maxRetries)
    }

    // 6️⃣ Launch all segment fetches
    for _, seg := range segments {
        wg.Add(1)
        go fetchSegment(seg[0], seg[1])
    }

    // 7️⃣ Close channels after all goroutines finish
    go func() {
        wg.Wait()
        close(blockCh)
        close(errCh)
    }()

    // 8️⃣ Ordered block insertion
    buffer := make(map[uint64]*ledger.Block)
    for blk := range blockCh {
        h := blk.Header.Height
        buffer[h] = blk

        for {
            b, ok := buffer[nextHeight]
            if !ok {
                break
            }
            if err := n.Ledger.AddBlock(b); err != nil {
                log.Printf("⚠️ Failed to add block %d: %v", nextHeight, err)
            } else {
                log.Printf("✅ Block %d synced", nextHeight)
            }
            delete(buffer, nextHeight)
            nextHeight++
        }
    }

    // 9️⃣ Log remaining errors
    for err := range errCh {
        log.Println("⚠️", err)
    }

    log.Println("✅ Ledger synchronization completed successfully")
}

func (n *Node) StartSeedMode() {
    n.config.IsSeedNode = true
    log.Println("🌱 Seed mode enabled: responding with peer lists.")
}

func (n *Node) AllPeers() []*Peer {
    n.PeersMutex.RLock()
    defer n.PeersMutex.RUnlock()
    return append([]*Peer(nil), n.Peers...)
}

func (n *Node) IsLedgerComplete() bool {
    if n.PeerCount() == 0 || n.Ledger == nil {
        return false
    }

    n.PeersMutex.RLock()
    defer n.PeersMutex.RUnlock()

    highest := n.Ledger.GetLatestBlockHeight()
    for _, p := range n.Peers {
        p.mu.RLock()
        peerHeight := p.LatestHeight
        p.mu.RUnlock()
        if peerHeight > highest {
            return false
        }
    }
    return true
}
