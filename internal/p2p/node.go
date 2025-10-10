// internal/p2p/node.go
// Patched version — Assistant improvements applied.
// NOTE_FOR_AUDIT: This file has received the following concrete improvements so they are
// not unintentionally duplicated in other files:
//  - inbound channel now carries peer context so handlers receive the originating peer.
//  - Signature verification / policy (RequireSignedMessages) enforced here; message-level
//    signature helpers live in message.go and are reused to avoid duplication.
//  - Peer eviction/watchdog implemented (PeerEvictionTimeout) to remove inactive peers.
//  - Global MaxPeers enforcement (prevent accepting new peers when at capacity).
//  - Per-peer invalid-message penalties & automatic temporary ban when threshold exceeded
//    (PeerInvalidMsgThreshold). Scoring/penalize logic uses Peer.Penalize already defined
//    in peer.go to avoid duplication.
//  - Deterministic port derivation helpers added: DerivePortFromIdentity,
//    DeriveListenAddrFromIdentity and ApplyDerivedListenAddrToNode.
//    These helpers do NOT change existing NewNode() signature — call ApplyDerivedListenAddrToNode
//    after restoring miner identity to apply the derived listen address.

package p2p

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
        "crypto/sha3"
	"encoding/binary"
	"encoding/hex"
        "strconv"
	"errors"
        "sort"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
        "explosive/internal/ledger"
)

// NodeConfig holds tunables for the P2P node.
type NodeConfig struct {
	ListenAddr              string
	DialTimeout             time.Duration
	ConnReadTimeout         time.Duration // read deadline for peer connections
	ConnWriteTimeout        time.Duration // write deadline for peer connections
	FlushInterval           time.Duration // periodic flush interval for write loop
	PeerDialPeriod          time.Duration
	MaxPeers                int
	SendQueueSize           int
	MaxMsgSize              int
	ProtocolName            string
	ProtocolVer             string
	MaxIncomingQueue        int // accept queue
	AcceptWorkers           int
	MaxBroadcastFanout      int // per shard
	// Additional node-level policies
	RequireSignedMessages    bool          // if true, reject envelopes without valid signature
	PeerEvictionTimeout      time.Duration // inactive peer eviction timeout
	PeerInvalidMsgThreshold  int           // number of invalid msgs before ban
}

// incomingMsg bundles a peer reference and envelope for dispatch.
type incomingMsg struct {
	peer *Peer
	env  *Envelope
}

// Node represents the local p2p node: listener, peers map and message handlers.

type Node struct {
    // Existing fields
    id              PeerID
    listenAddr      string
    networkID       string
    userAgent       string
    protocolVersion uint16
    config          NodeConfig

    ln         net.Listener
    peerShards []peerShard
    numShards  int
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
    inboundCh  chan *incomingMsg
    handlerMux sync.RWMutex
    handlers   map[MessageType]func(*Peer, *Envelope)
    metricsMu sync.RWMutex
    numInvalidMessages int

    // New fields for Mainnet
    Ledger *ledger.Ledger // pointer to local ledger
    Peers  []*Peer        // list of connected peers
}

type peerShard struct {
	peers map[PeerID]*Peer
	mu    sync.RWMutex
}

// NewNode constructs a Node with reasonable defaults.
func NewNode(listenAddr, networkID, userAgent string) *Node {
	r := make([]byte, 8)
	_, _ = rand.Read(r)
	id := PeerID(hex.EncodeToString(r))

	cfg := NodeConfig{
		ListenAddr:               listenAddr,
		DialTimeout:              3 * time.Second,
		ConnReadTimeout:          60 * time.Second,
		ConnWriteTimeout:         30 * time.Second,
		FlushInterval:            100 * time.Millisecond,
		PeerDialPeriod:           10 * time.Second,
		MaxPeers:                 10_000,
		SendQueueSize:            64,
		MaxMsgSize:               4 * 1024 * 1024,
		ProtocolName:             "explosive-p2p",
		ProtocolVer:              "1.0",
		MaxIncomingQueue:         256,
		AcceptWorkers:            4,
		MaxBroadcastFanout:       50,
		RequireSignedMessages:    false,
		PeerEvictionTimeout:      15 * time.Minute,
		PeerInvalidMsgThreshold:  5,
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

// shard selects the shard for a given peerID.
func (n *Node) shard(pid PeerID) *peerShard {
	if len(pid) == 0 {
		// fallback
		return &n.peerShards[0]
	}
	h := int(pid[0])
	return &n.peerShards[h%len(n.peerShards)]
}

// Start begins listening and dispatching messages.
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

	n.wg.Add(1)
	go n.acceptLoop()

	n.wg.Add(1)
	go n.messageDispatcher()

	// start watchdog to evict inactive peers and enforce capacity periodically
	n.wg.Add(1)
	go n.watchdogLoop()

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

func (n *Node) handleNewConnection(conn net.Conn) {
	peerAddr := conn.RemoteAddr().String()
	p := NewPeer(PeerID(peerAddr), peerAddr, n)
	p.mu.Lock()
	p.conn = conn
	p.connected = true
	p.mu.Unlock()
	p.wg.Add(2)
	go p.readLoop()
	go p.writeLoop()
	n.addPeer(p)
}

// addPeer adds a peer to the proper shard.
func (n *Node) addPeer(p *Peer) {
	sh := n.shard(p.id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	// ensure not exceeding per-shard capacity (approximation)
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
}

// Connect dials a remote peer.
func (n *Node) Connect(addr string) (*Peer, error) {
	p := NewPeer(PeerID(addr), addr, n)
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

// Broadcast sends envelope to a subset of peers (fan-out).
func (n *Node) Broadcast(e *Envelope) {
	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		count := 0
		for _, p := range sh.peers {
			if count >= n.config.MaxBroadcastFanout {
				break
			}
			if p == nil || !p.IsConnected() {
				continue
			}
			_ = p.SendEnvelope(e)
			count++
		}
		sh.mu.RUnlock()
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
	for {
		select {
		case <-n.ctx.Done():
			return
		case m := <-n.inboundCh:
			if m == nil || m.env == nil {
				continue
			}
			n.handlerMux.RLock()
			h, ok := n.handlers[m.env.Type]
			n.handlerMux.RUnlock()
			if ok && h != nil {
				// call handler in dedicated goroutine, passing originating peer
				go h(m.peer, m.env)
				continue
			}
			log.Printf("p2p: unhandled message type %s", m.env.Type)
		}
	}
}

func (n *Node) registerDefaultHandlers() {
    // Existing Ping/Pong handlers
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
    n.handlers[MsgTypePong] = func(p *Peer, env *Envelope) {}

    // --- New: block received from a peer ---
    n.handlers[MsgTypeBlock] = func(p *Peer, env *Envelope) {
        var blk ledger.Block
        if err := UnmarshalPayload(env.Payload, &blk); err != nil {
            log.Printf("⚠️ Failed to unmarshal block from peer %s: %v", p.addr, err)
            return
        }
        // Check if block is already present
        if blk.Header.Height <= n.Ledger.GetLatestBlockHeight() {
            return
        }
        // Add block to the ledger
        if err := n.Ledger.AddBlock(&blk); err != nil {
            log.Printf("⚠️ Failed to add block from peer %s: %v", p.addr, err)
            return
        }
        log.Printf("✅ Block %d added from peer %s", blk.Header.Height, p.addr)
    }

    // --- New: transaction received from a peer ---
    n.handlers[MsgTypeTx] = func(p *Peer, env *Envelope) {
        var tx ledger.Transaction
        if err := UnmarshalPayload(env.Payload, &tx); err != nil {
            log.Printf("⚠️ Failed to unmarshal transaction from peer %s: %v", p.addr, err)
            return
        }
        if err := n.Ledger.ApplyTransaction(&tx); err != nil {
            log.Printf("⚠️ Failed to apply transaction from peer %s: %v", p.addr, err)
            return
        }
        log.Printf("✅ Transaction applied from peer %s", p.addr)
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
//
// Important: cleanup (p.Close) is executed in a separate goroutine to avoid
// deadlocks when this function is called from the peer's own read/write loops.
func (n *Node) handlePeerDisconnect(p *Peer) {
	if p == nil {
		return
	}

	// Locate the shard for this peer and remove it safely.
	sh := n.shard(p.id)
	sh.mu.Lock()
	if existing, ok := sh.peers[p.id]; ok && existing == p {
		delete(sh.peers, p.id)
	}
	sh.mu.Unlock()

	// Log for observability
	log.Printf("[p2p] peer disconnected: id=%s addr=%s", p.id, p.addr)

	// Ensure resource cleanup happens asynchronously to avoid waiting inside
	// the peer's goroutine (which could cause a deadlock).
	go func() {
		// Close is idempotent and safe to call multiple times.
		p.Close()
	}()
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
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(out))))
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
			return
		case <-ticker.C:
			// evict inactive peers
			evictBefore := time.Now().Add(-n.config.PeerEvictionTimeout)
			for i := range n.peerShards {
				sh := &n.peerShards[i]
				sh.mu.Lock()
				for id, p := range sh.peers {
					p.mu.RLock()
					ls := p.lastSeen
					p.mu.RUnlock()
					if ls.IsZero() || ls.Before(evictBefore) {
						delete(sh.peers, id)
						log.Printf("p2p: evicted inactive peer id=%s addr=%s", id, p.addr)
						go p.Close()
					}
				}
				sh.mu.Unlock()
			}

// --- Fetch new blocks from connected peers after peer eviction ---
newBlocks, err := n.FetchBlocks()
if err != nil {
    log.Printf("⚠️ Failed to fetch blocks: %v", err)
} else {
    for _, blk := range newBlocks {
        ok, err := blk.VerifySignature() // Ledger/Block method to implement
        if err != nil || !ok {
            log.Printf("⚠️ Invalid block signature for block %d", blk.Header.Height)
            continue
        }
        if err := n.Ledger.AddBlock(blk); err == nil {
            log.Printf("✅ Block %d fetched and added from peers", blk.Header.Height)
        }
    }
}
			// enforce global capacity: if over, remove least-recently-seen (simple heuristic)
			for n.PeerCount() > n.config.MaxPeers {
				// find a victim
				var victimID PeerID
				var victimPeer *Peer
				var oldest time.Time = time.Now()
				for i := range n.peerShards {
					sh := &n.peerShards[i]
					sh.mu.RLock()
					for id, p := range sh.peers {
						p.mu.RLock()
						ls := p.lastSeen
						p.mu.RUnlock()
						if ls.IsZero() || ls.Before(oldest) {
							oldest = ls
							victimID = id
							victimPeer = p
						}
					}
					sh.mu.RUnlock()
				}
				if victimPeer != nil {
					log.Printf("p2p: evicting peer to enforce capacity id=%s addr=%s", victimID, victimPeer.addr)
					n.handlePeerDisconnect(victimPeer)
				} else {
					break
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

// DerivePortFromIdentity returns a deterministically-derived port from walletID & 4 words.
// Result is within [defaultMinPort, defaultMaxPort].
func DerivePortFromIdentity(walletID string, words []string) (int, error) {
	if walletID == "" {
		return 0, errors.New("empty walletID")
	}
	if len(words) != 4 {
		return 0, errors.New("consciousness words must be 4 items")
	}
	joined := normalizeAndJoinWords(words)
	input := walletID + ":" + joined

	h := sha256.Sum256([]byte(input))
	v := binary.BigEndian.Uint32(h[0:4])

	min := defaultMinPort
	max := defaultMaxPort
	if min < 1025 {
		min = 1025
	}
	if max > 65535 {
		max = 65535
	}
	if max <= min {
		return 0, errors.New("invalid port range")
	}
	rangeSize := uint32(max - min + 1)
	port := int(min + int(v%rangeSize))
	return port, nil
}

// DeriveListenAddrFromIdentity returns "0.0.0.0:PORT" using DerivePortFromIdentity.
func DeriveListenAddrFromIdentity(walletID string, words []string) (string, error) {
	p, err := DerivePortFromIdentity(walletID, words)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0.0.0.0:%d", p), nil
}

// ApplyDerivedListenAddrToNode applies the derived listen address to the node if the node
// currently has no explicit listenAddr set. It returns the applied listenAddr and error if any.
// Use this after the miner identity (walletID and 4 words) is available (e.g. after restore).
func ApplyDerivedListenAddrToNode(n *Node, walletID string, words []string) (string, error) {
	if n == nil {
		return "", errors.New("nil node")
	}
	// if node already has explicit listen address, do not override
	if n.listenAddr != "" {
		return n.listenAddr, nil
	}
	la, err := DeriveListenAddrFromIdentity(walletID, words)
	if err != nil {
		return "", err
	}
	n.listenAddr = la
	return la, nil
}

// FetchBlocks retrieves all new blocks from connected peers in ascending order by height.
// Only blocks that are higher than the local ledger's latest block are fetched.
func (n *Node) FetchBlocks() ([]*ledger.Block, error) {
	if n == nil {
		return nil, fmt.Errorf("p2p node not initialized")
	}
	if n.Ledger == nil {
		return nil, fmt.Errorf("local ledger not initialized")
	}

	var newBlocks []*ledger.Block
	latestHeight := n.Ledger.GetLatestBlockHeight() // utilise la méthode Ledger

	for _, peer := range n.Peers {
		peerBlocks, err := peer.RequestBlocksSince(latestHeight)
		if err != nil {
			fmt.Printf("⚠️ Failed to fetch blocks from peer %s: %v\n", peer.addr, err)
			continue
		}

		for _, blk := range peerBlocks {
			// Only add blocks that are higher than local height
			if blk.Header.Height > latestHeight {
				newBlocks = append(newBlocks, blk)
			}
		}
	}

	// Remove duplicates by BlockHash
	unique := make(map[string]*ledger.Block)
	for _, blk := range newBlocks {
		unique[blk.BlockHash] = blk
	}

	newBlocks = make([]*ledger.Block, 0, len(unique))
	for _, blk := range unique {
		newBlocks = append(newBlocks, blk)
	}

	// Sort blocks in ascending height order
	sort.Slice(newBlocks, func(i, j int) bool {
		return newBlocks[i].Header.Height < newBlocks[j].Header.Height
	})

	return newBlocks, nil
}

// DeriveWalletPort returns a deterministic port for wallet-only users
// based on their public wallet address. This ensures each wallet has
// a unique listening port without requiring mining credentials.
func DeriveWalletPort(walletAddress string) string {
    if walletAddress == "" {
        return "5001" // fallback port if address is empty
    }
    hash := Sha3Hex([]byte(walletAddress)) // hash wallet address
    last4 := hash[len(hash)-4:]            // take last 4 hex chars
    n, err := strconv.ParseInt(last4, 16, 32)
    if err != nil {
        return "5001" // fallback port on parse error
    }
    port := 5000 + (n % (59999 - 5000)) // assign port in reserved wallet range
    return strconv.Itoa(int(port))
}

// AutoDerivePort returns the correct listening port for a node
// depending on whether it is a miner or a wallet-only user.
// - minerID + 4 words: mine node
// - walletAddress only: wallet node
func AutoDerivePort(minerID string, words []string, walletAddress string) string {
    if minerID != "" && len(words) == 4 {
        return DeriveListenPort(minerID, words) // miner
    }
    return DeriveWalletPort(walletAddress) // wallet-only user
}


// ConnectWalletToP2P initializes a wallet-only P2P node and connects
// to a list of known peers. It allows wallets to receive blocks and
// interact with the network without mining.
func ConnectWalletToP2P(walletAddress string, knownPeers []string) (*Node, error) {
    port := DeriveWalletPort(walletAddress)
    listenAddr := "0.0.0.0:" + port

    node := NewNode(listenAddr, "explosive-mainnet", "wallet-client")
    err := node.Start()
    if err != nil {
        return nil, err
    }

    // connect to known peers
    for _, peerAddr := range knownPeers {
        _, err := node.Connect(peerAddr)
        if err != nil {
            log.Printf("⚠️ Failed to connect to peer %s: %v", peerAddr, err)
            continue
        }
        log.Printf("✅ Connected to peer %s", peerAddr)
    }

    return node, nil
}

// Sha3Hex computes SHA3-256 hash of input bytes and returns the hex string
func Sha3Hex(data []byte) string {
    hash := sha3.Sum256(data)
    return hex.EncodeToString(hash[:])
}

// DeriveListenPort computes a unique listening port (4000–65535) based on minerID + 4 sacred words
func DeriveListenPort(minerID string, words []string) string {
    if len(words) != 4 {
        return "4001"
    }

    key := minerID + "-" + strings.Join(words, "-")
    hash := Sha3Hex([]byte(key))

    last4 := hash[len(hash)-4:]
    n, err := strconv.ParseInt(last4, 16, 32)
    if err != nil {
        return "4001"
    }

    port := 4000 + (n % (65535 - 4000))
    return strconv.Itoa(int(port))
}
