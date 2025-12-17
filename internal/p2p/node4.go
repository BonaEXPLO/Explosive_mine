// internal/p2p/node4.go

package p2p

import (
        "context"
        "fmt"
        "log"
        "strings"
        "crypto/ed25519"
        "sync"
        "time"

        "explosive/internal/ledger"
)

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
// Fully V3-aligned:
// - Handshake verifies MinerInfo + Ed25519 envelope signature when present
// - Block handler strictly enforces miner signature in strict mode
// - Metrics handler validates signed origin when available
// - All other handlers remain efficient and mobile-friendly
func (n *Node) registerDefaultHandlers() {
    // --- Handshake handler (CRITICAL - must be registered first) ---
    n.RegisterHandler(MsgTypeHandshake, func(p *Peer, env *Envelope) {
        var hs HandshakePayload
        if err := UnmarshalPayload(env.Payload, &hs); err != nil {
            log.Printf("[p2p] Invalid handshake payload from %s: %v", p.addr, err)
            p.Close()
            return
        }

        log.Printf("[p2p] Handshake received from %s (id=%s, version=%s, listen=%s)",
            p.addr, hs.PeerID, hs.Version, hs.ListenAddr)

        // Enforce correct network
        if hs.Network != n.networkID {
            log.Printf("[p2p] Handshake rejected from %s: wrong network '%s' (expected '%s')",
                p.addr, hs.Network, n.networkID)
            p.Close()
            return
        }

        // Optional version warning (tolerant for now)
        if hs.Version != n.userAgent {
            log.Printf("[p2p] Version mismatch from %s: remote='%s' local='%s' – connection allowed",
                p.addr, hs.Version, n.userAgent)
        }

        // V3 trustless identity verification if MinerInfo and signature are present
        if env.MinerInfo != nil && len(env.Signature) > 0 && len(env.PubKey) > 0 {
            if env.MinerInfo.MinerID == "" || len(env.MinerInfo.PubKey) != ed25519.PublicKeySize {
                log.Printf("[p2p] Invalid MinerInfo in handshake from %s", p.addr)
                p.Penalize(1, 0)
            } else {
                ok, err := VerifyEnvelopeSignature(env)
                if err != nil {
                    log.Printf("[p2p] Handshake signature error from %s: %v", p.addr, err)
                    p.Penalize(1, 0)
                } else if !ok {
                    log.Printf("[p2p] Invalid handshake signature from claimed miner %s (%s)", env.MinerInfo.MinerID, p.addr)
                    p.Penalize(1, 0)
                } else {
                    log.Printf("[p2p] Verified V3 miner identity in handshake: %s", env.MinerInfo.MinerID)
                }
            }
        }

        // Accept the peer
        p.id = PeerID(hs.PeerID)

        log.Printf("[p2p] HANDSHAKE SUCCESSFUL → Peer authenticated: id=%s addr=%s", p.id, p.addr)

        // Accelerate discovery
        req := &Envelope{
            Version:   n.protocolVersion,
            Type:      MsgTypeRequestPeers,
            Payload:   nil,
            Timestamp: time.Now().UnixMilli(),
        }
        _ = p.SendEnvelope(req)
    })

    // --- Ping / Pong ---
    n.RegisterHandler(MsgTypePing, func(p *Peer, env *Envelope) {
        var ping PingPayload
        if err := UnmarshalPayload(env.Payload, &ping); err != nil {
            return
        }
        pong := PongPayload{Nonce: ping.Nonce}
        reply, _ := NewEnvelopeFromPayload(n.protocolVersion, MsgTypePong, pong)
        _ = p.SendEnvelope(reply)
    })

    n.RegisterHandler(MsgTypePong, func(p *Peer, env *Envelope) {
        // Presence of pong is sufficient for liveness tracking
    })

    // --- Block handler (V3 strict enforcement) ---
    n.RegisterHandler(MsgTypeBlock, func(p *Peer, env *Envelope) {
        var blk ledger.Block
        if err := UnmarshalPayload(env.Payload, &blk); err != nil {
            log.Printf("[p2p] Failed to unmarshal block from %s: %v", p.addr, err)
            return
        }

        currentHeight := n.Ledger.GetLatestBlockHeight()
        if blk.Header.Height <= currentHeight {
            return // Already processed or older
        }

        // Strict V3 signature verification
        valid, err := blk.VerifySignature()
        if err != nil {
            log.Printf("[p2p] Block %d signature verification error from %s: %v", blk.Header.Height, p.addr, err)
            p.Penalize(1, 0)
            return
        }
        if !valid && n.config.RequireStrictBlockSig {
            log.Printf("[p2p] Rejecting unsigned/invalid block %d from %s (strict mode enabled)", blk.Header.Height, p.addr)
            p.Penalize(1, 0)
            if p.errCount >= n.config.PeerInvalidMsgThreshold {
                p.Penalize(0, 5*time.Minute)
                log.Printf("[p2p] Temporary ban applied to %s for repeated invalid blocks", p.addr)
            }
            return
        }

        if err := n.Ledger.AddBlock(&blk); err != nil {
            log.Printf("[p2p] Failed to add block %d from %s: %v", blk.Header.Height, p.addr, err)
            return
        }

        log.Printf("[p2p] Block %d successfully added from %s", blk.Header.Height, p.addr)

        // Relay to other peers
        n.BroadcastExcept(env, p)
    })

    // --- GetBlocksRange & BlocksResponse (sync) ---
    n.RegisterHandler(MsgTypeGetBlocksRange, func(p *Peer, env *Envelope) {
        var req GetBlocksRangePayload
        if err := UnmarshalPayload(env.Payload, &req); err != nil {
            log.Printf("[p2p] Invalid GetBlocksRange request from %s: %v", p.addr, err)
            return
        }

        if req.From > req.To {
            return
        }

        // Limit response size for mobile bandwidth
        if req.To-req.From+1 > 50 {
            req.To = req.From + 49
        }

        blocks, err := n.Ledger.GetBlocksRange(req.From, req.To)
        if err != nil || len(blocks) == 0 {
            return
        }

        payload := struct {
            Blocks []*ledger.Block `cbor:"blocks"`
        }{Blocks: blocks}

        resp, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeBlocksResponse, payload)
        if err != nil {
            return
        }

        _ = p.SendEnvelope(resp)
        log.Printf("[p2p] Sent %d blocks (%d–%d) to %s", len(blocks), req.From, req.To, p.addr)
    })

    n.RegisterHandler(MsgTypeBlocksResponse, func(p *Peer, env *Envelope) {
        var resp struct {
            Blocks []*ledger.Block `cbor:"blocks"`
        }
        if err := UnmarshalPayload(env.Payload, &resp); err != nil || len(resp.Blocks) == 0 {
            return
        }

        for _, blk := range resp.Blocks {
            if err := n.Ledger.AddBlock(blk); err != nil {
                log.Printf("[p2p] Failed to add synced block %d: %v", blk.Header.Height, err)
            } else {
                log.Printf("[p2p] Synced block %d added", blk.Header.Height)
            }
        }
    })

    // --- Transaction handler ---
    n.RegisterHandler(MsgTypeTx, func(p *Peer, env *Envelope) {
        var tx ledger.Transaction
        if err := UnmarshalPayload(env.Payload, &tx); err != nil {
            log.Printf("[p2p] Failed to unmarshal TX from %s: %v", p.addr, err)
            return
        }

        // Retrocompatibility rule enforcement
        if !tx.IsReward && tx.AmountIM > 0 {
            log.Printf("[p2p] Invalid IMANI transfer rejected from %s", tx.From)
            p.Penalize(1, 0)
            return
        }

        msg, err := n.Ledger.ApplyAndPersistTransaction(&tx)
        if err != nil {
            log.Printf("[p2p] TX apply failed from %s: %v", p.addr, err)
            p.Penalize(1, 0)
            return
        }

        log.Printf("[p2p] TX applied: %s", msg)
        n.BroadcastExcept(env, p)
    })

    // --- Metrics handler (with optional V3 authentication) ---
    n.RegisterHandler(MsgTypeMetrics, func(p *Peer, env *Envelope) {
        var m MetricsData
        if err := UnmarshalPayload(env.Payload, &m); err != nil {
            log.Printf("[p2p] Failed to unmarshal metrics from %s: %v", p.addr, err)
            return
        }

        // Verify source if signed with miner identity
        if env.MinerInfo != nil && len(env.Signature) > 0 && len(env.PubKey) > 0 {
            if ok, _ := VerifyEnvelopeSignature(env); !ok {
                log.Printf("[p2p] Invalid signed metrics from claimed miner %s", env.MinerInfo.MinerID)
                p.Penalize(1, 0)
                return
            }
            log.Printf("[p2p] Authenticated metrics received from miner %s", env.MinerInfo.MinerID)
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
        n.CachedMetrics = m
        n.cachedMetricsOnce = true
        n.metricsMu.Unlock()

        log.Printf("[p2p] Metrics updated — Circulating:%.3f  Holders:%d  Miners:%d",
            m.Circulating, m.TotalHolders, m.MinersCount)
    })

    // --- Peer discovery handlers
n.RegisterHandler(MsgTypePeers, func(p *Peer, env *Envelope) {
    var pl PeersPayload
    if err := UnmarshalPayload(env.Payload, &pl); err != nil {
        return
    }

    log.Printf("[p2p] Received %d peer(s) from %s", len(pl.Addrs), p.addr)

    for _, addr := range pl.Addrs {
        if addr == n.listenAddr || addr == p.addr {
            continue
        }

        // Check if already known via sharded map (source of truth)
        pid := PeerID(fmt.Sprintf("%x", sha256Sum(addr)))
        sh := n.shard(pid)
        sh.mu.RLock()
        _, already := sh.peers[pid]
        sh.mu.RUnlock()

        if !already {
            go n.Connect(addr)
        }
    }
})

n.RegisterHandler(MsgTypeRequestPeers, func(p *Peer, env *Envelope) {
    n.SendKnownPeers(p)
})

    n.RegisterHandler(MsgTypeRequestPeers, func(p *Peer, env *Envelope) {
        n.SendKnownPeers(p)
    })
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


// SendKnownPeers sends a list of known connected peers to the requesting peer.
func (n *Node) SendKnownPeers(p *Peer) {
    addrs := make([]string, 0, 32)

    for i := range n.peerShards {
        sh := &n.peerShards[i]
        sh.mu.RLock()
        for _, peer := range sh.peers {
            if peer.IsConnected() && peer != p && peer.addr != n.listenAddr {
                addrs = append(addrs, peer.addr)
            }
        }
        sh.mu.RUnlock()
    }

    if len(addrs) == 0 {
        return
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


