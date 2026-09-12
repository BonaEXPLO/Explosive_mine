// internal/p2p/node3.go
package p2p
import (
        "encoding/hex"
        "github.com/fxamacker/cbor/v2"
        "log"
        "time"
        "explosive/internal/ledger"
)

func (n *Node) registerDefaultHandlers() {

	// =========================================================
	// HANDSHAKE (CRITICAL)
	// =========================================================
	n.RegisterHandler(MsgTypeHandshake, func(p *Peer, env *Envelope) {

		p.handshakeOnce.Do(func() {

			var hs HandshakePayload
			if err := UnmarshalPayload(env.Payload, &hs); err != nil {
				log.Printf("[p2p] Invalid handshake payload from %s: %v", p.addr, err)
				p.Close()
				return
			}

			log.Printf("[p2p] Handshake received from %s (id=%s, version=%s, listen=%s)",
				p.addr, hs.PeerID, hs.Version, hs.ListenAddr)

			// ---------------- NETWORK CHECK ----------------
			if hs.Network != n.networkID {
				log.Printf("[p2p] Handshake rejected from %s: wrong network '%s'", p.addr, hs.Network)
				p.Close()
				return
			}

			// ---------------- VERSION CHECK ----------------
			if hs.Version != n.userAgent {
				log.Printf("[p2p] Version mismatch %s remote=%s local=%s",
					p.addr, hs.Version, n.userAgent)
			}

			// =====================================================
// 🔥 LEDGER IDENTITY CHECK
// =====================================================

p.id = PeerID(hs.PeerID)

if !n.verifyPeerOnChain(p.id) {
        log.Printf("[p2p] 🚫 peer not in ledger identity set: %s", p.id)
        p.Close()
        return
}

			// =====================================================
			// V3 MINER AUTH
			// =====================================================
			if env.MinerInfo != nil && len(env.Signature) > 0 && len(env.PubKey) > 0 {

				ok, err := VerifyEnvelopeSignature(env)
				if err != nil {
					log.Printf("[p2p] V3 signature error %s: %v", p.addr, err)
					p.Penalize(5, 0)
				} else if ok {

					p.mu.Lock()
					p.verifiedMinerID = env.MinerInfo.MinerID
					p.verifiedPubKey = env.MinerInfo.PubKey
					p.verifiedMiner = true
					p.mu.Unlock()

					log.Printf("[p2p] ✅ Verified conscious miner: %s", env.MinerInfo.MinerID)
				} else {
					log.Printf("[p2p] Invalid V3 signature miner %s", env.MinerInfo.MinerID)
					p.Penalize(10, time.Hour)
					p.Close()
					return
				}
			}

			role := "observer/investor"
			if p.IsVerifiedMiner() {
				role = "verified conscious miner"
			}

			p.mu.Lock()
alreadyDone := p.handshakeDone
p.handshakeDone = true
p.mu.Unlock()

if !alreadyDone {

        // Register peer after successful validation
        n.addPeer(p)

        // Release bootstrap waiters
        select {
        case <-p.handshakeCh:
                // already closed
        default:
                close(p.handshakeCh)
        }

        log.Printf(
                "[p2p] ✅ BIDIRECTIONAL HANDSHAKE COMPLETE → %s (%s)",
                p.id,
                role,
        )
}
		})
	})

	// =========================================================
	// PING / PONG (UNCHANGED)
	// =========================================================
	n.RegisterHandler(MsgTypePing, func(p *Peer, env *Envelope) {
		var ping PingPayload
		if err := UnmarshalPayload(env.Payload, &ping); err != nil {
			return
		}
		pong := PongPayload{Nonce: ping.Nonce}
		reply, _ := NewEnvelopeFromPayload(n.protocolVersion, MsgTypePong, pong)
		_ = p.SendEnvelope(reply)
	})

	n.RegisterHandler(MsgTypePong, func(p *Peer, env *Envelope) {})

	// =========================================================
	// INV (SAFE + CONSENSUS AWARE)
	// =========================================================
	n.RegisterHandler(MsgTypeInv, func(p *Peer, env *Envelope) {

		inv, err := DecodeInvPayload(env.Payload)
		if err != nil {
			log.Printf("[p2p] Invalid INV payload from %s: %v", p.addr, err)
			return
		}

		if inv.Kind != InvKindBlockHeader && inv.Kind != InvKindBlockFull {
			return
		}

		var requestHashes [][]byte

		for _, h := range inv.Hashes {

			hashStr := hex.EncodeToString(h)

			_, ok := n.Ledger.GetHeightByBlockHash(hashStr)
			if ok {
				continue
			}

			requestHashes = append(requestHashes, h)
		}

		if len(requestHashes) > 0 {

			getEnv, err := NewGetDataMessage(InvKindBlockHeader, requestHashes)
			if err == nil {
				_ = p.SendEnvelope(getEnv)
			}
		}
	})

	// =========================================================
	// GETDATA (UNCHANGED + SAFE LIMITS)
	// =========================================================
	n.RegisterHandler(MsgTypeGetData, func(p *Peer, env *Envelope) {

		req, err := DecodeGetDataPayload(env.Payload)
		if err != nil {
			return
		}

		if len(req.Hashes) > 50 {
			req.Hashes = req.Hashes[:50]
		}

		for _, hashBytes := range req.Hashes {

			hashStr := hex.EncodeToString(hashBytes)

			blk, err := n.Ledger.GetBlockByHash(hashStr)
			if err != nil || blk == nil {
				continue
			}

			// 🔥 SAFETY: require PoW existence
			if blk.Header.DailyPoW == nil {
				continue
			}

			var payload []byte
			var kind string

			if req.Kind == InvKindBlockHeader || blk.IsLightBlock() {
				h := *blk
				h.Transactions = nil
				payload, _ = cbor.Marshal(h)
				kind = InvKindBlockHeader
			} else {
				payload, _ = cbor.Marshal(blk)
				kind = InvKindBlockFull
			}

			blockEnv, _ := NewEnvelopeFromPayload(n.ProtocolVersion(),
				MsgTypeBlock, BlockPayload{
					Kind: kind,
					Data: payload,
				})

			_ = p.SendEnvelope(blockEnv)
		}
	})

	// =========================================================
	// BLOCK (🔥 FULL CONSENSUS SECURITY FIX)
	// =========================================================
	n.RegisterHandler(MsgTypeBlock, func(p *Peer, env *Envelope) {

		var bp BlockPayload
		if err := UnmarshalPayload(env.Payload, &bp); err != nil {
			p.Penalize(5, 0)
			return
		}

		var blk ledger.Block
		if err := cbor.Unmarshal(bp.Data, &blk); err != nil {
			p.Penalize(5, 0)
			return
		}

		// ---------------- MINER CHECK ----------------
		if !p.IsVerifiedMiner() {
			p.Penalize(20, 24*time.Hour)
			return
		}

		// ---------------- POW VALIDATION (CRITICAL FIX) ----------------
		if blk.Header.DailyPoW == nil {
    p.Penalize(10, 0)
    return
}

if !ledger.VerifyDailyPoW(
    blk.Header.MinerAddress,
    *blk.Header.DailyPoW,
    blk.Header.PrevHash,
) {
    p.Penalize(15, time.Hour)
    return
}
		// ---------------- HEIGHT CHECK ----------------
		currentHeight := n.Ledger.GetLatestBlockHeight()
		if blk.Header.Height <= currentHeight {
			return
		}

		// ---------------- SIGNATURE CHECK ----------------
		ok, err := blk.VerifySignature()
		if err != nil || !ok {
			p.Penalize(10, 6*time.Hour)
			return
		}

		// ---------------- LEDGER APPLY ----------------
		if err := n.Ledger.AddBlock(&blk); err != nil {
			return
		}

		log.Printf("[p2p] ✅ Block #%d accepted", blk.Header.Height)

		bh, _ := hex.DecodeString(blk.BlockHash)
		n.BroadcastBlockInv(bh, InvKindBlockFull)
	})

	// =========================================================
	// GET BLOCK RANGE (UNCHANGED)
	// =========================================================
	n.RegisterHandler(MsgTypeGetBlocksRange, func(p *Peer, env *Envelope) {

		var req GetBlocksRangePayload
		if err := UnmarshalPayload(env.Payload, &req); err != nil {
			return
		}

		if req.From > req.To {
			return
		}

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

		resp, _ := NewEnvelopeFromPayload(n.ProtocolVersion(),
			MsgTypeBlocksResponse, payload)

		_ = p.SendEnvelope(resp)
	})

	// =========================================================
	// BLOCKS RESPONSE (UNCHANGED)
	// =========================================================
	n.RegisterHandler(MsgTypeBlocksResponse, func(p *Peer, env *Envelope) {

		var resp struct {
			Blocks []*ledger.Block `cbor:"blocks"`
		}

		if err := UnmarshalPayload(env.Payload, &resp); err != nil {
			return
		}

		for _, blk := range resp.Blocks {
			_ = n.Ledger.AddBlock(blk)
		}
	})

	// =========================================================
	// TRANSACTIONS (UNCHANGED)
	// =========================================================
	n.RegisterHandler(MsgTypeTx, func(p *Peer, env *Envelope) {

		var tx ledger.Transaction
		if err := UnmarshalPayload(env.Payload, &tx); err != nil {
			return
		}

		if !tx.IsReward && tx.AmountIM > 0 {
			p.Penalize(1, 0)
			return
		}

		_, err := n.Ledger.ApplyAndPersistTransaction(&tx)
		if err != nil {
			p.Penalize(1, 0)
			return
		}

		n.BroadcastExcept(env, p)
	})

	// =========================================================
	// METRICS (RESTORED EXACT LOGIC)
	// =========================================================
	n.RegisterHandler(MsgTypeMetrics, func(p *Peer, env *Envelope) {

		if !p.IsVerifiedMiner() {
			p.Penalize(5, 0)
			return
		}

		var m MetricsData
		if err := UnmarshalPayload(env.Payload, &m); err != nil {
			return
		}

		n.metricsMu.Lock()
		defer n.metricsMu.Unlock()

		n.GlobalMetrics = MetricsPayload{
			Timestamp:        m.Timestamp,
			MaxSupplyEXPLO:   m.MaxSupply,
			CirculatingEXPLO: m.Circulating,
			TotalHolders:     m.TotalHolders,
			MinersCount:      m.MinersCount,
			MinersRemaining:  m.MinersRemaining,
		}

		n.CachedMetrics = m
		n.cachedMetricsOnce = true

		log.Printf("[p2p] Metrics updated by %s — %.3f EXPLO",
			p.verifiedMinerID, m.Circulating)
	})

	// =========================================================
	// PEERS (UNCHANGED)
	// =========================================================
	n.RegisterHandler(MsgTypePeers, func(p *Peer, env *Envelope) {

		var pl PeersPayload
		if err := UnmarshalPayload(env.Payload, &pl); err != nil {
			return
		}

		for _, addr := range pl.Addrs {
			if addr != n.listenAddr {
				go n.Connect(addr)
			}
		}
	})

	n.RegisterHandler(MsgTypeRequestPeers, func(p *Peer, env *Envelope) {
		n.SendKnownPeers(p)
	})
}
