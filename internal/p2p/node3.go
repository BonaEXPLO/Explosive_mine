// internal/p2p/node3.go
package p2p

import (
	"crypto/ed25519"
	"encoding/hex"
	"explosive/internal/address"
	"explosive/internal/ledger"
	"github.com/fxamacker/cbor/v2"
	"log"
	"strings"
	"time"
)

func (n *Node) registerDefaultHandlers() {

	// =========================================================
	// HANDSHAKE (CRITICAL)
	// =========================================================
	n.RegisterHandler(MsgTypeHandshake, func(p *Peer, env *Envelope) {

		p.handshakeOnce.Do(func() {

			// =========================================================
			// 1. DECODE HANDSHAKE
			// =========================================================

			var hs HandshakePayload

			if err := UnmarshalPayload(env.Payload, &hs); err != nil {
				log.Printf(
					"[p2p] Invalid handshake payload from %s: %v",
					p.addr,
					err,
				)
				p.Close()
				return
			}

			log.Printf(
				"[p2p] Handshake received from %s (id=%s, version=%s, listen=%s, wallet=%s, miner=%v)",
				p.addr,
				hs.PeerID,
				hs.Version,
				hs.ListenAddr,
				hs.WalletAddress,
				hs.IsMiner,
			)

			// =========================================================
			// 2. NETWORK CHECK
			// =========================================================

			if hs.Network != n.networkID {
				log.Printf(
					"[p2p] Handshake rejected from %s: wrong network '%s'",
					p.addr,
					hs.Network,
				)
				p.Close()
				return
			}

			// =========================================================
			// 3. VERSION CHECK
			// =========================================================

			if hs.Version != n.userAgent {
				log.Printf(
					"[p2p] Version mismatch %s remote=%s local=%s",
					p.addr,
					hs.Version,
					n.userAgent,
				)
			}

			// =========================================================
			// 4. WALLET IDENTITY CHECK
			// =========================================================

			if hs.WalletAddress == "" {
				log.Printf(
					"[p2p] Handshake rejected from %s: wallet address missing",
					p.addr,
				)
				p.Close()
				return
			}

			if !address.IsValidEXPLOAddress(hs.WalletAddress) {
				log.Printf(
					"[p2p] Handshake rejected from %s: invalid wallet address %s",
					p.addr,
					hs.WalletAddress,
				)
				p.Close()
				return
			}

			// =========================================================
			// 5. WALLET PUBLIC KEY
			// =========================================================

			if len(env.PubKey) != ed25519.PublicKeySize {
				log.Printf(
					"[p2p] Handshake rejected from %s: invalid wallet public key size: got %d, want %d",
					p.addr,
					len(env.PubKey),
					ed25519.PublicKeySize,
				)
				p.Close()
				return
			}

			// =========================================================
			// 6. WALLET ADDRESS <-> PUBLIC KEY BINDING
			// =========================================================

			expectedAddress := address.FromEd25519PublicKey(
				ed25519.PublicKey(env.PubKey),
			)

			if hs.WalletAddress != expectedAddress {
				log.Printf(
					"[p2p] 🚫 Wallet identity mismatch from %s: announced=%s derived=%s",
					p.addr,
					hs.WalletAddress,
					expectedAddress,
				)

				p.Penalize(20, time.Hour)
				p.Close()
				return
			}

			log.Printf(
				"[p2p] ✅ Wallet identity verified: %s",
				hs.WalletAddress,
			)

			// =========================================================
			// 7. WALLET HANDSHAKE SIGNATURE
			// =========================================================

			if len(env.Signature) != ed25519.SignatureSize {
				log.Printf(
					"[p2p] Handshake rejected from %s: missing or invalid wallet signature",
					p.addr,
				)

				p.Penalize(20, time.Hour)
				p.Close()
				return
			}

			ok, err := VerifyEnvelopeSignature(env)
			if err != nil {
				log.Printf(
					"[p2p] Handshake wallet signature verification error from %s: %v",
					p.addr,
					err,
				)

				p.Penalize(20, time.Hour)
				p.Close()
				return
			}

			if !ok {
				log.Printf(
					"[p2p] 🚫 Invalid wallet handshake signature from %s",
					p.addr,
				)

				p.Penalize(20, time.Hour)
				p.Close()
				return
			}

			log.Printf(
				"[p2p] ✅ Wallet handshake signature verified: %s",
				hs.WalletAddress,
			)

			// =========================================================
			// 8. PEER ID CHECK
			// =========================================================

			if hs.PeerID == "" {
				log.Printf(
					"[p2p] Handshake rejected from %s: peer ID missing",
					p.addr,
				)

				p.Close()
				return
			}

			p.mu.Lock()
			p.id = PeerID(hs.PeerID)
			p.LatestHeight = hs.ChainHeight
			p.mu.Unlock()

			log.Printf(
				"[p2p] 📏 Remote chain height from %s: %d",
				hs.PeerID,
				hs.ChainHeight,
			)

			// =========================================================
			// 9. MINER / INVESTOR ROLE CONSISTENCY
			// =========================================================

			if hs.IsMiner {

				// -----------------------------------------------------
				// 9.1 MinerID is mandatory
				// -----------------------------------------------------

				if hs.MinerID == "" {
					log.Printf(
						"[p2p] Handshake rejected from %s: miner flag set but MinerID is empty",
						p.addr,
					)

					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.2 MinerID must equal WalletAddress
				// -----------------------------------------------------

				if !strings.EqualFold(hs.MinerID, hs.WalletAddress) {
					log.Printf(
						"[p2p] Handshake rejected from %s: MinerID %s does not match wallet %s",
						p.addr,
						hs.MinerID,
						hs.WalletAddress,
					)

					p.Penalize(20, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.3 MinerID must be a valid EXPLO address
				// -----------------------------------------------------

				if !address.IsValidEXPLOAddress(hs.MinerID) {
					log.Printf(
						"[p2p] Handshake rejected from %s: invalid MinerID %s",
						p.addr,
						hs.MinerID,
					)

					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.4 MinerInfo is mandatory for miners
				// -----------------------------------------------------

				if env.MinerInfo == nil {
					log.Printf(
						"[p2p] Handshake rejected from %s: miner handshake missing MinerInfo",
						p.addr,
					)

					p.Penalize(30, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.5 MinerInfo.MinerID must match MinerID
				// -----------------------------------------------------

				if !strings.EqualFold(
					env.MinerInfo.MinerID,
					hs.MinerID,
				) {
					log.Printf(
						"[p2p] Handshake rejected from %s: MinerInfo MinerID mismatch: info=%s handshake=%s",
						p.addr,
						env.MinerInfo.MinerID,
						hs.MinerID,
					)

					p.Penalize(30, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.6 MinerInfo timestamp must match envelope
				// -----------------------------------------------------

				if env.MinerInfo.Timestamp != env.Timestamp {
					log.Printf(
						"[p2p] Handshake rejected from %s: MinerInfo timestamp mismatch",
						p.addr,
					)

					p.Penalize(20, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.7 Miner public key must be valid
				// -----------------------------------------------------

				if len(env.MinerInfo.PubKey) != ed25519.PublicKeySize {
					log.Printf(
						"[p2p] Handshake rejected from %s: invalid miner public key size: got %d, want %d",
						p.addr,
						len(env.MinerInfo.PubKey),
						ed25519.PublicKeySize,
					)

					p.Penalize(30, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.8 Miner P2P signature must be valid
				// -----------------------------------------------------

				if len(env.MinerInfo.Signature) != ed25519.SignatureSize {
					log.Printf(
						"[p2p] Handshake rejected from %s: invalid miner P2P signature size: got %d, want %d",
						p.addr,
						len(env.MinerInfo.Signature),
						ed25519.SignatureSize,
					)

					p.Penalize(30, time.Hour)
					p.Close()
					return
				}

				// -----------------------------------------------------
				// 9.9 Verify Miner P2P proof
				// -----------------------------------------------------

				minerProofOK := VerifyMinerP2PProof(
					n.networkID,
					hs.WalletAddress,
					hs.MinerID,
					hs.PeerID,
					env.MinerInfo.PubKey,
					env.Timestamp,
					env.Nonce,
					env.MinerInfo.Signature,
				)

				if !minerProofOK {
					log.Printf(
						"[p2p] 🚫 Invalid Miner P2P proof from %s: miner=%s",
						p.addr,
						hs.MinerID,
					)

					p.Penalize(40, 4*time.Hour)
					p.Close()
					return
				}

				log.Printf(
					"[p2p] ✅ Miner P2P proof verified: miner=%s",
					hs.MinerID,
				)

				// -----------------------------------------------------
				// 9.10 On-chain miner identity verification
				// -----------------------------------------------------

				if !n.verifyPeerOnChain(PeerID(hs.MinerID)) {
					log.Printf(
						"[p2p] 🚫 miner identity not found in ledger: %s",
						hs.MinerID,
					)

					p.Close()
					return
				}

				log.Printf(
					"[p2p] ✅ on-chain miner identity accepted: %s",
					hs.MinerID,
				)

				// -----------------------------------------------------
				// 9.11 Store VERIFIED MINER identity
				// -----------------------------------------------------
				//
				// verifiedPubKey is the MINER public key here.
				// It is intentionally different from env.PubKey,
				// which is the WALLET public key.
				// -----------------------------------------------------

				p.mu.Lock()

				p.verifiedMinerID = hs.MinerID
				p.verifiedPubKey = append(
					[]byte(nil),
					env.MinerInfo.PubKey...,
				)
				p.verifiedMiner = true

				p.mu.Unlock()

				log.Printf(
					"[p2p] ✅ Verified conscious miner: %s",
					hs.MinerID,
				)

			} else {

				// =====================================================
				// OBSERVER / INVESTOR
				// =====================================================

				if hs.MinerID != "" {
					log.Printf(
						"[p2p] Handshake rejected from %s: observer cannot advertise MinerID %s",
						p.addr,
						hs.MinerID,
					)

					p.Close()
					return
				}

				// An observer must not send MinerInfo at all.
				if env.MinerInfo != nil {
					log.Printf(
						"[p2p] Handshake rejected from %s: observer cannot contain MinerInfo",
						p.addr,
					)

					p.Penalize(30, time.Hour)
					p.Close()
					return
				}

				log.Printf(
					"[p2p] 👁️ Verified observer/investor wallet: %s",
					hs.WalletAddress,
				)
			}

			// =========================================================
			// 10. COMPLETE HANDSHAKE
			// =========================================================

			role := "observer/investor"

			if p.IsVerifiedMiner() {
				role = "verified conscious miner"
			}

			p.mu.Lock()

			alreadyDone := p.handshakeDone
			p.handshakeDone = true

			peerID := p.id

			p.mu.Unlock()

			if !alreadyDone {

				// -----------------------------------------------------
				// Register the peer only after complete cryptographic
				// validation.
				// -----------------------------------------------------

				n.addPeer(p)

				// -----------------------------------------------------
				// Release bootstrap waiters.
				// -----------------------------------------------------

				select {
				case <-p.handshakeCh:
					// Already closed.
				default:
					close(p.handshakeCh)
				}

				log.Printf(
					"[p2p] ✅ BIDIRECTIONAL HANDSHAKE COMPLETE → %s (%s, wallet=%s)",
					peerID,
					role,
					hs.WalletAddress,
				)

				// -----------------------------------------------------
				// 11. IMMEDIATE LEDGER SYNCHRONIZATION TRIGGER
				// -----------------------------------------------------
				//
				// The remote chain height was authenticated above and
				// stored in p.LatestHeight.
				//
				// If this node is behind the remote peer,
				// SyncLedgerFromBestPeer() will immediately select this
				// peer and request the missing block range.
				//
				// Synchronization is deliberately asynchronous so the
				// handshake/message processing loop is never blocked.
				// -----------------------------------------------------

				go func() {
					if n == nil || n.Ledger == nil {
						return
					}

					log.Printf(
						"[p2p] 🔄 Peer authenticated — checking ledger synchronization with %s",
						peerID,
					)

					n.SyncLedgerFromBestPeer(n.ctx)
				}()
			}
		})
	})

	// =========================================================
	// PING / PONG
	// =========================================================
	//
	// PING/PONG measures the liveness of the CURRENT network session.
	//
	// IMPORTANT:
	//   - No reputation penalty is applied for a missing PONG.
	//   - Offline time is not malicious behavior.
	//   - A PONG must match a PING nonce issued by this session.
	//   - A valid PONG updates only session liveness metadata.
	// =========================================================

	n.RegisterHandler(MsgTypePing, func(p *Peer, env *Envelope) {
		if p == nil {
			return
		}

		var ping PingPayload

		if err := UnmarshalPayload(env.Payload, &ping); err != nil {
			log.Printf(
				"[p2p] ⚠️ invalid PING payload from %s: %v",
				p.Addr(),
				err,
			)
			return
		}

		if ping.Nonce == 0 {
			log.Printf(
				"[p2p] ⚠️ PING with invalid nonce from %s",
				p.Addr(),
			)
			return
		}

		// Always answer a valid PING with the same nonce.
		pong := PongPayload{
			Nonce: ping.Nonce,
		}

		reply, err := NewEnvelopeFromPayload(
			n.protocolVersion,
			MsgTypePong,
			pong,
		)

		if err != nil {
			log.Printf(
				"[p2p] ⚠️ failed to create PONG for %s: %v",
				p.Addr(),
				err,
			)
			return
		}

		if err := p.SendEnvelope(reply); err != nil {
			log.Printf(
				"[p2p] ⚠️ failed to send PONG to %s: %v",
				p.Addr(),
				err,
			)
			return
		}

		// Receiving a valid PING proves that the current network
		// session is alive.
		p.mu.Lock()
		p.lastSeen = time.Now()
		p.mu.Unlock()
	})

	n.RegisterHandler(MsgTypePong, func(p *Peer, env *Envelope) {
		if p == nil {
			return
		}

		var pong PongPayload

		if err := UnmarshalPayload(env.Payload, &pong); err != nil {
			log.Printf(
				"[p2p] ⚠️ invalid PONG payload from %s: %v",
				p.Addr(),
				err,
			)
			return
		}

		if pong.Nonce == 0 {
			log.Printf(
				"[p2p] ⚠️ PONG with invalid nonce from %s",
				p.Addr(),
			)
			return
		}

		rtt, valid := p.receivePong(pong.Nonce)

		if !valid {
			// Do NOT penalize the peer.
			//
			// An unmatched PONG can come from an old session, a delayed
			// packet, or a stale network path. It is not enough to classify
			// the permanent peer identity as malicious.
			log.Printf(
				"[p2p] ⚠️ unmatched PONG nonce from %s: %d",
				p.Addr(),
				pong.Nonce,
			)
			return
		}

		// A valid PONG proves that the current session is alive.
		p.mu.Lock()
		p.lastSeen = time.Now()
		p.mu.Unlock()

		log.Printf(
			"[p2p] 💓 PONG received from %s (RTT=%s)",
			p.Addr(),
			rtt,
		)
	})

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
	// BLOCK RANGE REQUEST
	// =========================================================
	//
	// GETBLOCKSRANGE requests a bounded range of blockchain blocks.
	//
	// The response is always asynchronous. The requesting peer receives
	// a BLOCKSRESPONSE through the normal P2P message pipeline.
	//
	// A maximum of 50 blocks is allowed per request in order to keep
	// memory, bandwidth and mobile CPU usage bounded.
	n.RegisterHandler(MsgTypeGetBlocksRange, func(p *Peer, env *Envelope) {

		if n == nil || n.Ledger == nil {
			log.Printf(
				"[p2p] ⚠️ Cannot serve GETBLOCKSRANGE: ledger not initialized",
			)
			return
		}

		if p == nil {
			log.Printf(
				"[p2p] ⚠️ GETBLOCKSRANGE received from nil peer",
			)
			return
		}

		// ---------------------------------------------------------
		// 1. Decode request
		// ---------------------------------------------------------

		var req GetBlocksRangePayload

		if err := UnmarshalPayload(env.Payload, &req); err != nil {
			log.Printf(
				"[p2p] ❌ Invalid GETBLOCKSRANGE from %s: %v",
				p.addr,
				err,
			)
			p.Penalize(5, 0)
			return
		}

		// ---------------------------------------------------------
		// 2. Validate requested range
		// ---------------------------------------------------------

		if req.From > req.To {
			log.Printf(
				"[p2p] 🚫 Invalid GETBLOCKSRANGE from %s: from=%d to=%d",
				p.addr,
				req.From,
				req.To,
			)
			p.Penalize(3, 0)
			return
		}

		// Never serve more than 50 blocks in one response.
		if req.To-req.From+1 > 50 {
			req.To = req.From + 49
		}

		// ---------------------------------------------------------
		// 3. Read requested blocks from the authoritative ledger
		// ---------------------------------------------------------

		blocks, err := n.Ledger.GetBlocksRange(
			req.From,
			req.To,
		)

		if err != nil {
			log.Printf(
				"[p2p] ⚠️ Failed to read blocks %d-%d for %s: %v",
				req.From,
				req.To,
				p.addr,
				err,
			)
			return
		}

		// ---------------------------------------------------------
		// 4. Return an explicit empty response when the requested
		// range is not available.
		//
		// The requester can then terminate the current sync session
		// instead of waiting forever.
		// ---------------------------------------------------------

		if len(blocks) == 0 {

			log.Printf(
				"[p2p] 📭 No blocks available for requested range %d-%d from %s",
				req.From,
				req.To,
				p.addr,
			)

			payload := struct {
				Blocks []*ledger.Block `cbor:"blocks"`
			}{
				Blocks: []*ledger.Block{},
			}

			resp, err := NewEnvelopeFromPayload(
				n.ProtocolVersion(),
				MsgTypeBlocksResponse,
				payload,
			)

			if err != nil {
				log.Printf(
					"[p2p] ⚠️ Failed to create empty BLOCKSRESPONSE for %s: %v",
					p.addr,
					err,
				)
				return
			}

			if err := p.SendEnvelope(resp); err != nil {
				log.Printf(
					"[p2p] ⚠️ Failed to send empty BLOCKSRESPONSE to %s: %v",
					p.addr,
					err,
				)
			}

			return
		}

		// ---------------------------------------------------------
		// 5. Build BLOCKSRESPONSE
		// ---------------------------------------------------------

		payload := struct {
			Blocks []*ledger.Block `cbor:"blocks"`
		}{
			Blocks: blocks,
		}

		resp, err := NewEnvelopeFromPayload(
			n.ProtocolVersion(),
			MsgTypeBlocksResponse,
			payload,
		)

		if err != nil {
			log.Printf(
				"[p2p] ⚠️ Failed to create BLOCKSRESPONSE for %s: %v",
				p.addr,
				err,
			)
			return
		}

		// ---------------------------------------------------------
		// 6. Send response asynchronously through the peer session
		// ---------------------------------------------------------

		if err := p.SendEnvelope(resp); err != nil {
			log.Printf(
				"[p2p] ⚠️ Failed to send BLOCKSRESPONSE to %s: %v",
				p.addr,
				err,
			)
			return
		}

		log.Printf(
			"[p2p] 📤 BLOCKSRESPONSE sent to %s: blocks=%d range=%d-%d",
			p.addr,
			len(blocks),
			req.From,
			req.To,
		)
	})

	// =========================================================
	// BLOCK SYNCHRONIZATION RESPONSE
	// =========================================================
	//
	// BLOCKSRESPONSE is the asynchronous continuation of a
	// GETBLOCKSRANGE synchronization session.
	//
	// Only the peer selected by SyncLedgerFromBestPeer may advance
	// the active synchronization session. Blocks are always applied
	// strictly in sequential height order and are cryptographically
	// verified before entering the local ledger.
	n.RegisterHandler(MsgTypeBlocksResponse, func(p *Peer, env *Envelope) {

		if n == nil || n.Ledger == nil {
			log.Printf(
				"[p2p] ⚠️ Cannot process BLOCKSRESPONSE: ledger not initialized",
			)
			return
		}

		if p == nil {
			log.Printf(
				"[p2p] ⚠️ BLOCKSRESPONSE received from nil peer",
			)
			return
		}

		// ---------------------------------------------------------
		// 1. Decode response
		// ---------------------------------------------------------

		var resp struct {
			Blocks []*ledger.Block `cbor:"blocks"`
		}

		if err := UnmarshalPayload(env.Payload, &resp); err != nil {
			log.Printf(
				"[p2p] ❌ Invalid BLOCKSRESPONSE from %s: %v",
				p.addr,
				err,
			)
			p.Penalize(5, 0)
			return
		}

		// ---------------------------------------------------------
		// 2. Verify active synchronization session
		// ---------------------------------------------------------

		n.syncMu.Lock()

		syncRunning := n.syncRunning
		syncPeer := n.syncPeer
		syncTarget := n.syncTarget

		n.syncMu.Unlock()

		if !syncRunning {
			log.Printf(
				"[p2p] ⚠️ Ignoring unsolicited BLOCKSRESPONSE from %s",
				p.addr,
			)
			return
		}

		if syncPeer == nil {
			log.Printf(
				"[p2p] ⚠️ Ignoring BLOCKSRESPONSE from %s: no active sync peer",
				p.addr,
			)
			return
		}

		if syncPeer != p {
			log.Printf(
				"[p2p] ⚠️ Ignoring BLOCKSRESPONSE from %s: response is not from active sync peer %s",
				p.addr,
				syncPeer.Addr(),
			)
			return
		}

		// ---------------------------------------------------------
		// 3. Empty response
		// ---------------------------------------------------------

		if len(resp.Blocks) == 0 {

			log.Printf(
				"[p2p] 📭 Empty BLOCKSRESPONSE from active sync peer %s",
				p.addr,
			)

			n.syncMu.Lock()

			if n.syncPeer == p {
				n.syncRunning = false
				n.syncPeer = nil
				n.syncTarget = 0
			}

			n.syncMu.Unlock()

			log.Printf(
				"[p2p] ⚠️ Synchronization session ended: peer %s returned no blocks",
				p.addr,
			)

			return
		}

		// ---------------------------------------------------------
		// 4. Apply blocks strictly in sequential order
		// ---------------------------------------------------------

		for _, blk := range resp.Blocks {

			if blk == nil {
				log.Printf(
					"[p2p] 🚫 Nil block received from %s",
					p.addr,
				)

				p.Penalize(5, 0)
				return
			}

			localHeight := n.Ledger.GetLatestBlockHeight()

			// Already synchronized.
			if blk.Header.Height <= localHeight {
				continue
			}

			// A synchronization response must contain exactly the
			// next expected block. Never accept height gaps.
			if blk.Header.Height != localHeight+1 {

				log.Printf(
					"[p2p] 🚫 Block height gap from %s: got=%d expected=%d",
					p.addr,
					blk.Header.Height,
					localHeight+1,
				)

				p.Penalize(15, time.Hour)

				n.syncMu.Lock()

				if n.syncPeer == p {
					n.syncRunning = false
					n.syncPeer = nil
					n.syncTarget = 0
				}

				n.syncMu.Unlock()

				return
			}

			// -----------------------------------------------------
			// Verify block cryptographic signature
			// -----------------------------------------------------

			ok, err := blk.VerifySignature()

			if err != nil || !ok {

				log.Printf(
					"[p2p] 🚫 Invalid block signature from %s at height %d: %v",
					p.addr,
					blk.Header.Height,
					err,
				)

				p.Penalize(15, time.Hour)

				n.syncMu.Lock()

				if n.syncPeer == p {
					n.syncRunning = false
					n.syncPeer = nil
					n.syncTarget = 0
				}

				n.syncMu.Unlock()

				return
			}

			// -----------------------------------------------------
			// Apply through the authoritative ledger validation layer
			// -----------------------------------------------------

			if err := n.Ledger.AddBlock(blk); err != nil {

				log.Printf(
					"[p2p] 🚫 Failed to apply synced block %d from %s: %v",
					blk.Header.Height,
					p.addr,
					err,
				)

				n.syncMu.Lock()

				if n.syncPeer == p {
					n.syncRunning = false
					n.syncPeer = nil
					n.syncTarget = 0
				}

				n.syncMu.Unlock()

				return
			}

			log.Printf(
				"[p2p] ✅ Synced block #%d from %s",
				blk.Header.Height,
				p.addr,
			)
		}

		// ---------------------------------------------------------
		// 5. Check synchronization progress
		// ---------------------------------------------------------

		currentHeight := n.Ledger.GetLatestBlockHeight()

		if currentHeight >= syncTarget {

			n.syncMu.Lock()

			if n.syncPeer == p {
				n.syncRunning = false
				n.syncPeer = nil
				n.syncTarget = 0
			}

			n.syncMu.Unlock()

			log.Printf(
				"[p2p] 🎉 Ledger synchronized with %s at height %d",
				p.addr,
				currentHeight,
			)

			return
		}

		// ---------------------------------------------------------
		// 6. Request next synchronization segment
		// ---------------------------------------------------------

		from := currentHeight + 1
		to := from + 49

		if to > syncTarget {
			to = syncTarget
		}

		log.Printf(
			"[p2p] 📥 Requesting next sync segment %d-%d from %s",
			from,
			to,
			p.addr,
		)

		if err := p.requestBlocksRange(from, to); err != nil {

			log.Printf(
				"[p2p] ⚠️ Failed to request next sync segment from %s: %v",
				p.addr,
				err,
			)

			n.syncMu.Lock()

			if n.syncPeer == p {
				n.syncRunning = false
				n.syncPeer = nil
				n.syncTarget = 0
			}

			n.syncMu.Unlock()

			return
		}

		log.Printf(
			"[p2p] 📤 Next sync request sent: blocks %d-%d from %s",
			from,
			to,
			p.addr,
		)
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
	// METRICS
	// =========================================================
	//
	// METRICS is available to every authenticated P2P participant.
	//
	// A peer does NOT need to be a miner to provide network metrics.
	// Wallet authentication and the completed P2P handshake establish
	// the peer's network identity.
	//
	// Miner status is an additional role, not a requirement for metrics.

	n.RegisterHandler(MsgTypeMetrics, func(p *Peer, env *Envelope) {

		if p == nil {
			log.Printf("[p2p] ⚠️ Ignoring METRICS from nil peer")
			return
		}

		// =========================================================
		// 1. REQUIRE COMPLETED HANDSHAKE
		// =========================================================
		//
		// Both miners and observers/investors are valid P2P peers.
		// The only requirement here is that the peer has completed
		// the authenticated handshake.

		p.mu.RLock()
		handshakeDone := p.handshakeDone
		peerID := p.id
		verifiedMinerID := p.verifiedMinerID
		p.mu.RUnlock()

		if !handshakeDone {
			log.Printf(
				"[p2p] 🚫 Ignoring METRICS from unauthenticated peer %s",
				p.addr,
			)
			p.Penalize(5, 0)
			return
		}

		// =========================================================
		// 2. DECODE METRICS
		// =========================================================

		var m MetricsData

		if err := UnmarshalPayload(env.Payload, &m); err != nil {
			log.Printf(
				"[p2p] ⚠️ Invalid METRICS payload from %s: %v",
				p.addr,
				err,
			)
			p.Penalize(2, 0)
			return
		}

		// =========================================================
		// 3. UPDATE GLOBAL METRICS
		// =========================================================

		n.metricsMu.Lock()

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

		n.metricsMu.Unlock()

		// =========================================================
		// 4. LOG ROLE
		// =========================================================

		if verifiedMinerID != "" {
			log.Printf(
				"[p2p] 📊 Metrics updated by authenticated miner %s (peer=%s) — %.3f EXPLO",
				verifiedMinerID,
				peerID,
				m.Circulating,
			)
			return
		}

		log.Printf(
			"[p2p] 📊 Metrics updated by authenticated observer/investor %s — %.3f EXPLO",
			peerID,
			m.Circulating,
		)
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
