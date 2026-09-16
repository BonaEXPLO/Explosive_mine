// internal/p2p/node1.go
package p2p

import (
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"explosive/internal/ledger"
	"fmt"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────────────────────────────────────
// PORT DERIVATION – Deterministic P2P listen port for miners and investors
// ─────────────────────────────────────────────────────────────────────────────

const (
	MinerPortMin    = 4000 // Miners use high ports for censorship-resistant direct connectivity
	MinerPortMax    = 65535
	InvestorPortMin = 5000 // Investor/light nodes use a narrower range
	InvestorPortMax = 59999
)

// DerivePort is the single canonical deterministic port derivation routine.
// Uses full 8-byte entropy → virtually zero collision risk.
func DerivePort(seed string, minPort, maxPort int) (int, error) {
	if seed == "" {
		return 0, errors.New("seed cannot be empty")
	}
	hash := sha3.Sum256([]byte(seed))
	value := binary.BigEndian.Uint64(hash[:8])
	rangeSize := uint64(maxPort - minPort + 1)
	return minPort + int(value%rangeSize), nil
}

// DeriveMinerPort derives a stable listen port for a registered miner.
// Updated to use the exact same canonical identity format as V3 key derivation:
// "MINER|" + walletID + "|" + words joined by "|"
// This ensures perfect alignment with DeriveMinerKey() in miner.go.
func DeriveMinerPort(walletID string, words []string) (int, error) {
	if len(words) != 4 {
		return 0, errors.New("miner port derivation requires exactly 4 consciousness words")
	}

	// Canonical V3 identity string – MUST match the message signed in SignMinerIdentity()
	// Format: "MINER|walletID|word1|word2|word3|word4"
	// This guarantees deterministic alignment with Ed25519 key derivation
	seedParts := append([]string{"MINER", walletID}, words...)
	seed := strings.Join(seedParts, "|")

	return DerivePort(seed, MinerPortMin, MinerPortMax)
}

// DeriveInvestorPort derives a port for non-miner (investor/light) wallets.
func DeriveInvestorPort(walletAddress string) (int, error) {
	if walletAddress == "" {
		return InvestorPortMin + 1, nil
	}
	return DerivePort(walletAddress, InvestorPortMin, InvestorPortMax)
}

// DeriveListenAddr returns a full "0.0.0.0:port" listen address based on node type.
func DeriveListenAddr(walletID string, words []string, walletAddress string) (string, error) {
	var port int
	var err error

	if walletID != "" && len(words) == 4 {
		port, err = DeriveMinerPort(walletID, words)
	} else {
		port, err = DeriveInvestorPort(walletAddress)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0.0.0.0:%d", port), nil
}

// ListenAddr returns the effective P2P listen address of the node.
// Safe to call after Start().
func (n *Node) ListenAddr() string {
	if n == nil {
		return ""
	}
	return n.listenAddr
}

// ApplyDerivedListenAddrToNode sets the node's listen address if not already configured.
// Safe to call multiple times (idempotent).
func ApplyDerivedListenAddrToNode(n *Node, walletID string, words []string, walletAddress string) (string, error) {
	if n == nil {
		return "", errors.New("node cannot be nil")
	}
	if n.listenAddr != "" {
		return n.listenAddr, nil // Already configured
	}
	addr, err := DeriveListenAddr(walletID, words, walletAddress)
	if err != nil {
		return "", err
	}
	n.listenAddr = addr
	n.config.ListenAddr = addr
	return addr, nil
}

// FetchBlocks starts the single ledger synchronization engine.
//
// Block synchronization is asynchronous:
//
//	FetchBlocks()
//	     |
//	     v
//	SyncLedgerFromBestPeer()
//	     |
//	     v
//	GETBLOCKSRANGE
//	     |
//	     v
//	BLOCKSRESPONSE
//	     |
//	     v
//	   AddBlock()
//
// FetchBlocks does not send block requests directly and does not wait
// for blocks to arrive. The BLOCKSRESPONSE handler continues the
// synchronization session asynchronously.
func (n *Node) FetchBlocks() ([]*ledger.Block, error) {
	if n == nil {
		return nil, errors.New("node is nil")
	}

	if n.Ledger == nil {
		return nil, errors.New("ledger not initialized")
	}

	ctx := n.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	n.SyncLedgerFromBestPeer(ctx)

	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BROADCASTING – CBOR-based, sharded, high-performance
// ─────────────────────────────────────────────────────────────────────────────

// BroadcastEnvelope sends an envelope to all connected peers (sharded, lock-free read).
// Enhanced to be fully non-blocking (fire-and-forget) and skip banned peers for efficiency.
func (n *Node) BroadcastEnvelope(env *Envelope) {
	if env == nil {
		return
	}
	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		for _, p := range sh.peers {
			if p.IsConnected() && !p.IsBanned() {
				go p.SendEnvelope(env) // Fire-and-forget to prevent any blocking
			}
		}
		sh.mu.RUnlock()
	}
}

// BroadcastExcept sends to all peers except the specified one (used for relaying).
// Enhanced to be non-blocking and skip banned peers.
func (n *Node) BroadcastExcept(env *Envelope, except *Peer) {
	if env == nil || except == nil {
		return
	}
	for i := range n.peerShards {
		sh := &n.peerShards[i]
		sh.mu.RLock()
		for _, p := range sh.peers {
			if p != except && p.IsConnected() && !p.IsBanned() {
				go p.SendEnvelope(env) // Fire-and-forget
			}
		}
		sh.mu.RUnlock()
	}
}

// BroadcastTransaction serializes and broadcasts a ledger transaction using the canonical MsgTypeTx.
// Enhanced to use secure envelope creation with nonce and payload size check.
func (n *Node) BroadcastTransaction(tx *ledger.Transaction) error {
	env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MsgTypeTx, tx)
	if err != nil {
		return fmt.Errorf("failed to encode transaction: %w", err)
	}
	n.BroadcastEnvelope(env)
	return nil
}

// Implement scan.Broadcaster interface required by Exploscan
func (n *Node) BroadcastMessage(msgType string, payload interface{}) error {
	env, err := NewEnvelopeFromPayload(n.ProtocolVersion(), MessageType(msgType), payload)
	if err != nil {
		return fmt.Errorf("failed to create envelope: %w", err)
	}
	n.BroadcastEnvelope(env)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CUSTOM MESSAGE HANDLING – Multi-handler support (no overwrite)
// ─────────────────────────────────────────────────────────────────────────────

type CustomHandler func(peer *Peer, payload []byte)

var (
	customHandlers   []CustomHandler
	customHandlersMu sync.RWMutex
)

// RegisterCustomHandler adds a handler for MsgTypeCustom and MsgTypeCustomData.
// Multiple handlers are supported (useful for metrics, wallet events, etc.).
func RegisterCustomHandler(h CustomHandler) {
	customHandlersMu.Lock()
	customHandlers = append(customHandlers, h)
	customHandlersMu.Unlock()
}

// initCustomHandlers must be called once (usually from Node.registerDefaultHandlers).
// Routes both custom message types to all registered handlers.
func initCustomHandlers(n *Node) {
	n.RegisterHandler(MsgTypeCustom, func(p *Peer, env *Envelope) {
		customHandlersMu.RLock()
		defer customHandlersMu.RUnlock()
		for _, h := range customHandlers {
			h(p, env.Payload)
		}
	})
	n.RegisterHandler(MsgTypeCustomData, func(p *Peer, env *Envelope) {
		customHandlersMu.RLock()
		defer customHandlersMu.RUnlock()
		for _, h := range customHandlers {
			h(p, env.Payload)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// NODE STATUS HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// IsOnlineCount returns the number of connected peers across all shards.
// Optimized for mobile:
// - minimal locking
// - nil-safe
// - limited checks per shard for CPU efficiency
// - can be used to adapt Broadcast fanout dynamically
// IsOnlineCount returns the number of connected peers across all shards.

func (n *Node) IsOnlineCount(maxPerShard int) int {
	total := 0

	for i := range n.peerShards {
		sh := &n.peerShards[i]

		sh.mu.RLock()
		checked := 0
		for _, p := range sh.peers {
			if p.IsConnected() {
				total++
			}
			checked++
			if maxPerShard > 0 && checked >= maxPerShard {
				break
			}
		}
		sh.mu.RUnlock()
	}

	return total
}

// HasPeers returns true if the node knows at least one peer (connected or not).
func (n *Node) HasPeers() bool {
	n.PeersMutex.RLock()
	defer n.PeersMutex.RUnlock()
	return len(n.Peers) > 0
}
