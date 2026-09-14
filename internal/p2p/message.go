// internal/p2p/message.go
package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Protocol constants
const (
	CurrentProtocolVersion uint16 = 1               // Current protocol version
	MaxPayloadSize         int    = 5 * 1024 * 1024 // 5 MB maximum payload (mobile-safe, sufficient for blocks)
	MaxTxPayloadSize       int    = 100 * 1024      // 100 KB maximum for transaction payloads
	MaxBlockPayloadSize    int    = 2 * 1024 * 1024 // 2 MB maximum for block payloads
	MaxClockSkew           int64  = 30 * 60 * 1000  // ±30 minutes clock skew tolerance
)

// Inventory object kinds (explicit & extensible)
const (
	InvKindBlockHeader = "BLOCK_HEADER" // header-only (always available, even after pruning)
	InvKindBlockFull   = "BLOCK_FULL"   // full block with transactions (may be pruned)
	InvKindTx          = "TX"           // future: transaction inventory
)

// MessageType defines top-level message types used on the network.
type MessageType string

const (
	MsgTypeHandshake MessageType = "HANDSHAKE"

	MsgTypePing           MessageType = "PING"
	MsgTypePong           MessageType = "PONG"
	MsgTypeInv            MessageType = "INV"
	MsgTypeGetData        MessageType = "GETDATA"
	MsgTypeTx             MessageType = "TX"
	MsgTypeBlock          MessageType = "BLOCK"
	MsgTypeCustomData     MessageType = "CUSTOM_DATA"
	MsgTypeMetrics        MessageType = "METRICS"
	MsgTypeRequestPeers   MessageType = "REQUEST_PEERS"
	MsgTypePeers          MessageType = "PEERS"
	MsgTypeCustom         MessageType = "CUSTOM"
	MsgTypeAnnounceMiner  MessageType = "ANNOUNCE_MINER"
	MsgTypeGetBlocksRange MessageType = "GETBLOCKSRANGE"
	MsgTypeBlocksResponse MessageType = "BLOCKSRESPONSE"
)

// MinerInfo carries public miner identity information.
// Used in handshake and MsgTypeAnnounceMiner to prove possession of the consciousness fingerprint
// via the included PubKey and future Signature field (if needed at envelope level).
type MinerInfo struct {
	MinerID   string `cbor:"miner_id"` // Wallet address (explo...)
	Timestamp int64  `cbor:"timestamp"`
	PubKey    []byte `cbor:"pubkey"`              // Mandatory: Ed25519 public key derived deterministically
	Signature []byte `cbor:"miner_sig,omitempty"` // Optional: signature of "MINER|ID|word1|..." (proof of sacred words)
}

// Envelope is the wire-level envelope. Use CBOR for compactness and speed.
// Updated for full V3 integration:
// - Signature and PubKey are now mandatory for critical messages when RequireSignedMessages is enabled.
// - MinerInfo is used to broadcast the miner's public identity (ID + PubKey) without revealing sacred words.
// - Signature covers the canonical message (Version, Type, Payload, Timestamp) using the miner's deterministic Ed25519 key.
// Enhanced with:
// - Mandatory cryptographically secure Nonce for replay protection
// - Stricter validation and size limits
type Envelope struct {
	Version   uint16      `cbor:"v"`
	Type      MessageType `cbor:"t"`
	Payload   []byte      `cbor:"p,omitempty"` // Optional for control messages (PING, etc.)
	Timestamp int64       `cbor:"ts"`
	Nonce     uint64      `cbor:"nonce"`                // Cryptographically secure nonce (anti-replay protection)
	Signature []byte      `cbor:"sig,omitempty"`        // Ed25519 signature of canonical data
	PubKey    []byte      `cbor:"pk,omitempty"`         // Ed25519 public key (derived from miner ID + 4 words)
	MinerInfo *MinerInfo  `cbor:"miner_info,omitempty"` // Optional: announces miner identity (used in handshake & announce)
}

// -------------------- PAYLOAD STRUCTS --------------------

// HandshakePayload is exchanged when a P2P connection is established.
//
// The handshake identifies the public wallet identity of the node and
// describes its network role.
//
// SECURITY:
//   - WalletAddress is public.
//   - PeerID is public.
//   - ListenAddr is public.
//   - Version and Network are public protocol information.
//   - MinerID is public when the node is a miner.
//   - No password, private key, BIP39 mnemonic or sacred mining words
//     are ever included in this payload.
type HandshakePayload struct {
	WalletAddress string `cbor:"wallet_address"`
	PeerID        string `cbor:"peer_id"`
	ListenAddr    string `cbor:"listen_addr"`
	Version       string `cbor:"ver"`
	Network       string `cbor:"net"`
	IsMiner       bool   `cbor:"is_miner"`
	MinerID       string `cbor:"miner_id,omitempty"`
}

type PingPayload struct {
	Nonce int64 `cbor:"nonce"`
}

type PongPayload struct {
	Nonce int64 `cbor:"nonce"`
}

// InvPayload announces the availability of objects by hash.
// Peers MUST respond with GETDATA if interested.
type InvPayload struct {
	Kind   string   `cbor:"kind"`   // BLOCK_HEADER | BLOCK_FULL | TX
	Hashes [][]byte `cbor:"hashes"` // canonical SHA3-256 hashes
}

// GetDataPayload requests objects previously announced via INV.
type GetDataPayload struct {
	Kind   string   `cbor:"kind"` // BLOCK_HEADER | BLOCK_FULL | TX
	Hashes [][]byte `cbor:"hashes"`
}

type TxPayload struct {
	Data []byte `cbor:"data"`
}

// BlockPayload transports either a full block or a header-only block.
// The receiver determines validity based on the Kind it requested.
type BlockPayload struct {
	Kind string `cbor:"kind"` // BLOCK_HEADER | BLOCK_FULL
	Data []byte `cbor:"data"` // CBOR-encoded Block (full or header-only)
}

type GetBlocksRangePayload struct {
	From uint64 `cbor:"from"`
	To   uint64 `cbor:"to"`
}

// MetricsPayload used for broadcasting Exploscan metrics to all peers.
// Fully aligned with canonical scan.MetricsData.
type MetricsPayload struct {
	Timestamp int64 `cbor:"timestamp"`

	MaxSupplyEXPLO   float64 `cbor:"max_supply_explo"`
	CirculatingEXPLO float64 `cbor:"circulating_explo"`

	TotalIMANI     float64 `cbor:"total_imani"`      // EXPLO donnés * 1000
	TotalLUMEN     float64 `cbor:"total_lumen"`      // √IMANI
	ImaniFundEXPLO float64 `cbor:"imani_fund_explo"` // EXPLO collectés pour le pool

	TotalHolders    uint64 `cbor:"total_holders"`
	MinersCount     uint64 `cbor:"miners_count"`
	MinersRemaining uint64 `cbor:"miners_remaining"`
}

// -------------------- ENCODING/DECODING --------------------

func EncodeEnvelope(e *Envelope) ([]byte, error) {
	return cbor.Marshal(e)
}

func DecodeEnvelope(b []byte) (*Envelope, error) {
	var e Envelope
	if err := cbor.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func MarshalPayload(v interface{}) ([]byte, error) {
	return cbor.Marshal(v)
}

func UnmarshalPayload(b []byte, out interface{}) error {
	return cbor.Unmarshal(b, out)
}

// -------------------- VALIDATION --------------------

// ValidateEnvelope performs structural and timing validation.
// Enhanced to enforce presence of PubKey and valid MinerInfo when present.
// Additional checks: protocol version, nonce presence, payload size limit, reduced clock skew.
func ValidateEnvelope(e *Envelope) error {
	if e == nil {
		return errors.New("nil envelope")
	}
	if e.Version != CurrentProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %d (expected %d)", e.Version, CurrentProtocolVersion)
	}
	if e.Timestamp == 0 {
		return errors.New("missing timestamp")
	}
	if e.Nonce == 0 {
		return errors.New("missing nonce")
	}

	// Allow reasonable clock skew (±30 minutes)
	now := time.Now().UnixMilli()
	if diff := now - e.Timestamp; diff > MaxClockSkew || diff < -MaxClockSkew {
		return errors.New("timestamp skew too large")
	}

	// Type-specific payload size limits
	switch e.Type {
	case MsgTypeTx:
		if len(e.Payload) == 0 || len(e.Payload) > MaxTxPayloadSize {
			return fmt.Errorf("invalid transaction payload size: %d bytes", len(e.Payload))
		}
	case MsgTypeBlock:
		if len(e.Payload) == 0 || len(e.Payload) > MaxBlockPayloadSize {
			return fmt.Errorf("invalid block payload size: %d bytes", len(e.Payload))
		}
	default:
		if len(e.Payload) > MaxPayloadSize {
			return fmt.Errorf("payload exceeds maximum size: %d > %d bytes", len(e.Payload), MaxPayloadSize)
		}
	}

	// Payload requirements per message type
	switch e.Type {

	case MsgTypeHandshake:
		if len(e.Payload) == 0 {
			return errors.New("handshake payload required")
		}

	case MsgTypeTx, MsgTypeBlock, MsgTypeInv,
		MsgTypeGetData, MsgTypeMetrics:
		if len(e.Payload) == 0 {
			return errors.New("payload required for this message type")
		}

	case MsgTypeAnnounceMiner:
		// May rely only on MinerInfo (payload optional)

	case MsgTypePing, MsgTypePong:
		if len(e.Payload) > 1024 {
			return errors.New("ping/pong payload too large")
		}

	case MsgTypeRequestPeers, MsgTypePeers:
		// Payload optional

	default:
		return errors.New("unknown message type")
	}

	// If MinerInfo is present, PubKey must be included and valid length
	if e.MinerInfo != nil {
		if len(e.MinerInfo.PubKey) != ed25519.PublicKeySize {
			return errors.New("invalid or missing miner public key in MinerInfo")
		}
	}

	return nil
}

// -------------------- SIGNATURE --------------------
// VerifyEnvelopeSignature verifies the Ed25519 signature over the canonical message data.
// Returns (true, nil) if no signature is present (backward compatible).
// Returns error only on malformed data; invalid signature returns (false, nil).
// Canonical data now includes Nonce for full replay protection.
func VerifyEnvelopeSignature(e *Envelope) (bool, error) {
	if e == nil {
		return false, fmt.Errorf("nil envelope")
	}

	// No signature present → accepted for backward compatibility and non-critical messages
	if len(e.Signature) == 0 || len(e.PubKey) == 0 {
		return true, nil
	}

	// Canonical signed data: Version + Type + Payload + Timestamp + Nonce
	// This excludes Signature, PubKey, and MinerInfo to prevent self-referencing issues
	canon := struct {
		V     uint16      `cbor:"v"`
		T     MessageType `cbor:"t"`
		P     []byte      `cbor:"p,omitempty"`
		Ts    int64       `cbor:"ts"`
		Nonce uint64      `cbor:"nonce"`
	}{
		V:     e.Version,
		T:     e.Type,
		P:     e.Payload,
		Ts:    e.Timestamp,
		Nonce: e.Nonce,
	}

	msg, err := cbor.Marshal(canon)
	if err != nil {
		return false, fmt.Errorf("failed to marshal canonical data for signature verification: %w", err)
	}

	if len(e.PubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key length")
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return false, errors.New("invalid signature length")
	}

	if !ed25519.Verify(ed25519.PublicKey(e.PubKey), msg, e.Signature) {
		return false, nil // Invalid signature, but no internal error
	}

	return true, nil
}

// -------------------- HELPERS --------------------

// generateSecureNonce produces a cryptographically secure random nonce.
func generateSecureNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// NewEnvelopeFromPayload quickly wraps a struct payload into an Envelope.
// Enhanced with secure nonce generation and payload size check.
func NewEnvelopeFromPayload(version uint16, mtype MessageType, payload interface{}) (*Envelope, error) {
	pb, err := MarshalPayload(payload)
	if err != nil {
		return nil, err
	}

	// Type-specific size enforcement
	switch mtype {
	case MsgTypeTx:
		if len(pb) > MaxTxPayloadSize {
			return nil, fmt.Errorf("transaction payload exceeds maximum size: %d > %d bytes", len(pb), MaxTxPayloadSize)
		}
	case MsgTypeBlock:
		if len(pb) > MaxBlockPayloadSize {
			return nil, fmt.Errorf("block payload exceeds maximum size: %d > %d bytes", len(pb), MaxBlockPayloadSize)
		}
	default:
		if len(pb) > MaxPayloadSize {
			return nil, fmt.Errorf("payload exceeds maximum size: %d > %d bytes", len(pb), MaxPayloadSize)
		}
	}

	nonce, err := generateSecureNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure nonce: %w", err)
	}

	return &Envelope{
		Version:   version,
		Type:      mtype,
		Payload:   pb,
		Timestamp: time.Now().UnixMilli(),
		Nonce:     nonce,
	}, nil
}

// ✅ New: helper to construct a ready-to-broadcast message (used by exploscan.go)
// Enhanced with secure nonce generation.
func NewMessage(mtype MessageType, payload interface{}) *Envelope {
	pb, _ := MarshalPayload(payload)
	nonce, _ := generateSecureNonce()
	return &Envelope{
		Version:   CurrentProtocolVersion,
		Type:      mtype,
		Payload:   pb,
		Timestamp: time.Now().UnixMilli(),
		Nonce:     nonce,
	}
}

// DecodeHandshakePayload decodes a CBOR handshake payload
func DecodeHandshakePayload(b []byte) (*HandshakePayload, error) {
	var hp HandshakePayload
	if err := cbor.Unmarshal(b, &hp); err != nil {
		return nil, err
	}
	return &hp, nil
}

// NewInvMessage constructs an INV message for hashes of a given kind.
func NewInvMessage(kind string, hashes [][]byte) (*Envelope, error) {
	if len(hashes) == 0 {
		return nil, errors.New("inv requires at least one hash")
	}

	payload := InvPayload{
		Kind:   kind,
		Hashes: hashes,
	}

	return NewEnvelopeFromPayload(
		CurrentProtocolVersion,
		MsgTypeInv,
		payload,
	)
}

// NewGetDataMessage constructs a GETDATA request.
func NewGetDataMessage(kind string, hashes [][]byte) (*Envelope, error) {
	if len(hashes) == 0 {
		return nil, errors.New("getdata requires at least one hash")
	}

	payload := GetDataPayload{
		Kind:   kind,
		Hashes: hashes,
	}

	return NewEnvelopeFromPayload(
		CurrentProtocolVersion,
		MsgTypeGetData,
		payload,
	)
}

// DecodeInvPayload safely decodes and validates an Inv payload.
func DecodeInvPayload(b []byte) (*InvPayload, error) {
	var p InvPayload
	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Kind == "" || len(p.Hashes) == 0 {
		return nil, errors.New("invalid inv payload")
	}
	return &p, nil
}

// DecodeGetDataPayload safely decodes and validates a GetData payload.
func DecodeGetDataPayload(b []byte) (*GetDataPayload, error) {
	var p GetDataPayload
	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Kind == "" || len(p.Hashes) == 0 {
		return nil, errors.New("invalid getdata payload")
	}
	return &p, nil
}
