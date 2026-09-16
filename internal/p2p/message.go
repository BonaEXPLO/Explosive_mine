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
	CurrentProtocolVersion uint16 = 1
	MaxPayloadSize         int    = 5 * 1024 * 1024
	MaxTxPayloadSize       int    = 100 * 1024
	MaxBlockPayloadSize    int    = 2 * 1024 * 1024
	MaxClockSkew           int64  = 30 * 60 * 1000
)

// Inventory object kinds.
const (
	InvKindBlockHeader = "BLOCK_HEADER"
	InvKindBlockFull   = "BLOCK_FULL"
	InvKindTx          = "TX"
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

// -----------------------------------------------------------------------------
// MINER P2P PROOF
// -----------------------------------------------------------------------------

// minerP2PProofDomain provides domain separation for miner authentication.
//
// This signature is completely separate from the legacy on-chain miner
// signature. Sacred words are NEVER included in this proof.
const minerP2PProofDomain = "EXPLOSIVE-MINER-P2P-V1"

// MinerP2PProofPayload is the canonical public data signed by a miner
// when authenticating itself during a P2P handshake.
//
// SECURITY:
//   - Contains public identity information only.
//   - Does not contain sacred words.
//   - Does not contain passwords.
//   - Does not contain private keys.
type MinerP2PProofPayload struct {
	Domain        string `cbor:"domain"`
	Network       string `cbor:"network"`
	WalletAddress string `cbor:"wallet_address"`
	MinerID       string `cbor:"miner_id"`
	PeerID        string `cbor:"peer_id"`
	MinerPubKey   []byte `cbor:"miner_pubkey"`
	Timestamp     int64  `cbor:"timestamp"`
	Nonce         uint64 `cbor:"nonce"`
}

// BuildMinerP2PProof builds the canonical public message that must be signed
// by the miner private key.
//
// The proof binds the miner identity to:
//   - the EXPLOSIVE network,
//   - the wallet address,
//   - the MinerID,
//   - the P2P node identity,
//   - the miner public key,
//   - the handshake timestamp,
//   - the handshake nonce.
//
// This prevents reuse of a valid miner signature in another handshake context.
func BuildMinerP2PProof(
	network string,
	walletAddress string,
	minerID string,
	peerID string,
	minerPubKey []byte,
	timestamp int64,
	nonce uint64,
) ([]byte, error) {
	if network == "" {
		return nil, errors.New("miner proof network is empty")
	}

	if walletAddress == "" {
		return nil, errors.New("miner proof wallet address is empty")
	}

	if minerID == "" {
		return nil, errors.New("miner proof miner ID is empty")
	}

	if peerID == "" {
		return nil, errors.New("miner proof peer ID is empty")
	}

	if timestamp == 0 {
		return nil, errors.New("miner proof timestamp is missing")
	}

	if nonce == 0 {
		return nil, errors.New("miner proof nonce is missing")
	}

	if len(minerPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid miner public key size: got %d, want %d",
			len(minerPubKey),
			ed25519.PublicKeySize,
		)
	}

	payload := MinerP2PProofPayload{
		Domain:        minerP2PProofDomain,
		Network:       network,
		WalletAddress: walletAddress,
		MinerID:       minerID,
		PeerID:        peerID,
		MinerPubKey:   append([]byte(nil), minerPubKey...),
		Timestamp:     timestamp,
		Nonce:         nonce,
	}

	return cbor.Marshal(payload)
}

// VerifyMinerP2PProof verifies a miner's P2P authentication signature.
//
// The signature is verified exclusively with the public miner key supplied
// inside MinerInfo. No sacred words are required on the receiving node.
func VerifyMinerP2PProof(
	network string,
	walletAddress string,
	minerID string,
	peerID string,
	minerPubKey []byte,
	timestamp int64,
	nonce uint64,
	signature []byte,
) bool {
	if len(minerPubKey) != ed25519.PublicKeySize {
		return false
	}

	if len(signature) != ed25519.SignatureSize {
		return false
	}

	payload, err := BuildMinerP2PProof(
		network,
		walletAddress,
		minerID,
		peerID,
		minerPubKey,
		timestamp,
		nonce,
	)
	if err != nil {
		return false
	}

	return ed25519.Verify(
		ed25519.PublicKey(minerPubKey),
		payload,
		signature,
	)
}

// -----------------------------------------------------------------------------
// PAYLOADS
// -----------------------------------------------------------------------------

// MinerInfo carries the public cryptographic identity of a miner.
//
// PubKey is the MINER public key.
// Signature is the P2P miner proof.
//
// IMPORTANT:
// MinerInfo does NOT contain sacred words or any private information.
type MinerInfo struct {
	MinerID   string `cbor:"miner_id"`
	Timestamp int64  `cbor:"timestamp"`
	PubKey    []byte `cbor:"pubkey"`
	Signature []byte `cbor:"miner_sig,omitempty"`
}

// Envelope is the wire-level P2P envelope.
//
// Identity separation:
//
//	Envelope.PubKey
//	    = Wallet public key
//
//	Envelope.Signature
//	    = Wallet signature
//
//	Envelope.MinerInfo.PubKey
//	    = Miner public key
//
//	Envelope.MinerInfo.Signature
//	    = Miner P2P signature
//
// Wallet and miner keys are intentionally separate identities.
type Envelope struct {
	Version   uint16      `cbor:"v"`
	Type      MessageType `cbor:"t"`
	Payload   []byte      `cbor:"p,omitempty"`
	Timestamp int64       `cbor:"ts"`
	Nonce     uint64      `cbor:"nonce"`
	Signature []byte      `cbor:"sig,omitempty"`
	PubKey    []byte      `cbor:"pk,omitempty"`
	MinerInfo *MinerInfo  `cbor:"miner_info,omitempty"`
}

// -----------------------------------------------------------------------------
// PAYLOAD STRUCTS
// -----------------------------------------------------------------------------

// HandshakePayload identifies the public wallet identity and network role.
//
// SECURITY:
//   - WalletAddress is public.
//   - PeerID is public.
//   - ListenAddr is public.
//   - Version and Network are public protocol information.
//   - MinerID is public when the node is a miner.
//   - No wallet password, private key, BIP39 mnemonic or sacred words
//     are ever transmitted.
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
type InvPayload struct {
	Kind   string   `cbor:"kind"`
	Hashes [][]byte `cbor:"hashes"`
}

// GetDataPayload requests objects previously announced via INV.
type GetDataPayload struct {
	Kind   string   `cbor:"kind"`
	Hashes [][]byte `cbor:"hashes"`
}

type TxPayload struct {
	Data []byte `cbor:"data"`
}

// BlockPayload transports either a full block or a header-only block.
type BlockPayload struct {
	Kind string `cbor:"kind"`
	Data []byte `cbor:"data"`
}

type GetBlocksRangePayload struct {
	From uint64 `cbor:"from"`
	To   uint64 `cbor:"to"`
}

// MetricsPayload is used for broadcasting Exploscan metrics.
type MetricsPayload struct {
	Timestamp int64 `cbor:"timestamp"`

	MaxSupplyEXPLO   float64 `cbor:"max_supply_explo"`
	CirculatingEXPLO float64 `cbor:"circulating_explo"`

	TotalIMANI     float64 `cbor:"total_imani"`
	TotalLUMEN     float64 `cbor:"total_lumen"`
	ImaniFundEXPLO float64 `cbor:"imani_fund_explo"`

	TotalHolders    uint64 `cbor:"total_holders"`
	MinersCount     uint64 `cbor:"miners_count"`
	MinersRemaining uint64 `cbor:"miners_remaining"`
}

// -----------------------------------------------------------------------------
// ENCODING / DECODING
// -----------------------------------------------------------------------------

func EncodeEnvelope(e *Envelope) ([]byte, error) {
	if e == nil {
		return nil, errors.New("nil envelope")
	}

	return cbor.Marshal(e)
}

func DecodeEnvelope(b []byte) (*Envelope, error) {
	if len(b) == 0 {
		return nil, errors.New("empty envelope")
	}

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
	if len(b) == 0 {
		return errors.New("empty payload")
	}

	return cbor.Unmarshal(b, out)
}

// -----------------------------------------------------------------------------
// VALIDATION
// -----------------------------------------------------------------------------

// ValidateEnvelope performs structural and timing validation.
//
// MinerInfo is structurally validated here.
// Cryptographic miner authentication is performed separately through
// VerifyMinerP2PProof().
func ValidateEnvelope(e *Envelope) error {
	if e == nil {
		return errors.New("nil envelope")
	}

	if e.Version != CurrentProtocolVersion {
		return fmt.Errorf(
			"unsupported protocol version: %d (expected %d)",
			e.Version,
			CurrentProtocolVersion,
		)
	}

	if e.Timestamp == 0 {
		return errors.New("missing timestamp")
	}

	if e.Nonce == 0 {
		return errors.New("missing nonce")
	}

	now := time.Now().UnixMilli()

	if diff := now - e.Timestamp; diff > MaxClockSkew ||
		diff < -MaxClockSkew {
		return errors.New("timestamp skew too large")
	}

	// ------------------------------------------------------------------
	// TYPE-SPECIFIC PAYLOAD SIZE LIMITS
	// ------------------------------------------------------------------

	switch e.Type {
	case MsgTypeTx:
		if len(e.Payload) == 0 || len(e.Payload) > MaxTxPayloadSize {
			return fmt.Errorf(
				"invalid transaction payload size: %d bytes",
				len(e.Payload),
			)
		}

	case MsgTypeBlock:
		if len(e.Payload) == 0 || len(e.Payload) > MaxBlockPayloadSize {
			return fmt.Errorf(
				"invalid block payload size: %d bytes",
				len(e.Payload),
			)
		}

	default:
		if len(e.Payload) > MaxPayloadSize {
			return fmt.Errorf(
				"payload exceeds maximum size: %d > %d bytes",
				len(e.Payload),
				MaxPayloadSize,
			)
		}
	}

	// ------------------------------------------------------------------
	// PAYLOAD REQUIREMENTS PER MESSAGE TYPE
	// ------------------------------------------------------------------

	switch e.Type {
	case MsgTypeHandshake:
		if len(e.Payload) == 0 {
			return errors.New("handshake payload required")
		}

	case MsgTypeTx,
		MsgTypeBlock,
		MsgTypeInv,
		MsgTypeGetData,
		MsgTypeMetrics:

		if len(e.Payload) == 0 {
			return errors.New(
				"payload required for this message type",
			)
		}

	case MsgTypeAnnounceMiner:
		// MinerInfo may carry the public miner identity.

	case MsgTypePing,
		MsgTypePong:

		if len(e.Payload) > 1024 {
			return errors.New("ping/pong payload too large")
		}

	case MsgTypeRequestPeers,
		MsgTypePeers:
		// Payload optional.

	case MsgTypeGetBlocksRange:
		// GETBLOCKSRANGE is a valid blockchain synchronization request.
		// The payload is validated by the registered message handler.
		if len(e.Payload) == 0 {
			return errors.New("GETBLOCKSRANGE payload is empty")
		}

	case MsgTypeBlocksResponse:
		// BLOCKSRESPONSE is a valid blockchain synchronization response.
		// The payload is validated by the registered message handler.
		if len(e.Payload) == 0 {
			return errors.New("BLOCKSRESPONSE payload is empty")
		}

	default:
		return errors.New("unknown message type")
	}

	// ------------------------------------------------------------------
	// MINER INFO STRUCTURAL VALIDATION
	// ------------------------------------------------------------------

	if e.MinerInfo != nil {
		if e.MinerInfo.MinerID == "" {
			return errors.New("miner ID is missing in MinerInfo")
		}

		if e.MinerInfo.Timestamp == 0 {
			return errors.New("miner timestamp is missing")
		}

		if e.MinerInfo.Timestamp != e.Timestamp {
			return errors.New(
				"miner timestamp does not match envelope timestamp",
			)
		}

		if len(e.MinerInfo.PubKey) != ed25519.PublicKeySize {
			return errors.New(
				"invalid or missing miner public key in MinerInfo",
			)
		}

		if len(e.MinerInfo.Signature) != ed25519.SignatureSize {
			return errors.New(
				"invalid or missing miner signature in MinerInfo",
			)
		}
	}

	return nil
}

// -----------------------------------------------------------------------------
// WALLET / ENVELOPE SIGNATURE
// -----------------------------------------------------------------------------

// VerifyEnvelopeSignature verifies the wallet-level Ed25519 signature.
//
// Envelope.PubKey is the WALLET public key.
//
// MinerInfo.PubKey is intentionally NOT used here because wallet and miner
// identities are separate.
//
// If both Signature and PubKey are absent, this function returns true for
// compatibility with non-critical unsigned control messages.
func VerifyEnvelopeSignature(e *Envelope) (bool, error) {
	if e == nil {
		return false, fmt.Errorf("nil envelope")
	}

	if len(e.Signature) == 0 || len(e.PubKey) == 0 {
		return true, nil
	}

	if len(e.PubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid wallet public key length")
	}

	if len(e.Signature) != ed25519.SignatureSize {
		return false, errors.New("invalid wallet signature length")
	}

	// Canonical wallet-signed data.
	//
	// MinerInfo is intentionally excluded because the wallet signature
	// authenticates the wallet identity, while the miner signature
	// authenticates the miner identity.
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
		return false, fmt.Errorf(
			"failed to marshal canonical data for signature verification: %w",
			err,
		)
	}

	if !ed25519.Verify(
		ed25519.PublicKey(e.PubKey),
		msg,
		e.Signature,
	) {
		return false, nil
	}

	return true, nil
}

// -----------------------------------------------------------------------------
// NONCE
// -----------------------------------------------------------------------------

// generateSecureNonce produces a cryptographically secure random nonce.
func generateSecureNonce() (uint64, error) {
	var b [8]byte

	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}

	nonce := binary.LittleEndian.Uint64(b[:])

	// Zero is treated as invalid by ValidateEnvelope().
	// Extremely unlikely, but regenerate instead of returning zero.
	if nonce == 0 {
		return generateSecureNonce()
	}

	return nonce, nil
}

// -----------------------------------------------------------------------------
// ENVELOPE CONSTRUCTION
// -----------------------------------------------------------------------------

// NewEnvelopeFromPayload wraps a payload into an Envelope.
//
// The existing API is intentionally preserved:
//
//	NewEnvelopeFromPayload(version, messageType, payload)
func NewEnvelopeFromPayload(
	version uint16,
	mtype MessageType,
	payload interface{},
) (*Envelope, error) {

	pb, err := MarshalPayload(payload)
	if err != nil {
		return nil, err
	}

	switch mtype {
	case MsgTypeTx:
		if len(pb) > MaxTxPayloadSize {
			return nil, fmt.Errorf(
				"transaction payload exceeds maximum size: %d > %d bytes",
				len(pb),
				MaxTxPayloadSize,
			)
		}

	case MsgTypeBlock:
		if len(pb) > MaxBlockPayloadSize {
			return nil, fmt.Errorf(
				"block payload exceeds maximum size: %d > %d bytes",
				len(pb),
				MaxBlockPayloadSize,
			)
		}

	default:
		if len(pb) > MaxPayloadSize {
			return nil, fmt.Errorf(
				"payload exceeds maximum size: %d > %d bytes",
				len(pb),
				MaxPayloadSize,
			)
		}
	}

	nonce, err := generateSecureNonce()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate secure nonce: %w",
			err,
		)
	}

	return &Envelope{
		Version:   version,
		Type:      mtype,
		Payload:   pb,
		Timestamp: time.Now().UnixMilli(),
		Nonce:     nonce,
	}, nil
}

// NewMessage constructs a ready-to-broadcast message.
func NewMessage(
	mtype MessageType,
	payload interface{},
) *Envelope {

	pb, err := MarshalPayload(payload)
	if err != nil {
		return nil
	}

	nonce, err := generateSecureNonce()
	if err != nil {
		return nil
	}

	return &Envelope{
		Version:   CurrentProtocolVersion,
		Type:      mtype,
		Payload:   pb,
		Timestamp: time.Now().UnixMilli(),
		Nonce:     nonce,
	}
}

// -----------------------------------------------------------------------------
// HANDSHAKE
// -----------------------------------------------------------------------------

// DecodeHandshakePayload decodes a CBOR handshake payload.
func DecodeHandshakePayload(
	b []byte,
) (*HandshakePayload, error) {

	if len(b) == 0 {
		return nil, errors.New("empty handshake payload")
	}

	var hp HandshakePayload

	if err := cbor.Unmarshal(b, &hp); err != nil {
		return nil, err
	}

	return &hp, nil
}

// -----------------------------------------------------------------------------
// INVENTORY
// -----------------------------------------------------------------------------

// NewInvMessage constructs an INV message for hashes of a given kind.
func NewInvMessage(
	kind string,
	hashes [][]byte,
) (*Envelope, error) {

	if kind == "" {
		return nil, errors.New("inv kind is empty")
	}

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
func NewGetDataMessage(
	kind string,
	hashes [][]byte,
) (*Envelope, error) {

	if kind == "" {
		return nil, errors.New("getdata kind is empty")
	}

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

// DecodeInvPayload safely decodes and validates an INV payload.
func DecodeInvPayload(
	b []byte,
) (*InvPayload, error) {

	if len(b) == 0 {
		return nil, errors.New("empty inv payload")
	}

	var p InvPayload

	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, err
	}

	if p.Kind == "" || len(p.Hashes) == 0 {
		return nil, errors.New("invalid inv payload")
	}

	return &p, nil
}

// DecodeGetDataPayload safely decodes and validates a GETDATA payload.
func DecodeGetDataPayload(
	b []byte,
) (*GetDataPayload, error) {

	if len(b) == 0 {
		return nil, errors.New("empty getdata payload")
	}

	var p GetDataPayload

	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, err
	}

	if p.Kind == "" || len(p.Hashes) == 0 {
		return nil, errors.New("invalid getdata payload")
	}

	return &p, nil
}
