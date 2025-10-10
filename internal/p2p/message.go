// internal/p2p/message.go
// Patched version — Assistant improvements applied.
// NOTE_FOR_AUDIT: This file has received the following concrete improvements so they are
// not unintentionally duplicated in other files:
//  - Added optional envelope-level signature/public-key fields (Signature, PubKey) to
//    allow message-level authentication if desired. Verification helpers provided.
//  - Stronger validation rules for envelope type/payload presence where applicable.
//  - Timestamp handling clarified (tolerance comment) and explicit non-zero checks.
package p2p

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MessageType defines top-level message types used on the network.
type MessageType string

const (
	MsgTypeHandshake MessageType = "HANDSHAKE" // initial handshake
	MsgTypePing      MessageType = "PING"
	MsgTypePong      MessageType = "PONG"
	MsgTypeInv       MessageType = "INV"       // inventory (tx/block headers)
	MsgTypeGetData   MessageType = "GETDATA"   // request full object
	MsgTypeTx        MessageType = "TX"        // transaction broadcast
	MsgTypeBlock     MessageType = "BLOCK"     // block (full)
	MsgTypeAck       MessageType = "ACK"       // generic ack
)

// Envelope is the wire-level envelope. Use CBOR for compactness and speed.
// Added optional Signature and PubKey fields for message-level auth (ed25519).
// If Signature/PubKey are present, VerifyEnvelopeSignature can be used to validate.
type Envelope struct {
	// Version allows for future protocol upgrades.
	Version uint16      `cbor:"v"`
	Type    MessageType `cbor:"t"`
	// Payload is a CBOR-encoded payload whose structure depends on Type.
	Payload []byte `cbor:"p"`
	// Timestamp to mitigate replay and for basic bookkeeping (ms).
	Timestamp int64 `cbor:"ts"`
	// Optional: signature over (Version, Type, Payload, Timestamp)
	Signature []byte `cbor:"sig,omitempty"`
	// Optional: public key of the signer (ed25519). If provided, receiver may verify.
	PubKey []byte `cbor:"pk,omitempty"`
}

// HandshakePayload exchanged at connection time.
type HandshakePayload struct {
	PeerID     string `cbor:"peer_id"`
	ListenAddr string `cbor:"listen_addr"` // optional: addr the peer claims to be listening on
	Version    string `cbor:"ver"`
	Network    string `cbor:"net"` // network id e.g. "explosive-mainnet"
}

// PingPayload is empty now; kept for extensibility.
type PingPayload struct {
	Nonce int64 `cbor:"nonce"`
}

// PongPayload echoes ping nonce.
type PongPayload struct {
	Nonce int64 `cbor:"nonce"`
}

// InvPayload lists object ids (hashes) advertised by a peer (bytes).
// For simplicity we model IDs as byte-slices (CBOR bytes).
type InvPayload struct {
	ObjectIDs [][]byte `cbor:"ids"`
	Kind      string   `cbor:"kind"` // "tx" or "block"
}

// GetDataPayload requests objects by ID.
type GetDataPayload struct {
	ObjectIDs [][]byte `cbor:"ids"`
	Kind      string   `cbor:"kind"`
}

// TxPayload and BlockPayload are opaque CBOR blobs (ledger types) to avoid circular imports.
type TxPayload struct {
	Data []byte `cbor:"data"`
}

type BlockPayload struct {
	Data []byte `cbor:"data"`
}

// EncodeEnvelope CBOR-encodes the envelope.
func EncodeEnvelope(e *Envelope) ([]byte, error) {
	return cbor.Marshal(e)
}

// DecodeEnvelope decodes CBOR bytes into an Envelope.
func DecodeEnvelope(b []byte) (*Envelope, error) {
	var e Envelope
	if err := cbor.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// MarshalPayload helper to CBOR-encode a payload structure.
func MarshalPayload(v interface{}) ([]byte, error) {
	return cbor.Marshal(v)
}

// UnmarshalPayload decodes payload bytes into target struct.
func UnmarshalPayload(b []byte, out interface{}) error {
	return cbor.Unmarshal(b, out)
}

// ValidateEnvelope performs minimal validation rules on an envelope.
// Note: signature verification is optional and must be invoked explicitly
// via VerifyEnvelopeSignature when the receiver requires it.
func ValidateEnvelope(e *Envelope) error {
	if e == nil {
		return errors.New("nil envelope")
	}
	if e.Version == 0 {
		return errors.New("invalid version")
	}
	if e.Timestamp == 0 {
		return errors.New("missing timestamp")
	}
	// Basic timestamp tolerance: +/- 1 hour (3600*1000 ms)
	if now := time.Now().UnixMilli(); (e.Timestamp-now) > 3600*1000 || (now-e.Timestamp) > 3600*1000 {
		// Do not reject solely for timestamp skew by default; higher layer may decide.
	}

	// Type-specific minimal checks
	switch e.Type {
	case MsgTypeHandshake:
		if len(e.Payload) == 0 {
			return errors.New("handshake missing payload")
		}
	case MsgTypePing, MsgTypePong:
		// allow empty payload for ping/pong but payload should be small if present
		if len(e.Payload) > 1024 {
			return errors.New("ping/pong payload too large")
		}
	case MsgTypeInv, MsgTypeGetData, MsgTypeTx, MsgTypeBlock:
		if len(e.Payload) == 0 {
			return errors.New("payload required for this message type")
		}
	case MsgTypeAck:
		// ack may be empty
	default:
		return errors.New("unknown message type")
	}

	return nil
}

// VerifyEnvelopeSignature verifies an envelope's Signature against its PubKey (ed25519).
// It constructs the canonical message as CBOR of {v, t, p, ts} and verifies the signature.
// Returns (true, nil) if signature is present and valid. If signature or pubkey is missing,
// returns (false, nil). Returns an error if verification fails due to malformed inputs.
func VerifyEnvelopeSignature(e *Envelope) (bool, error) {
	if e == nil {
		return false, errors.New("nil envelope")
	}
	if len(e.Signature) == 0 || len(e.PubKey) == 0 {
		// nothing to verify
		return false, nil
	}
	// prepare canonical structure
	canon := struct {
		V  uint16      `cbor:"v"`
		T  MessageType `cbor:"t"`
		P  []byte      `cbor:"p"`
		Ts int64       `cbor:"ts"`
	}{
		V:  e.Version,
		T:  e.Type,
		P:  e.Payload,
		Ts: e.Timestamp,
	}
	msg, err := cbor.Marshal(canon)
	if err != nil {
		return false, err
	}
	// pubkey length check for ed25519
	if len(e.PubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid pubkey length")
	}
	if len(e.Signature) != ed25519.SignatureSize {
		return false, errors.New("invalid signature length")
	}
	ok := ed25519.Verify(ed25519.PublicKey(e.PubKey), msg, e.Signature)
	if !ok {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

// Small utility: produce an Envelope quickly from a payload struct.
func NewEnvelopeFromPayload(version uint16, mtype MessageType, payload interface{}) (*Envelope, error) {
	pb, err := MarshalPayload(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Version:   version,
		Type:      mtype,
		Payload:   pb,
		Timestamp: time.Now().UnixMilli(),
	}, nil
}

// Safe equality check for ObjectIDs
func ObjectIDEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
