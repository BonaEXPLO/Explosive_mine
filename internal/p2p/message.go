// internal/p2p/message.go
package p2p

import (
        "crypto/ed25519"
        "errors"
        "time"
        "fmt"

        "github.com/fxamacker/cbor/v2"
)

// MessageType defines top-level message types used on the network.
type MessageType string

const (
    MsgTypeHandshake      MessageType = "HANDSHAKE"
    MsgTypePing           MessageType = "PING"
    MsgTypePong           MessageType = "PONG"
    MsgTypeInv            MessageType = "INV"
    MsgTypeGetData        MessageType = "GETDATA"
    MsgTypeTx             MessageType = "TX"
    MsgTypeBlock          MessageType = "BLOCK"
    MsgTypeAck            MessageType = "ACK"
    MsgTypeCustomData     MessageType = "CUSTOM_DATA"
    MsgTypeMetrics        MessageType = "METRICS"           // 🌐 network metrics broadcast                             
    MsgTypeRequestPeers   MessageType = "REQUEST_PEERS"     // 🔹 request list of peers from a node                     
    MsgTypePeers          MessageType = "PEERS"             // réponse contenant la liste des peers
    MsgTypeCustom         MessageType = "CUSTOM"            // messages personnalisés
    MsgTypeAnnounceMiner  MessageType = "ANNOUNCE_MINER"
    MsgTypeGetBlocksRange MessageType = "GETBLOCKSRANGE"    // Demande blocks de height from à to
    MsgTypeBlocksResponse MessageType = "BLOCKSRESPONSE"    // Réponse avec liste de blocks
)

// MinerInfo carries public miner identity information.
// Used in handshake and MsgTypeAnnounceMiner to prove possession of the consciousness fingerprint
// via the included PubKey and future Signature field (if needed at envelope level).
type MinerInfo struct {
    MinerID   string `cbor:"miner_id"`              // Wallet address (explo...)
    Timestamp int64  `cbor:"timestamp"`
    PubKey    []byte `cbor:"pubkey"`                // Mandatory: Ed25519 public key derived deterministically
    Signature []byte `cbor:"miner_sig,omitempty"`     // Optional: signature of "MINER|ID|word1|..." (proof of sacred words)
}

// Envelope is the wire-level envelope. Use CBOR for compactness and speed.
// Updated for full V3 integration:
// - Signature and PubKey are now mandatory for critical messages when RequireSignedMessages is enabled.
// - MinerInfo is used to broadcast the miner's public identity (ID + PubKey) without revealing sacred words.
// - Signature covers the canonical message (Version, Type, Payload, Timestamp) using the miner's deterministic Ed25519 key.
type Envelope struct {
    Version   uint16      `cbor:"v"`
    Type      MessageType `cbor:"t"`
    Payload   []byte      `cbor:"p,omitempty"` // Optional for control messages (ACK, PING, etc.)
    Timestamp int64       `cbor:"ts"`
    Signature []byte      `cbor:"sig,omitempty"` // Ed25519 signature of canonical data
    PubKey    []byte      `cbor:"pk,omitempty"`  // Ed25519 public key (derived from miner ID + 4 words)
    MinerInfo *MinerInfo  `cbor:"miner_info,omitempty"` // Optional: announces miner identity (used in handshake & announce)
}


// -------------------- PAYLOAD STRUCTS --------------------

// HandshakePayload exchanged at connection time.
type HandshakePayload struct {
        PeerID     string `cbor:"peer_id"`
        ListenAddr string `cbor:"listen_addr"`
        Version    string `cbor:"ver"`
        Network    string `cbor:"net"`
}

type PingPayload struct {
        Nonce int64 `cbor:"nonce"`
}

type PongPayload struct {
        Nonce int64 `cbor:"nonce"`
}

type InvPayload struct {
        ObjectIDs [][]byte `cbor:"ids"`
        Kind      string   `cbor:"kind"`
}

type GetDataPayload struct {
        ObjectIDs [][]byte `cbor:"ids"`
        Kind      string   `cbor:"kind"`
}

type TxPayload struct {
        Data []byte `cbor:"data"`
}

type BlockPayload struct {
        Data []byte `cbor:"data"`
}

type GetBlocksRangePayload struct {
    From uint64 `cbor:"from"`
    To   uint64 `cbor:"to"`
}

// ✅ New: MetricsPayload used for broadcasting Exploscan metrics to all peers.
type MetricsPayload struct {
        Timestamp       int64   `cbor:"timestamp"`
        MaxSupply       uint64  `cbor:"max_supply"`
        Circulating     float64 `cbor:"circulating"`
        TotalHolders    int     `cbor:"total_holders"`
        MinersCount     int     `cbor:"miners_count"`
        MinersRemaining int     `cbor:"miners_remaining"`
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

    // Allow reasonable clock skew (1 hour)
    now := time.Now().UnixMilli()
    if diff := now - e.Timestamp; diff > 3600000 || diff < -3600000 {
        return errors.New("timestamp skew too large")
    }

    // Payload requirements per message type
    switch e.Type {
    case MsgTypeHandshake, MsgTypeTx, MsgTypeBlock, MsgTypeInv, MsgTypeGetData, MsgTypeMetrics, MsgTypeAnnounceMiner:
        if len(e.Payload) == 0 && e.Type != MsgTypeAnnounceMiner { // AnnounceMiner may rely on MinerInfo
            return errors.New("payload required for this message type")
        }
    case MsgTypePing, MsgTypePong:
        if len(e.Payload) > 1024 {
            return errors.New("ping/pong payload too large")
        }
    case MsgTypeAck, MsgTypeRequestPeers, MsgTypePeers:
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
func VerifyEnvelopeSignature(e *Envelope) (bool, error) {
    if e == nil {
        return false, errors.New("nil envelope")
    }

    // No signature present → accepted for backward compatibility and non-critical messages
    if len(e.Signature) == 0 || len(e.PubKey) == 0 {
        return true, nil
    }

    // Canonical signed data: Version + Type + Payload + Timestamp
    // This excludes Signature, PubKey, and MinerInfo to prevent self-referencing issues
    canon := struct {
        V  uint16      `cbor:"v"`
        T  MessageType `cbor:"t"`
        P  []byte      `cbor:"p,omitempty"`
        Ts int64       `cbor:"ts"`
    }{
        V:  e.Version,
        T:  e.Type,
        P:  e.Payload,
        Ts: e.Timestamp,
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

// NewEnvelopeFromPayload quickly wraps a struct payload into an Envelope.
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

// ✅ New: helper to construct a ready-to-broadcast message (used by exploscan.go)
func NewMessage(mtype MessageType, payload interface{}) *Envelope {
        pb, _ := MarshalPayload(payload)
        return &Envelope{
                Version:   1,
                Type:      mtype,
                Payload:   pb,
                Timestamp: time.Now().UnixMilli(),
        }
}

