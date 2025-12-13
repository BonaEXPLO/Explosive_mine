// internal/p2p/message.go
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
    MsgTypeHandshake      MessageType = "HANDSHAKE"
    MsgTypePing           MessageType = "PING"
    MsgTypePong           MessageType = "PONG"
    MsgTypeInv            MessageType = "INV"
    MsgTypeGetData        MessageType = "GETDATA"
    MsgTypeTx             MessageType = "TX"
    MsgTypeBlock          MessageType = "BLOCK"
    MsgTypeAck            MessageType = "ACK"
    MsgTypeCustomData     MessageType = "CUSTOM_DATA"
    MsgTypeMetrics        MessageType = "METRICS"       // 🌐 network metrics broadcast
    MsgTypeRequestPeers   MessageType = "REQUEST_PEERS" // 🔹 request list of peers from a node
    MsgTypePeers         MessageType = "PEERS"          // réponse contenant la liste des peers
    MsgTypeCustom        MessageType = "CUSTOM"         // messages personnalisés
    MsgTypeAnnounceMiner MessageType = "ANNOUNCE_MINER" // annonce d’un nouveau mineur
)

type MinerInfo struct {
    MinerID   string `cbor:"miner_id"`
    Timestamp int64  `cbor:"timestamp"`
    PubKey    []byte `cbor:"pubkey,omitempty"`
}

// Envelope is the wire-level envelope. Use CBOR for compactness and speed.
// Added optional Signature and PubKey fields for message-level auth (ed25519).
type Envelope struct {
    Version   uint16      `cbor:"v"`
    Type      MessageType `cbor:"t"`
    Payload   []byte      `cbor:"p"`
    Timestamp int64       `cbor:"ts"`
    Signature []byte      `cbor:"sig,omitempty"`
    PubKey    []byte      `cbor:"pk,omitempty"`
    MinerInfo *MinerInfo  `cbor:"miner_info,omitempty"` // optional, only for miners
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

        now := time.Now().UnixMilli()
        skew := now - e.Timestamp
        if skew > 3600*1000 || skew < -3600*1000 {
                // warning log tolerated
        }

        switch e.Type {
        case MsgTypeHandshake, MsgTypeTx, MsgTypeBlock, MsgTypeInv, MsgTypeGetData, MsgTypeMetrics:
                if len(e.Payload) == 0 {
                        return errors.New("payload required for this message type")
                }
        case MsgTypePing, MsgTypePong:
                if len(e.Payload) > 1024 {
                        return errors.New("ping/pong payload too large")
                }
        case MsgTypeAck, MsgTypeCustomData:
                // optional payload
        default:
                return errors.New("unknown message type")
        }

        return nil
}

// -------------------- SIGNATURE --------------------

func VerifyEnvelopeSignature(e *Envelope) (bool, error) {
        if e == nil {
                return false, errors.New("nil envelope")
        }
        if len(e.Signature) == 0 || len(e.PubKey) == 0 {
                return false, nil
        }

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

func ObjectIDEqual(a, b []byte) bool {
        return bytes.Equal(a, b)
}
