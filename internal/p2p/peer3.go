package p2p

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"

	"explosive/internal/address"
	"explosive/internal/ledger"
)

// SendEnvelope serializes and enqueues an envelope for sending.
//
// Signing policy:
//  1. HANDSHAKE is already signed explicitly by sendHandshake().
//  2. If a wallet signer is configured, regular messages are signed with
//     the authenticated wallet identity.
//  3. If no wallet signer is configured, the legacy miner signing path is
//     preserved temporarily for miner-only nodes.
//  4. Critical messages can never be sent unsigned.
//
// The P2P layer never receives or stores wallet private keys.
func (p *Peer) SendEnvelope(e *Envelope) error {

	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("missing node reference")
	}

	if e == nil {
		return errors.New("nil envelope")
	}

	// ================================================================
	// SIGNING
	// ================================================================
	//
	// The handshake is signed explicitly by sendHandshake().
	//
	// Every other signed P2P message uses the authenticated wallet
	// identity. The wallet public key is stored in Envelope.PubKey and
	// the corresponding wallet signature is stored in Envelope.Signature.
	//
	// Miner authentication is separate and is carried only through
	// MinerInfo when explicitly required by the protocol.
	//
	// The P2P package never accesses miner sacred words or derives
	// miner private keys.
	// ================================================================

	if p.node.config.RequireSignedMessages &&
		e.Type != MsgTypeHandshake {

		signed := false

		// ------------------------------------------------------------
		// WALLET PUBLIC IDENTITY
		// ------------------------------------------------------------

		p.node.walletIdentityMu.RLock()

		walletAddress := p.node.walletAddress
		walletPublicKey := append(
			[]byte(nil),
			p.node.walletPublicKey...,
		)

		p.node.walletIdentityMu.RUnlock()

		// ------------------------------------------------------------
		// WALLET SIGNER
		// ------------------------------------------------------------

		p.node.walletSignerMu.RLock()
		walletSignerConfigured := p.node.walletSigner != nil
		p.node.walletSignerMu.RUnlock()

		if walletSignerConfigured &&
			walletAddress != "" &&
			address.IsValidEXPLOAddress(walletAddress) &&
			len(walletPublicKey) == ed25519.PublicKeySize {

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
				return fmt.Errorf(
					"failed to marshal canonical wallet signing data: %w",
					err,
				)
			}

			signature, err := p.node.signWalletData(msg)
			if err != nil {
				return fmt.Errorf(
					"failed to sign message with wallet: %w",
					err,
				)
			}

			if len(signature) != ed25519.SignatureSize {
				return fmt.Errorf(
					"invalid wallet signature size: got %d, want %d",
					len(signature),
					ed25519.SignatureSize,
				)
			}

			e.Signature = append([]byte(nil), signature...)
			e.PubKey = append([]byte(nil), walletPublicKey...)

			signed = true

			log.Printf(
				"[p2p] 🔐 message signed with wallet identity: type=%s wallet=%s",
				e.Type,
				walletAddress,
			)
		}

		// ------------------------------------------------------------
		// NO LEGACY MINER FALLBACK
		// ------------------------------------------------------------
		//
		// A P2P node must never enumerate local miners, read sacred
		// words, derive miner private keys, or silently select miners[0].
		//
		// Miner authentication is handled separately by the explicit
		// MinerInfo proof mechanism.
		// ------------------------------------------------------------

		if !signed {

			critical :=
				e.Type == MsgTypeTx ||
					e.Type == MsgTypeBlock ||
					e.Type == MsgTypeInv ||
					e.Type == MsgTypeMetrics

			if critical {
				return fmt.Errorf(
					"critical message %s cannot be sent without a valid wallet identity",
					e.Type,
				)
			}

			return fmt.Errorf(
				"message %s cannot be sent without a valid wallet identity",
				e.Type,
			)
		}
	}

	// ================================================================
	// ENCODE
	// ================================================================

	b, err := EncodeEnvelope(e)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	max := p.node.config.MaxMsgSize
	if max <= 0 {
		max = 4 * 1024 * 1024
	}

	if len(b) > max {
		return fmt.Errorf(
			"message too large: %d > %d",
			len(b),
			max,
		)
	}

	select {
	case <-p.ctx.Done():
		return errors.New("peer closed")
	default:
	}

	// ================================================================
	// TRANSACTION QUEUE
	// ================================================================

	if e.Type == MsgTypeTx {

		select {
		case p.sendQ <- b:
			return nil

		default:
			p.Penalize(1, 0)
			return errors.New("TX queue full")
		}
	}

	// ================================================================
	// CRITICAL QUEUE
	// ================================================================

	critical :=
		e.Type == MsgTypeHandshake ||
			e.Type == MsgTypeBlock ||
			e.Type == MsgTypeInv

	if critical {

		timeout := 500 * time.Millisecond

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-p.ctx.Done():
			return errors.New("peer closed")

		case p.sendQ <- b:
			return nil

		case <-timer.C:

			log.Printf(
				"[p2p] timeout sending critical %s to %s",
				e.Type,
				p.addr,
			)

			return errors.New("critical send timeout")
		}
	}

	// ================================================================
	// NORMAL QUEUE
	// ================================================================

	select {
	case p.sendQ <- b:
		return nil

	default:

		log.Printf(
			"[p2p] peer %s: outbound queue full, dropping %s",
			p.addr,
			e.Type,
		)

		return errors.New("send queue full")
	}
}

func (p *Peer) signEnvelope(
	env *Envelope,
	priv ed25519.PrivateKey,
	miner *ledger.Miner,
) error {

	if p == nil {
		return errors.New("nil peer")
	}

	if p.node == nil {
		return errors.New("missing node reference")
	}

	if env == nil {
		return errors.New("nil envelope")
	}

	// The P2P envelope identity is the wallet identity.
	// Miner identity is separate and must never replace Wallet.PubKey.
	//
	// Keep the legacy parameters in the function signature for
	// compatibility with existing callers, but never use them to
	// construct the P2P envelope identity.

	p.node.walletIdentityMu.RLock()

	walletAddress := p.node.walletAddress
	walletPublicKey := append(
		[]byte(nil),
		p.node.walletPublicKey...,
	)

	p.node.walletIdentityMu.RUnlock()

	if walletAddress == "" {
		return errors.New("wallet identity is not configured")
	}

	if !address.IsValidEXPLOAddress(walletAddress) {
		return errors.New("invalid wallet address")
	}

	if len(walletPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid wallet public key size: got %d, want %d",
			len(walletPublicKey),
			ed25519.PublicKeySize,
		)
	}

	p.node.walletSignerMu.RLock()
	walletSignerConfigured := p.node.walletSigner != nil
	p.node.walletSignerMu.RUnlock()

	if !walletSignerConfigured {
		return errors.New("wallet signer is not configured")
	}

	canon := struct {
		V     uint16      `cbor:"v"`
		T     MessageType `cbor:"t"`
		P     []byte      `cbor:"p,omitempty"`
		Ts    int64       `cbor:"ts"`
		Nonce uint64      `cbor:"nonce"`
	}{
		V:     env.Version,
		T:     env.Type,
		P:     env.Payload,
		Ts:    env.Timestamp,
		Nonce: env.Nonce,
	}

	msg, err := cbor.Marshal(canon)
	if err != nil {
		return fmt.Errorf(
			"failed to marshal canonical data for signing: %w",
			err,
		)
	}

	signature, err := p.node.signWalletData(msg)
	if err != nil {
		return fmt.Errorf(
			"failed to sign envelope with wallet: %w",
			err,
		)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf(
			"invalid wallet signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	env.Signature = append([]byte(nil), signature...)
	env.PubKey = walletPublicKey

	return nil
}
