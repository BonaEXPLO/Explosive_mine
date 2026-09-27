package p2p

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"explosive/internal/address"
)

func (n *Node) SetWalletIdentity(walletAddress string, publicKey []byte) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	walletAddress = strings.ToLower(strings.TrimSpace(walletAddress))

	if walletAddress == "" {
		return errors.New("wallet address is empty")
	}

	if !address.IsValidEXPLOAddress(walletAddress) {
		return errors.New("invalid EXPLO wallet address")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid wallet public key size: got %d, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}

	// The wallet address must be cryptographically derived
	// from the supplied Ed25519 public key.
	expectedAddress := address.GenerateEXPLOAddress(
		ed25519.PublicKey(publicKey),
	)

	if !strings.EqualFold(expectedAddress, walletAddress) {
		return errors.New(
			"wallet identity mismatch: address does not match public key",
		)
	}

	// Copy the public key so callers cannot mutate node identity
	// through the original byte slice.
	pubCopy := make([]byte, len(publicKey))
	copy(pubCopy, publicKey)

	n.walletIdentityMu.Lock()
	defer n.walletIdentityMu.Unlock()

	// A permanent wallet identity must never be silently replaced.
	if n.identityReady {
		if !strings.EqualFold(n.walletAddress, walletAddress) {
			return errors.New(
				"permanent wallet identity cannot be changed",
			)
		}

		if !ed25519.PublicKey(n.walletPublicKey).Equal(
			ed25519.PublicKey(pubCopy),
		) {
			return errors.New(
				"permanent wallet public key cannot be changed",
			)
		}

		return nil
	}

	n.walletAddress = walletAddress
	n.walletPublicKey = pubCopy

	// The wallet address is the permanent EXPLOSIVE
	// network identity of this node.
	n.id = PeerID(walletAddress)

	n.identityReady = true

	return nil
}

// SetWalletSigner configures the local wallet signing callback.
//
// SECURITY:
//   - The P2P node does not receive or store a private key.
//   - The P2P node does not receive or store a wallet password.
//   - The wallet layer remains responsible for secure key handling.
//   - Only the signing callback is retained by the node.
func (n *Node) SetWalletSigner(signer func([]byte) ([]byte, error)) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	if signer == nil {
		return errors.New("wallet signer is nil")
	}

	n.walletSignerMu.Lock()
	n.walletSigner = signer
	n.walletSignerMu.Unlock()

	return nil
}

// signWalletData delegates signing to the configured wallet signer.
//
// The private key never enters the P2P package.
func (n *Node) signWalletData(data []byte) ([]byte, error) {
	if n == nil {
		return nil, errors.New("nil P2P node")
	}

	if len(data) == 0 {
		return nil, errors.New("data to sign is empty")
	}

	n.walletSignerMu.RLock()
	signer := n.walletSigner
	n.walletSignerMu.RUnlock()

	if signer == nil {
		return nil, errors.New("wallet signer is not configured")
	}

	signature, err := signer(data)
	if err != nil {
		return nil, fmt.Errorf("wallet signing failed: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid wallet signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	// Copy the result so the callback cannot mutate the returned
	// signature after this function returns.
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	return sigCopy, nil
}

// SetMinerIdentity configures the public miner identity used by P2P.
//
// SECURITY:
//   - Only the MinerID and public key are stored.
//   - Sacred words are never stored in the P2P node.
//   - The miner private key never enters the P2P package.
func (n *Node) SetMinerIdentity(
	minerID string,
	publicKey []byte,
) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	minerID = strings.TrimSpace(minerID)

	if minerID == "" {
		return errors.New("miner ID is empty")
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid miner public key size: got %d, want %d",
			len(publicKey),
			ed25519.PublicKeySize,
		)
	}

	pubCopy := make([]byte, len(publicKey))
	copy(pubCopy, publicKey)

	n.minerIdentityMu.Lock()
	n.minerID = minerID
	n.minerPublicKey = pubCopy
	n.minerIdentityMu.Unlock()

	return nil
}

// SetMinerSigner configures the local miner signing callback.
//
// SECURITY:
//   - The P2P node does not receive or store the miner private key.
//   - The P2P node does not receive or store sacred words.
//   - The miner layer remains responsible for secure key derivation.
func (n *Node) SetMinerSigner(
	signer func([]byte) ([]byte, error),
) error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	if signer == nil {
		return errors.New("miner signer is nil")
	}

	n.minerSignerMu.Lock()
	n.minerSigner = signer
	n.minerSignerMu.Unlock()

	return nil
}

// getMinerIdentity returns a defensive copy of the public miner identity.
func (n *Node) getMinerIdentity() (string, []byte) {
	if n == nil {
		return "", nil
	}

	n.minerIdentityMu.RLock()
	defer n.minerIdentityMu.RUnlock()

	minerID := n.minerID

	var pubCopy []byte
	if len(n.minerPublicKey) > 0 {
		pubCopy = make([]byte, len(n.minerPublicKey))
		copy(pubCopy, n.minerPublicKey)
	}

	return minerID, pubCopy
}

// signMinerData delegates signing to the configured miner signer.
//
// The miner private key and sacred words never enter the P2P package.
func (n *Node) signMinerData(data []byte) ([]byte, error) {
	if n == nil {
		return nil, errors.New("nil P2P node")
	}

	if len(data) == 0 {
		return nil, errors.New("data to sign is empty")
	}

	n.minerSignerMu.RLock()
	signer := n.minerSigner
	n.minerSignerMu.RUnlock()

	if signer == nil {
		return nil, errors.New("miner signer is not configured")
	}

	signature, err := signer(data)
	if err != nil {
		return nil, fmt.Errorf("miner signing failed: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid miner signature size: got %d, want %d",
			len(signature),
			ed25519.SignatureSize,
		)
	}

	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	return sigCopy, nil
}

// normalizeListenAddr converts the provided listen address into a dual-stack compatible format.
//
// The function ensures the node binds to a single socket capable of accepting both IPv4 and IPv6
// connections by preferring the "[::]:port" format when possible. This leverages Go's native
// dual-stack support without requiring separate listeners.
//
// - Empty address → "[::]:defaultPort"
// - Port-only (e.g. ":8443") → "[::]:8443"
// - Already valid IPv6 or IPv4 address → returned unchanged
func normalizeListenAddr(addr string, defaultPort int) string {
	if addr == "" {
		return fmt.Sprintf("[::]:%d", defaultPort)
	}

	// Port only → dual stack
	if !strings.Contains(addr, ":") {
		return fmt.Sprintf("[::]:%s", addr)
	}

	return addr
}

// generateDeterministicTLSCert creates a self-signed Ed25519 TLS certificate.
//
// If a valid miner identity is provided (walletID + exactly 4 sacred words),
// a deterministic *sub-key* is derived specifically for TLS usage.
func generateDeterministicTLSCert(walletID string, words []string) (tls.Certificate, error) {
	var priv ed25519.PrivateKey

	if walletID != "" && len(words) == 4 {
		seed := sha256.Sum256([]byte(walletID + "|" + strings.Join(words, " ") + "|TLS_V1"))
		priv = ed25519.NewKeyFromSeed(seed[:])
	} else {
		_, p, err := ed25519.GenerateKey(cryptorand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		priv = p
	}

	now := time.Now()

	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		Subject: pkix.Name{
			CommonName: walletID,
		},
	}

	certDER, err := x509.CreateCertificate(
		cryptorand.Reader,
		&template,
		&template,
		priv.Public(),
		priv,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	// 🔥 CRITICAL FIX: parse Leaf
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])

	return cert, nil
}

// sha256Sum computes the SHA-256 hash of a string and returns the raw bytes
func sha256Sum(s string) []byte {
	h := sha256.New()
	h.Write([]byte(s))
	return h.Sum(nil)
}
