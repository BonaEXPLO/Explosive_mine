// internal/wallet/encryption.go
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// Encryption parameters
const (
	ArgonTime    = 3         // iterations (tunable)
	ArgonMemory  = 64 * 1024 // memory in KiB -> 64 * 1024 KiB = 64 MiB
	ArgonThreads = 4
	KeyLength    = 64 // derive 64 bytes and split: encKey=32, macKey=32
	SaltLength   = 16
	NonceLength  = 12
)

// EncryptedWallet stores encrypted payload and associated metadata.
// Ciphertext, Salt and Nonce are hex-encoded strings.
type EncryptedWallet struct {
	Salt             string `json:"salt"`
	Nonce            string `json:"nonce"`
	Ciphertext       string `json:"ciphertext"`
	HMAC             string `json:"hmac"`
	// Versioning / metadata could be added here (alg, kdf params, etc.)
}

// internal struct used as plaintext before encryption
type plaintextBundle struct {
	PrivateKeyHex string `json:"private_key_hex"`
	Mnemonic      string `json:"mnemonic,omitempty"`
}

// generateRandomBytes returns secure random bytes or an error.
func generateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	n, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}
	if n != length {
		return nil, fmt.Errorf("short read for random bytes")
	}
	return b, nil
}

// deriveKey returns a KeyLength bytes derived key using Argon2id.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, uint32(KeyLength))
}

// zeroBytes tries to overwrite a byte slice with zeros.
func zeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// EncryptWallet encrypts the private key and optional mnemonic with password.
// We now encrypt a JSON bundle {private_key_hex, mnemonic} to allow
// returning the mnemonic only after successful decryption.
func EncryptWallet(privKey []byte, mnemonic, password string) (*EncryptedWallet, error) {
	// Build plaintext JSON bundle
	bundle := plaintextBundle{
		PrivateKeyHex: hex.EncodeToString(privKey),
		Mnemonic:      mnemonic,
	}
	plaintext, err := json.Marshal(&bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plaintext bundle: %w", err)
	}

	salt, err := generateRandomBytes(SaltLength)
	if err != nil {
		zeroBytes(plaintext)
		return nil, err
	}

	derived := deriveKey(password, salt) // KeyLength bytes
	// split keys: first 32 bytes for AES, next 32 bytes for HMAC
	if len(derived) < 64 {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, errors.New("derived key too short")
	}
	encKey := derived[:32]
	macKey := derived[32:64]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce, err := generateRandomBytes(NonceLength)
	if err != nil {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// compute HMAC-SHA3-256 over ciphertext with macKey
	h := hmac.New(sha3.New256, macKey)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	// wipe sensitive slices
	zeroBytes(derived)
	zeroBytes(plaintext)

	return &EncryptedWallet{
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
		HMAC:       hex.EncodeToString(mac),
	}, nil
}

// DecryptWallet decrypts the EncryptedWallet using password.
// It returns private key bytes and the mnemonic string (may be empty).
func DecryptWallet(enc *EncryptedWallet, password string) ([]byte, string, error) {
	if enc == nil {
		return nil, "", errors.New("nil encrypted wallet")
	}
	salt, err := hex.DecodeString(enc.Salt)
	if err != nil {
		return nil, "", fmt.Errorf("invalid salt hex: %w", err)
	}
	nonce, err := hex.DecodeString(enc.Nonce)
	if err != nil {
		return nil, "", fmt.Errorf("invalid nonce hex: %w", err)
	}
	ciphertext, err := hex.DecodeString(enc.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	macBytes, err := hex.DecodeString(enc.HMAC)
	if err != nil {
		return nil, "", fmt.Errorf("invalid hmac hex: %w", err)
	}

	derived := deriveKey(password, salt)
	if len(derived) < 64 {
		zeroBytes(derived)
		return nil, "", errors.New("derived key too short")
	}
	encKey := derived[:32]
	macKey := derived[32:64]

	// verify HMAC
	h := hmac.New(sha3.New256, macKey)
	h.Write(ciphertext)
	expectedMac := h.Sum(nil)
	if !hmac.Equal(macBytes, expectedMac) {
		zeroBytes(derived)
		return nil, "", errors.New("HMAC verification failed: wrong password or corrupted data")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		zeroBytes(derived)
		return nil, "", fmt.Errorf("AES cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(derived)
		return nil, "", fmt.Errorf("GCM creation failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		zeroBytes(derived)
		return nil, "", fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	// parse JSON bundle
	var bundle plaintextBundle
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, "", fmt.Errorf("failed to unmarshal decrypted bundle: %w", err)
	}

	// convert private_key_hex to bytes
	privBytes, err := hex.DecodeString(bundle.PrivateKeyHex)
	if err != nil {
		zeroBytes(derived)
		zeroBytes(plaintext)
		return nil, "", fmt.Errorf("invalid private key hex in bundle: %w", err)
	}

	// wipe sensitive data
	zeroBytes(derived)
	zeroBytes(plaintext)

	return privBytes, bundle.Mnemonic, nil
}

// ToJSON returns JSON bytes for the EncryptedWallet.
func (enc *EncryptedWallet) ToJSON() ([]byte, error) {
	return json.Marshal(enc)
}

// EncryptedWalletFromJSON parses JSON bytes into an EncryptedWallet.
func EncryptedWalletFromJSON(data []byte) (*EncryptedWallet, error) {
	var enc EncryptedWallet
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted wallet JSON: %w", err)
	}
	return &enc, nil
}
