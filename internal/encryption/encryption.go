// internal/encryption/encryption.go
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"explosive/internal/argon2id"
	"golang.org/x/crypto/sha3"
)

// -----------------------------
// Core AES-GCM + HMAC-SHA3 bundle
// -----------------------------

// EncryptBundle encrypts a raw bundle using AES-GCM and appends an HMAC-SHA3
// over the nonce+ciphertext for integrity. Returns: nonce||ciphertext||hmac.
func EncryptBundle(bundle []byte, password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	key := argon2id.DeriveKeyDefault([]byte(password), salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Seal(dst, nonce, plaintext, additionalData) returns dst || nonce || ciphertext
	// we pass nonce as dst to produce nonce || ciphertext as output
	cipherText := aesgcm.Seal(nonce, nonce, bundle, nil)

	// HMAC-SHA3 for integrity over nonce||ciphertext
	h := hmac.New(sha3.New256, key)
	h.Write(cipherText)
	hmacValue := h.Sum(nil)

	// Append HMAC at the end for storage
	return append(cipherText, hmacValue...), nil
}

// DecryptBundle verifies HMAC-SHA3 then decrypts AES-GCM (expects nonce at start).
func DecryptBundle(cipherData []byte, password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	key := argon2id.DeriveKeyDefault([]byte(password), salt)

	const hmacLen = 32
	if len(cipherData) < hmacLen {
		return nil, errors.New("cipherData too short")
	}

	// Separate HMAC from cipher bytes
	hmacValue := cipherData[len(cipherData)-hmacLen:]
	cipherText := cipherData[:len(cipherData)-hmacLen]

	// Verify HMAC
	h := hmac.New(sha3.New256, key)
	h.Write(cipherText)
	expected := h.Sum(nil)
	if !hmac.Equal(expected, hmacValue) {
		return nil, errors.New("HMAC mismatch: data integrity check failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("cipherText too short for nonce")
	}

	nonce := cipherText[:nonceSize]
	data := cipherText[nonceSize:]

	plainText, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Sha3Hex returns SHA3-256 hash as hex string.
func Sha3Hex(data []byte) string {
	hash := sha3.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// -----------------------------
// Wallet helpers (bundle priv + mnemonic)
// -----------------------------

// EncryptedWallet stores the salt and encrypted blob.
// Tagged for CBOR/JSON so it serializes properly inside Wallet struct.
type EncryptedWallet struct {
	Salt []byte `cbor:"salt" json:"salt"`
	Data []byte `cbor:"data" json:"data"`
}

// walletSecret is the internal JSON shape stored inside the encrypted bundle.
type walletSecret struct {
	PrivKey  []byte `json:"priv"`
	Mnemonic string `json:"mnemonic"`
}

// GenerateSalt creates a random salt of given size in bytes.
func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid salt size")
	}
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// EncryptWallet packages priv + mnemonic and encrypts using EncryptBundle.
// Returns EncryptedWallet (salt + encrypted data).
func EncryptWallet(priv []byte, mnemonic, password string) (*EncryptedWallet, error) {
	// bundle priv + mnemonic as JSON (internal format)
	b, err := json.Marshal(walletSecret{
		PrivKey:  priv,
		Mnemonic: mnemonic,
	})
	if err != nil {
		return nil, err
	}

	salt, err := GenerateSalt(16)
	if err != nil {
		return nil, err
	}

	enc, err := EncryptBundle(b, password, salt)
	if err != nil {
		return nil, err
	}

	return &EncryptedWallet{
		Salt: salt,
		Data: enc,
	}, nil
}

// DecryptWallet decrypts an EncryptedWallet using the provided password and returns
// the private key bytes and mnemonic string.
func DecryptWallet(e *EncryptedWallet, password string) ([]byte, string, error) {
	if e == nil {
		return nil, "", errors.New("missing encrypted wallet")
	}
	plain, err := DecryptBundle(e.Data, password, e.Salt)
	if err != nil {
		return nil, "", err
	}

	var secret walletSecret
	if err := json.Unmarshal(plain, &secret); err != nil {
		return nil, "", err
	}
	return secret.PrivKey, secret.Mnemonic, nil
}
