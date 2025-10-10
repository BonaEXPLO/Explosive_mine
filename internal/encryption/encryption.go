// internal/encryption/encryption.go
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"

	"explosive/internal/argon2id"

	"golang.org/x/crypto/sha3"
)

// EncryptBundle encrypts ID + 4 sacred words using AES-GCM with HMAC-SHA3 integrity.
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

	cipherText := aesgcm.Seal(nonce, nonce, bundle, nil)

	// HMAC-SHA3 for integrity
	h := hmac.New(sha3.New256, key)
	h.Write(cipherText)
	hmacValue := h.Sum(nil)

	// Append HMAC at the end for storage
	return append(cipherText, hmacValue...), nil
}

// DecryptBundle decrypts the bundle and verifies HMAC-SHA3.
func DecryptBundle(cipherData []byte, password string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	key := argon2id.DeriveKeyDefault([]byte(password), salt)

	// Separate HMAC from cipher
	if len(cipherData) < 32 {
		return nil, errors.New("cipherText too short")
	}
	hmacValue := cipherData[len(cipherData)-32:]
	cipherText := cipherData[:len(cipherData)-32]

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

	if len(cipherText) < aesgcm.NonceSize() {
		return nil, errors.New("cipherText too short for nonce")
	}

	nonce := cipherText[:aesgcm.NonceSize()]
	data := cipherText[aesgcm.NonceSize():]

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
