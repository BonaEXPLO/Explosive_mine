package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"explosive/internal/argon2id"
	"golang.org/x/crypto/sha3"
)

// ============================================================================
// EXPLOSIVE CRYPTOGRAPHIC FORMAT
// ============================================================================
//
// This package intentionally keeps backward compatibility.
//
// V1:
//   Legacy AES-GCM + HMAC-SHA3 bundle.
//   Existing wallets encrypted with V1 remain decryptable.
//
// V2:
//   AES-256-GCM authenticated encryption.
//   Explicit versioned envelope.
//   No redundant HMAC.
//   Cryptographic context authenticated through AEAD additional data.
//
// Future:
//   V3+ may introduce a different KDF, encryption scheme, hybrid recovery,
//   or post-quantum cryptographic migration without invalidating V1/V2 data.
//
// IMPORTANT:
//   DecryptBundle() automatically detects V1 or V2.
//   EncryptBundle() always creates V2.
//
// ============================================================================

const (
	// ------------------------------------------------------------------------
	// V2 envelope
	// ------------------------------------------------------------------------

	// magic identifies an EXPLOSIVE encrypted bundle.
	//
	// It is deliberately short and fixed because it is part of the
	// binary envelope, not a secret.
	v2Magic = "EXENCV2!"

	// V2 format version.
	v2Version byte = 2

	// AES-256 key size.
	v2KeyLength = 32

	// AES-GCM standard nonce size.
	v2NonceLength = 12

	// Minimum encrypted payload:
	// nonce + GCM authentication tag.
	v2MinimumDataLength = v2NonceLength + 16

	// ------------------------------------------------------------------------
	// Legacy V1
	// ------------------------------------------------------------------------

	// Legacy HMAC-SHA3-256 output size.
	legacyHMACLength = 32

	// ------------------------------------------------------------------------
	// General limits
	// ------------------------------------------------------------------------

	// Maximum salt accepted by this package.
	//
	// Normal EXPLOSIVE wallets use 16 or 32 bytes. A very large salt is not
	// useful and could be abused as an input-amplification vector.
	maxSaltLength = 64

	// Maximum encrypted bundle accepted.
	//
	// Wallet private material should be tiny. A large limit here would only
	// increase the usefulness of this API as a memory/DoS primitive.
	maxEncryptedBundleLength = 16 << 20 // 16 MiB

	// Maximum decrypted bundle accepted.
	maxPlaintextBundleLength = 8 << 20 // 8 MiB

	// ------------------------------------------------------------------------
	// Wallet encryption
	// ------------------------------------------------------------------------

	// Wallet salts are deliberately fixed-size.
	walletSaltLength = 16

	// ========================================================================
	// AEAD domain separation
	// ========================================================================
	//
	// This value is authenticated by AES-GCM.
	//
	// If the same key were ever accidentally reused by another EXPLOSIVE
	// subsystem, the cryptographic contexts remain separated.
	//
	// The value is NOT secret.
	//
	v2BundleAAD = "EXPLOSIVE-ENCRYPTED-BUNDLE-V2"
)

// ============================================================================
// Errors
// ============================================================================
//
// Errors returned to higher layers should preferably be mapped to generic
// user-facing messages. Detailed cryptographic errors should not be exposed
// through public wallet APIs.
//
// ============================================================================

var (
	ErrInvalidEncryptedData = errors.New("invalid encrypted data")
	ErrInvalidPasswordOrData = errors.New("invalid password or corrupted encrypted data")
	ErrUnsupportedVersion = errors.New("unsupported encrypted data version")
	ErrInvalidSalt = errors.New("invalid encryption salt")
	ErrInvalidKey = errors.New("invalid encryption key")
	ErrBundleTooLarge = errors.New("encrypted bundle too large")
	ErrPlaintextTooLarge = errors.New("decrypted bundle too large")
)

// ============================================================================
// Secure memory helpers
// ============================================================================

// zeroBytes attempts to overwrite sensitive byte material.
//
// IMPORTANT:
// Go does not provide guaranteed memory zeroization because of compiler
// optimizations, garbage collection and possible copies. This helper is
// nevertheless useful for reducing the lifetime of sensitive byte slices.
func zeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}

	for i := range b {
		b[i] = 0
	}
}

// ============================================================================
// Validation helpers
// ============================================================================

func validatePassword(password string) error {
	if password == "" {
		return errors.New("password cannot be empty")
	}

	return nil
}

func validateSalt(salt []byte) error {
	if len(salt) == 0 || len(salt) > maxSaltLength {
		return ErrInvalidSalt
	}

	return nil
}

func validateBundleSize(data []byte) error {
	if len(data) == 0 {
		return ErrInvalidEncryptedData
	}

	if len(data) > maxEncryptedBundleLength {
		return ErrBundleTooLarge
	}

	return nil
}

// ============================================================================
// Randomness
// ============================================================================

// randomBytes creates cryptographically secure random bytes.
func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("invalid random byte length")
	}

	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		zeroBytes(b)
		return nil, fmt.Errorf("secure random generation failed: %w", err)
	}

	return b, nil
}

// GenerateSalt creates a cryptographically secure random salt.
func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 || size > maxSaltLength {
		return nil, errors.New("invalid salt size")
	}

	return randomBytes(size)
}

// ============================================================================
// V2 key derivation
// ============================================================================

// deriveV2Key derives an AES-256 key.
//
// Argon2id is the password-based key derivation function.
//
// The exact Argon2 parameters are defined by the argon2id package. Future
// formats should store their KDF parameters in their own versioned envelope
// rather than silently changing them.
//
// V2 currently uses a single 32-byte key because AES-GCM already provides
// authenticated encryption and therefore does not need the legacy second
// HMAC key.
func deriveV2Key(password string, salt []byte) ([]byte, error) {
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	if err := validateSalt(salt); err != nil {
		return nil, err
	}

	key := argon2id.DeriveKeyDefault(
		[]byte(password),
		salt,
	)

	if len(key) != v2KeyLength {
		zeroBytes(key)
		return nil, ErrInvalidKey
	}

	return key, nil
}

// ============================================================================
// V2 envelope
// ============================================================================
//
// Layout:
//
//   magic[8]
//   version[1]
//   nonce[12]
//   ciphertext[n]
//
// The AAD is authenticated separately by AES-GCM.
//
// ============================================================================

func isV2Bundle(data []byte) bool {
	if len(data) < len(v2Magic)+1 {
		return false
	}

	return string(data[:len(v2Magic)]) == v2Magic &&
		data[len(v2Magic)] == v2Version
}

func buildV2Envelope(
	nonce []byte,
	ciphertext []byte,
) ([]byte, error) {
	if len(nonce) != v2NonceLength {
		return nil, ErrInvalidEncryptedData
	}

	if len(ciphertext) < 16 {
		return nil, ErrInvalidEncryptedData
	}

	total := len(v2Magic) + 1 + len(nonce) + len(ciphertext)

	if total > maxEncryptedBundleLength {
		return nil, ErrBundleTooLarge
	}

	out := make([]byte, 0, total)

	out = append(out, []byte(v2Magic)...)
	out = append(out, v2Version)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func parseV2Envelope(
	data []byte,
) ([]byte, []byte, error) {
	headerLength := len(v2Magic) + 1

	if len(data) < headerLength+v2MinimumDataLength {
		return nil, nil, ErrInvalidEncryptedData
	}

	if !isV2Bundle(data) {
		return nil, nil, ErrUnsupportedVersion
	}

	offset := headerLength

	nonceEnd := offset + v2NonceLength

	if nonceEnd > len(data) {
		return nil, nil, ErrInvalidEncryptedData
	}

	nonce := data[offset:nonceEnd]
	ciphertext := data[nonceEnd:]

	if len(ciphertext) < 16 {
		return nil, nil, ErrInvalidEncryptedData
	}

	return nonce, ciphertext, nil
}

// ============================================================================
// EncryptBundle
// ============================================================================
//
// EncryptBundle ALWAYS creates V2.
//
// Existing V1 data is handled by DecryptBundle.
//
// This means:
//   old wallet -> still decryptable
//   newly encrypted wallet -> V2
//
// ============================================================================

func EncryptBundle(
	bundle []byte,
	password string,
	salt []byte,
) ([]byte, error) {
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	if err := validateSalt(salt); err != nil {
		return nil, err
	}

	if len(bundle) == 0 {
		return nil, errors.New("bundle cannot be empty")
	}

	if len(bundle) > maxPlaintextBundleLength {
		return nil, ErrPlaintextTooLarge
	}

	key, err := deriveV2Key(password, salt)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES initialization failed: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM initialization failed: %w", err)
	}

	if aesgcm.NonceSize() != v2NonceLength {
		return nil, ErrInvalidEncryptedData
	}

	nonce, err := randomBytes(v2NonceLength)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)

	// AES-GCM authenticates the AAD together with the ciphertext.
	ciphertext := aesgcm.Seal(
		nil,
		nonce,
		bundle,
		[]byte(v2BundleAAD),
	)

	envelope, err := buildV2Envelope(
		nonce,
		ciphertext,
	)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

// ============================================================================
// Legacy V1 decryption
// ============================================================================
//
// V1 layout:
//
//   nonce || ciphertext || HMAC-SHA3-256
//
// The same Argon2-derived key was historically used for both AES-GCM and HMAC.
//
// DO NOT use this format for new encryption.
//
// It exists solely so old wallets can be migrated instead of invalidated.
// ============================================================================

func decryptLegacyV1(
	cipherData []byte,
	password string,
	salt []byte,
) ([]byte, error) {
	if err := validatePassword(password); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if err := validateSalt(salt); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(cipherData) < legacyHMACLength {
		return nil, ErrInvalidPasswordOrData
	}

	if len(cipherData) > maxEncryptedBundleLength {
		return nil, ErrInvalidPasswordOrData
	}

	key := argon2id.DeriveKeyDefault(
		[]byte(password),
		salt,
	)
	defer zeroBytes(key)

	if len(key) != v2KeyLength {
		return nil, ErrInvalidPasswordOrData
	}

	hmacValue := cipherData[len(cipherData)-legacyHMACLength:]
	cipherText := cipherData[:len(cipherData)-legacyHMACLength]

	// The legacy format stores nonce at the beginning.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	nonceSize := aesgcm.NonceSize()

	if len(cipherText) < nonceSize+aesgcm.Overhead() {
		return nil, ErrInvalidPasswordOrData
	}

	// Verify the legacy HMAC before attempting decryption.
	h := hmac.New(sha3.New256, key)

	_, _ = h.Write(cipherText)

	expectedMAC := h.Sum(nil)
	defer zeroBytes(expectedMAC)

	if !hmac.Equal(expectedMAC, hmacValue) {
		return nil, ErrInvalidPasswordOrData
	}

	nonce := cipherText[:nonceSize]
	data := cipherText[nonceSize:]

	plainText, err := aesgcm.Open(
		nil,
		nonce,
		data,
		nil,
	)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(plainText) > maxPlaintextBundleLength {
		zeroBytes(plainText)
		return nil, ErrPlaintextTooLarge
	}

	return plainText, nil
}

// ============================================================================
// V2 decryption
// ============================================================================

func decryptV2(
	cipherData []byte,
	password string,
	salt []byte,
) ([]byte, error) {
	if err := validatePassword(password); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if err := validateSalt(salt); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(cipherData) > maxEncryptedBundleLength {
		return nil, ErrInvalidPasswordOrData
	}

	nonce, ciphertext, err := parseV2Envelope(cipherData)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	key, err := deriveV2Key(password, salt)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, ErrInvalidPasswordOrData
	}

	plainText, err := aesgcm.Open(
		nil,
		nonce,
		ciphertext,
		[]byte(v2BundleAAD),
	)
	if err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(plainText) > maxPlaintextBundleLength {
		zeroBytes(plainText)
		return nil, ErrPlaintextTooLarge
	}

	return plainText, nil
}

// ============================================================================
// DecryptBundle
// ============================================================================
//
// Automatically supports:
//
//   V1 -> legacy decrypt
//   V2 -> hardened decrypt
//
// Unknown versions are rejected.
//
// This is the compatibility bridge that allows old wallets to survive the
// cryptographic migration.
// ============================================================================

func DecryptBundle(
	cipherData []byte,
	password string,
	salt []byte,
) ([]byte, error) {
	if err := validatePassword(password); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if err := validateSalt(salt); err != nil {
		return nil, ErrInvalidPasswordOrData
	}

	if len(cipherData) == 0 {
		return nil, ErrInvalidPasswordOrData
	}

	if len(cipherData) > maxEncryptedBundleLength {
		return nil, ErrInvalidPasswordOrData
	}

	if isV2Bundle(cipherData) {
		return decryptV2(
			cipherData,
			password,
			salt,
		)
	}

	// If the data begins with our magic but carries an unsupported version,
	// never silently interpret it as legacy data.
	if len(cipherData) >= len(v2Magic) &&
		string(cipherData[:len(v2Magic)]) == v2Magic {
		return nil, ErrUnsupportedVersion
	}

	// Everything else is treated as legacy V1.
	return decryptLegacyV1(
		cipherData,
		password,
		salt,
	)
}

// ============================================================================
// SHA3
// ============================================================================

// Sha3Hex returns a SHA3-256 digest as a lowercase hexadecimal string.
//
// This function is intentionally retained for compatibility with existing
// callers.
func Sha3Hex(data []byte) string {
	hash := sha3.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ============================================================================
// Wallet encrypted representation
// ============================================================================

// EncryptedWallet stores:
//
//   Salt -> password KDF salt
//   Data -> versioned encrypted bundle
//
// The structure remains compatible with the existing CBOR/JSON representation.
//
// IMPORTANT:
// Adding fields to this structure later should be done carefully and only
// through explicit versioned migration.
//
// ============================================================================

type EncryptedWallet struct {
	Salt []byte `cbor:"salt" json:"salt"`
	Data []byte `cbor:"data" json:"data"`
}

// ============================================================================
// Wallet secret
// ============================================================================
//
// LEGACY COMPATIBILITY:
//
// The existing wallet format stores both private key and mnemonic inside the
// encrypted secret.
//
// We keep this structure so existing wallets remain recoverable.
//
// SECURITY DIRECTION:
//
// Future wallet versions should avoid storing the mnemonic as part of the
// normal private-key bundle. The mnemonic should exist only during:
//   - wallet creation
//   - explicit recovery
//   - explicit backup/export
//
// That migration belongs to the wallet layer because this package must remain
// compatible with the existing DecryptWallet API during the transition.
//
// ============================================================================

type walletSecret struct {
	PrivKey  []byte `json:"priv"`
	Mnemonic string `json:"mnemonic"`
}

// ============================================================================
// EncryptWallet
// ============================================================================
//
// New wallets are encrypted using V2.
//
// The existing function signature is intentionally preserved so callers do
// not need to change immediately.
//
// ============================================================================

func EncryptWallet(
	priv []byte,
	mnemonic string,
	password string,
) (*EncryptedWallet, error) {
	if len(priv) == 0 {
		return nil, errors.New("private key cannot be empty")
	}

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// The wallet bundle remains structurally compatible.
	//
	// Future hardened wallet versions should separate recovery material from
	// the normal signing bundle.
	secret := walletSecret{
		PrivKey:  priv,
		Mnemonic: mnemonic,
	}

	plainText, err := json.Marshal(secret)
	if err != nil {
		return nil, errors.New("failed to encode wallet secret")
	}

	defer zeroBytes(plainText)

	if len(plainText) > maxPlaintextBundleLength {
		return nil, ErrPlaintextTooLarge
	}

	salt, err := GenerateSalt(walletSaltLength)
	if err != nil {
		return nil, err
	}

	encrypted, err := EncryptBundle(
		plainText,
		password,
		salt,
	)
	if err != nil {
		zeroBytes(salt)
		return nil, err
	}

	return &EncryptedWallet{
		Salt: salt,
		Data: encrypted,
	}, nil
}

// ============================================================================
// DecryptWallet
// ============================================================================
//
// Compatibility API:
//
//   returns private key + mnemonic
//
// This API is intentionally retained because existing wallet code depends on
// it.
//
// SECURITY NOTE:
//
// A future hardened wallet API should expose separate operations:
//
//   DecryptPrivateKey()
//   RecoverMnemonic()
//
// so normal signing never receives a mnemonic.
//
// ============================================================================

func DecryptWallet(
	e *EncryptedWallet,
	password string,
) ([]byte, string, error) {
	if e == nil {
		return nil, "", ErrInvalidPasswordOrData
	}

	if len(e.Salt) == 0 || len(e.Salt) > maxSaltLength {
		return nil, "", ErrInvalidPasswordOrData
	}

	if len(e.Data) == 0 || len(e.Data) > maxEncryptedBundleLength {
		return nil, "", ErrInvalidPasswordOrData
	}

	plainText, err := DecryptBundle(
		e.Data,
		password,
		e.Salt,
	)
	if err != nil {
		// Do not expose whether the problem was:
		//   - wrong password
		//   - bad HMAC
		//   - bad GCM tag
		//   - malformed ciphertext
		//
		// All are represented as a generic cryptographic failure.
		return nil, "", ErrInvalidPasswordOrData
	}

	defer zeroBytes(plainText)

	var secret walletSecret

	decoder := json.NewDecoder(
		bytes.NewReader(plainText),
	)

	if err := decoder.Decode(&secret); err != nil {
		return nil, "", ErrInvalidPasswordOrData
	}

	// Reject trailing JSON values.
	var extra interface{}

	if err := decoder.Decode(&extra); err == nil {
		return nil, "", ErrInvalidPasswordOrData
	}

	if len(secret.PrivKey) == 0 {
		return nil, "", ErrInvalidPasswordOrData
	}

	// Make an independent private-key copy for the caller.
	//
	// secret.PrivKey itself belongs to the decoded JSON structure and will
	// become unreachable after return. The returned copy is explicit.
	privKey := make([]byte, len(secret.PrivKey))
	copy(privKey, secret.PrivKey)

	// The mnemonic is returned for compatibility with the existing API.
	//
	// It cannot be securely zeroized because Go strings are immutable.
	// The next wallet-layer hardening phase will remove routine mnemonic
	// exposure from normal signing paths.
	mnemonic := secret.Mnemonic

	// Reduce the lifetime of the decoded private key buffer.
	zeroBytes(secret.PrivKey)

	return privKey, mnemonic, nil
}

// ============================================================================
// Wallet format inspection
// ============================================================================

// IsV2EncryptedWallet reports whether the encrypted data uses the hardened
// V2 format.
//
// It does not decrypt anything and does not require the password.
func IsV2EncryptedWallet(e *EncryptedWallet) bool {
	if e == nil {
		return false
	}

	return isV2Bundle(e.Data)
}

// IsLegacyEncryptedWallet reports whether the wallet appears to use the
// legacy V1 encrypted bundle.
//
// This is only format detection. It does not prove that the data is valid.
func IsLegacyEncryptedWallet(e *EncryptedWallet) bool {
	if e == nil || len(e.Data) == 0 {
		return false
	}

	return !isV2Bundle(e.Data) &&
		!(len(e.Data) >= len(v2Magic) &&
			string(e.Data[:len(v2Magic)]) == v2Magic)
}

// ============================================================================
// Wallet migration helper
// ============================================================================
//
// MigrateWalletToV2 decrypts an existing wallet and immediately re-encrypts
// it using the new V2 encryption format.
//
// IMPORTANT:
//
// This helper preserves the existing wallet's logical contents.
//
// It does NOT change:
//   - address
//   - private key
//   - mnemonic
//
// It only upgrades the encrypted representation.
//
// The wallet layer should later decide when migration is committed to storage.
//
// ============================================================================

func MigrateWalletToV2(
	e *EncryptedWallet,
	password string,
) (*EncryptedWallet, error) {
	if e == nil {
		return nil, ErrInvalidPasswordOrData
	}

	// Already V2: no migration necessary.
	if IsV2EncryptedWallet(e) {
		return e, nil
	}

	privKey, mnemonic, err := DecryptWallet(
		e,
		password,
	)
	if err != nil {
		return nil, err
	}

	defer zeroBytes(privKey)

	migrated, err := EncryptWallet(
		privKey,
		mnemonic,
		password,
	)
	if err != nil {
		return nil, err
	}

	return migrated, nil
}

// ============================================================================
// Secure binary integer helpers
// ============================================================================
//
// Reserved for future versioned cryptographic envelopes.
//
// Keeping binary encoding helpers here avoids relying on JSON for future
// cryptographic metadata.
//
// ============================================================================

func appendUint32(dst []byte, value uint32) []byte {
	var buf [4]byte

	binary.BigEndian.PutUint32(
		buf[:],
		value,
	)

	return append(dst, buf[:]...)
}
