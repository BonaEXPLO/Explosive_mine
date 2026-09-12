// internal/wallet/wallet.go
package wallet

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/tyler-smith/go-bip39"

	"explosive/internal/address"
	"explosive/internal/encryption"
)

// Wallet represents a user wallet for the EXPLOSIVE blockchain.
//
// Security model:
//   - PublicKeyHex and Address are public metadata.
//   - EncryptedPriv contains the encrypted private material.
//   - Mnemonic is intentionally never populated in normal wallet memory.
//   - BalanceEXP and BalanceIM are display/cache fields only.
//     Consensus balances must come from the ledger.
type Wallet struct {
	PublicKeyHex  string                      `cbor:"public_key_hex"`
	Address       string                      `cbor:"address"`
	Mnemonic      string                      `cbor:"mnemonic,omitempty"` // Deprecated: must remain empty.
	EncryptedPriv *encryption.EncryptedWallet `cbor:"encrypted_priv"`

	// Display/cache values only.
	// The ledger remains the authoritative source of truth.
	BalanceEXP float64 `cbor:"balance_exp"`
	BalanceIM  float64 `cbor:"balance_im"`
}

const (
	maxWalletCBORSize = 64 * 1024

	expectedPublicKeySize  = ed25519.PublicKeySize
	expectedPrivateKeySize = ed25519.PrivateKeySize

	expectedMnemonicWords = 24

	minPasswordRunes = 12
)

// validatePassword enforces a strong password policy for newly created
// or re-encrypted wallets.
func validatePassword(password string) error {
	if !utf8.ValidString(password) {
		return errors.New("password contains invalid UTF-8")
	}

	if len([]rune(password)) < minPasswordRunes {
		return fmt.Errorf(
			"password must be at least %d characters",
			minPasswordRunes,
		)
	}

	var hasUpper bool
	var hasLower bool
	var hasDigit bool
	var hasSymbol bool

	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true

		case 'a' <= c && c <= 'z':
			hasLower = true

		case '0' <= c && c <= '9':
			hasDigit = true

		case strings.ContainsRune(
			"!@#$%^&*()-_=+[]{}<>?/|\\:;,.~`'\"",
			c,
		):
			hasSymbol = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	if !hasSymbol {
		return errors.New("password must contain at least one symbol")
	}

	return nil
}

func validatePasswordForRestore(password string) error {
	return validatePassword(password)
}

// validateMnemonic performs strict BIP39 validation.
func validateMnemonic(mnemonic string) error {
	if !utf8.ValidString(mnemonic) {
		return errors.New("mnemonic contains invalid UTF-8")
	}

	mnemonic = strings.TrimSpace(mnemonic)

	if mnemonic == "" {
		return errors.New("mnemonic is empty")
	}

	words := strings.Fields(mnemonic)

	if len(words) != expectedMnemonicWords {
		return fmt.Errorf(
			"mnemonic must contain exactly %d words",
			expectedMnemonicWords,
		)
	}

	normalized := strings.Join(words, " ")

	if !bip39.IsMnemonicValid(normalized) {
		return errors.New("invalid BIP39 mnemonic")
	}

	return nil
}

// deriveKeyPair deterministically derives the EXPLOSIVE Ed25519 keypair.
//
// Compatibility rule:
//
//	BIP39 mnemonic
//	    -> bip39.NewSeed(mnemonic, "")
//	    -> first 32 bytes
//	    -> Ed25519 private key
//
// DO NOT change this derivation for legacy wallets.
func deriveKeyPair(
	mnemonic string,
) (
	ed25519.PrivateKey,
	ed25519.PublicKey,
	error,
) {
	if err := validateMnemonic(mnemonic); err != nil {
		return nil, nil, err
	}

	seed := bip39.NewSeed(mnemonic, "")

	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if len(seed) < ed25519.SeedSize {
		return nil, nil, errors.New("derived BIP39 seed is too short")
	}

	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])

	if len(priv) != expectedPrivateKeySize {
		for i := range priv {
			priv[i] = 0
		}

		return nil, nil, errors.New(
			"derived private key has invalid size",
		)
	}

	pubRaw := priv.Public()

	pub, ok := pubRaw.(ed25519.PublicKey)
	if !ok {
		for i := range priv {
			priv[i] = 0
		}

		return nil, nil, errors.New(
			"failed to derive Ed25519 public key",
		)
	}

	if len(pub) != expectedPublicKeySize {
		for i := range priv {
			priv[i] = 0
		}

		for i := range pub {
			pub[i] = 0
		}

		return nil, nil, errors.New(
			"derived public key has invalid size",
		)
	}

	pubCopy := make([]byte, len(pub))
	copy(pubCopy, pub)

	return priv, ed25519.PublicKey(pubCopy), nil
}

// buildWallet creates the wallet from public identity and encrypted
// private material.
//
// The private key is deliberately NOT passed here.
// At this point the private key should already have been zeroized.
func buildWallet(
	pub ed25519.PublicKey,
	encPriv *encryption.EncryptedWallet,
) (*Wallet, error) {
	if len(pub) != expectedPublicKeySize {
		return nil, errors.New("invalid public key size")
	}

	if encPriv == nil {
		return nil, errors.New("encrypted private key is nil")
	}

	addr := address.GenerateEXPLOAddress(pub)

	if !address.IsValidEXPLOAddress(addr) {
		return nil, errors.New("generated EXPLO address is invalid")
	}

	return &Wallet{
		PublicKeyHex: hex.EncodeToString(pub),
		Address:      addr,
		Mnemonic:     "",
		EncryptedPriv: encPriv,

		BalanceEXP: 0,
		BalanceIM:  0,
	}, nil
}

// CreateWallet generates a new 24-word BIP39 wallet.
func CreateWallet(password string) (*Wallet, error) {
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate entropy: %w",
			err,
		)
	}

	defer func() {
		for i := range entropy {
			entropy[i] = 0
		}
	}()

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to generate mnemonic: %w",
			err,
		)
	}

	priv, pub, err := deriveKeyPair(mnemonic)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to derive wallet keys: %w",
			err,
		)
	}

	encPriv, encErr := encryption.EncryptWallet(
		priv,
		mnemonic,
		password,
	)

	for i := range priv {
		priv[i] = 0
	}

	if encErr != nil {
		for i := range pub {
			pub[i] = 0
		}

		return nil, fmt.Errorf(
			"failed to encrypt wallet: %w",
			encErr,
		)
	}

	w, err := buildWallet(pub, encPriv)

	for i := range pub {
		pub[i] = 0
	}

	if err != nil {
		return nil, err
	}

	return w, nil
}

// RestoreWalletByMnemonic restores a wallet from a BIP39 mnemonic.
func RestoreWalletByMnemonic(
	mnemonic,
	password string,
) (*Wallet, error) {
	mnemonic = strings.Join(
		strings.Fields(mnemonic),
		" ",
	)

	if err := validateMnemonic(mnemonic); err != nil {
		return nil, err
	}

	if err := validatePasswordForRestore(password); err != nil {
		return nil, err
	}

	priv, pub, err := deriveKeyPair(mnemonic)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to derive wallet keys: %w",
			err,
		)
	}

	encPriv, encErr := encryption.EncryptWallet(
		priv,
		mnemonic,
		password,
	)

	for i := range priv {
		priv[i] = 0
	}

	if encErr != nil {
		for i := range pub {
			pub[i] = 0
		}

		return nil, fmt.Errorf(
			"failed to encrypt restored wallet: %w",
			encErr,
		)
	}

	w, err := buildWallet(pub, encPriv)

	for i := range pub {
		pub[i] = 0
	}

	if err != nil {
		return nil, err
	}

	return w, nil
}

// validatePublicIdentity verifies that PublicKeyHex and Address form a
// valid cryptographic identity.
func (w *Wallet) validatePublicIdentity() (
	ed25519.PublicKey,
	error,
) {
	if w == nil {
		return nil, errors.New("wallet is nil")
	}

	if w.PublicKeyHex == "" {
		return nil, errors.New("wallet public key is empty")
	}

	if len(w.PublicKeyHex) != expectedPublicKeySize*2 {
		return nil, errors.New(
			"wallet public key has invalid length",
		)
	}

	pubBytes, err := hex.DecodeString(w.PublicKeyHex)
	if err != nil {
		return nil, errors.New(
			"wallet public key is not valid hexadecimal",
		)
	}

	if len(pubBytes) != expectedPublicKeySize {
		for i := range pubBytes {
			pubBytes[i] = 0
		}

		return nil, errors.New(
			"wallet public key has invalid size",
		)
	}

	if !address.IsValidEXPLOAddress(w.Address) {
		for i := range pubBytes {
			pubBytes[i] = 0
		}

		return nil, errors.New("wallet address is invalid")
	}

	expectedAddress := address.GenerateEXPLOAddress(
		ed25519.PublicKey(pubBytes),
	)

	if !strings.EqualFold(
		expectedAddress,
		w.Address,
	) {
		for i := range pubBytes {
			pubBytes[i] = 0
		}

		return nil, errors.New(
			"wallet address does not match public key",
		)
	}

	return ed25519.PublicKey(pubBytes), nil
}

// validateEncryptedWallet validates the encrypted wallet container.
func (w *Wallet) validateEncryptedWallet() error {
	if w == nil {
		return errors.New("wallet is nil")
	}

	if w.EncryptedPriv == nil {
		return errors.New(
			"wallet has no encrypted private key",
		)
	}

	if len(w.EncryptedPriv.Salt) == 0 {
		return errors.New(
			"wallet encryption salt is empty",
		)
	}

	if len(w.EncryptedPriv.Data) == 0 {
		return errors.New(
			"wallet encrypted data is empty",
		)
	}

	return nil
}

// RevealMnemonic returns the recovery phrase.
//
// LEGACY / SENSITIVE API.
// Retained for compatibility with the current application.
func (w *Wallet) RevealMnemonic(
	password string,
) (string, error) {
	if err := w.validateEncryptedWallet(); err != nil {
		return "", err
	}

	_, mnemonic, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		password,
	)
	if err != nil {
		return "", errors.New(
			"invalid password or corrupted wallet",
		)
	}

	if err := validateMnemonic(mnemonic); err != nil {
		return "", errors.New(
			"decrypted recovery phrase is invalid",
		)
	}

	return mnemonic, nil
}

// ChangePassword changes the wallet password.
func (w *Wallet) ChangePassword(
	oldPassword,
	newPassword string,
) error {
	if err := w.validateEncryptedWallet(); err != nil {
		return err
	}

	if oldPassword == "" {
		return errors.New(
			"old password cannot be empty",
		)
	}

	if err := validatePassword(newPassword); err != nil {
		return errors.New(
			"new password does not meet strength requirements",
		)
	}

	priv, mnemonic, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		oldPassword,
	)
	if err != nil {
		return errors.New(
			"old password incorrect or wallet corrupted",
		)
	}

	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()

	if len(priv) != expectedPrivateKeySize {
		return errors.New(
			"decrypted private key has invalid size",
		)
	}

	if err := validateMnemonic(mnemonic); err != nil {
		return errors.New(
			"decrypted recovery phrase is invalid",
		)
	}

	pub, err := w.validatePublicIdentity()
	if err != nil {
		return err
	}

	defer func() {
		for i := range pub {
			pub[i] = 0
		}
	}()

	privPubRaw := ed25519.PrivateKey(priv).Public()

        privPub, ok := privPubRaw.(ed25519.PublicKey)
	if !ok || len(privPub) != expectedPublicKeySize {
		return errors.New(
			"failed to derive public key from private key",
		)
	}

	matches := subtle.ConstantTimeCompare(
		privPub,
		pub,
	) == 1

	for i := range privPub {
		privPub[i] = 0
	}

	if !matches {
		return errors.New(
			"encrypted private key does not match wallet identity",
		)
	}

	newEnc, err := encryption.EncryptWallet(
		priv,
		mnemonic,
		newPassword,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to re-encrypt wallet: %w",
			err,
		)
	}

	if newEnc == nil {
		return errors.New(
			"new encrypted wallet is nil",
		)
	}

	w.EncryptedPriv = newEnc
	w.Mnemonic = ""

	return nil
}

// DeleteWallet verifies the recovery phrase and password, then clears the
// in-memory wallet.
//
// Persistent database deletion is handled by the storage layer.
func (w *Wallet) DeleteWallet(
	mnemonic,
	password string,
) error {
	if err := w.validateEncryptedWallet(); err != nil {
		return err
	}

	mnemonic = strings.Join(
		strings.Fields(mnemonic),
		" ",
	)

	if err := validateMnemonic(mnemonic); err != nil {
		return errors.New(
			"invalid recovery phrase",
		)
	}

	priv, storedMnemonic, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		password,
	)
	if err != nil {
		return errors.New(
			"invalid password or corrupted wallet",
		)
	}

	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()

	if len(priv) != expectedPrivateKeySize {
		return errors.New(
			"decrypted private key has invalid size",
		)
	}

	if err := validateMnemonic(storedMnemonic); err != nil {
		return errors.New(
			"stored recovery phrase is corrupted",
		)
	}

	if subtle.ConstantTimeCompare(
		[]byte(mnemonic),
		[]byte(storedMnemonic),
	) != 1 {
		return errors.New(
			"mnemonic does not match",
		)
	}

	pub, err := w.validatePublicIdentity()
	if err != nil {
		return err
	}

	defer func() {
		for i := range pub {
			pub[i] = 0
		}
	}()

	privPubRaw := ed25519.PrivateKey(priv).Public()

        privPub, ok := privPubRaw.(ed25519.PublicKey)
	if !ok || len(privPub) != expectedPublicKeySize {
		return errors.New(
			"failed to derive public key from private key",
		)
	}

	matches := subtle.ConstantTimeCompare(
		privPub,
		pub,
	) == 1

	for i := range privPub {
		privPub[i] = 0
	}

	if !matches {
		return errors.New(
			"private key does not match wallet identity",
		)
	}

	*w = Wallet{}

	return nil
}

// ToCBORLine serializes the wallet as CBOR + Base64.
func (w *Wallet) ToCBORLine() (string, error) {
	if w == nil {
		return "", errors.New("wallet is nil")
	}

	if w.Mnemonic != "" {
		return "", errors.New(
			"refusing to serialize wallet containing plaintext mnemonic",
		)
	}

	if _, err := w.validatePublicIdentity(); err != nil {
		return "", fmt.Errorf(
			"invalid wallet identity: %w",
			err,
		)
	}

	if err := w.validateEncryptedWallet(); err != nil {
		return "", err
	}

	data, err := cbor.Marshal(w)
	if err != nil {
		return "", fmt.Errorf(
			"failed to serialize wallet: %w",
			err,
		)
	}

	if len(data) > maxWalletCBORSize {
		return "", errors.New(
			"serialized wallet is too large",
		)
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// FromCBORLine deserializes an untrusted wallet record.
func FromCBORLine(line string) (*Wallet, error) {
	line = strings.TrimSpace(line)

	if line == "" {
		return nil, errors.New(
			"wallet data is empty",
		)
	}

	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode base64 wallet: %w",
			err,
		)
	}

	if len(raw) == 0 {
		return nil, errors.New(
			"decoded wallet data is empty",
		)
	}

	if len(raw) > maxWalletCBORSize {
		return nil, errors.New(
			"wallet data is too large",
		)
	}

	var w Wallet

	if err := cbor.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf(
			"failed to deserialize wallet: %w",
			err,
		)
	}

	if w.Mnemonic != "" {
		return nil, errors.New(
			"wallet contains forbidden plaintext mnemonic",
		)
	}

	if _, err := w.validatePublicIdentity(); err != nil {
		return nil, fmt.Errorf(
			"invalid wallet identity: %w",
			err,
		)
	}

	if err := w.validateEncryptedWallet(); err != nil {
		return nil, err
	}

	return &w, nil
}

// ExportEd25519Keys decrypts and returns the Ed25519 keys in hexadecimal.
//
// LEGACY / HIGHLY SENSITIVE API.
// This should eventually be removed from the normal wallet API.
func (w *Wallet) ExportEd25519Keys(
	password string,
) (privHex, pubHex string, err error) {
	if err := w.validateEncryptedWallet(); err != nil {
		return "", "", err
	}

	storedPub, err := w.validatePublicIdentity()
	if err != nil {
		return "", "", err
	}

	defer func() {
		for i := range storedPub {
			storedPub[i] = 0
		}
	}()

	privBytes, _, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		password,
	)
	if err != nil {
		return "", "", errors.New(
			"invalid password or corrupted wallet",
		)
	}

	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	if len(privBytes) != expectedPrivateKeySize {
		return "", "", errors.New(
			"decrypted private key has invalid size",
		)
	}

	priv := ed25519.PrivateKey(privBytes)

	pubRaw := priv.Public()

	pub, ok := pubRaw.(ed25519.PublicKey)
	if !ok || len(pub) != expectedPublicKeySize {
		return "", "", errors.New(
			"failed to derive valid public key",
		)
	}

	if subtle.ConstantTimeCompare(
		pub,
		storedPub,
	) != 1 {
		for i := range pub {
			pub[i] = 0
		}

		return "", "", errors.New(
			"private key does not match wallet identity",
		)
	}

	privHex = hex.EncodeToString(priv)
	pubHex = hex.EncodeToString(pub)

	for i := range pub {
		pub[i] = 0
	}

	return privHex, pubHex, nil
}

// SignTransaction signs the supplied canonical transaction bytes.
func SignTransaction(
	w *Wallet,
	password string,
	txData []byte,
) ([]byte, error) {
	if w == nil {
		return nil, errors.New(
			"wallet is nil",
		)
	}

	if len(txData) == 0 {
		return nil, errors.New(
			"transaction data is empty",
		)
	}

	if err := w.validateEncryptedWallet(); err != nil {
		return nil, err
	}

	storedPub, err := w.validatePublicIdentity()
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range storedPub {
			storedPub[i] = 0
		}
	}()

	privBytes, _, err := encryption.DecryptWallet(
		w.EncryptedPriv,
		password,
	)
	if err != nil {
		return nil, errors.New(
			"invalid password or corrupted wallet",
		)
	}

	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	if len(privBytes) != expectedPrivateKeySize {
		return nil, errors.New(
			"decrypted private key has invalid size",
		)
	}

	priv := ed25519.PrivateKey(privBytes)

	derivedPubRaw := priv.Public()

	derivedPub, ok := derivedPubRaw.(ed25519.PublicKey)
	if !ok || len(derivedPub) != expectedPublicKeySize {
		return nil, errors.New(
			"failed to derive valid public key",
		)
	}

	if subtle.ConstantTimeCompare(
		derivedPub,
		storedPub,
	) != 1 {
		for i := range derivedPub {
			derivedPub[i] = 0
		}

		return nil, errors.New(
			"private key does not match wallet identity",
		)
	}

	signature := ed25519.Sign(
		priv,
		txData,
	)

	for i := range derivedPub {
		derivedPub[i] = 0
	}

	if len(signature) != ed25519.SignatureSize {
		for i := range signature {
			signature[i] = 0
		}

		return nil, errors.New(
			"invalid Ed25519 signature size",
		)
	}

	return signature, nil
}

// PublicKeyBytes returns a copy of the stored public key.
//
// The password parameter remains only for source compatibility.
func (w *Wallet) PublicKeyBytes(
	password string,
) ([]byte, error) {
	_ = password

	if w == nil {
		return nil, errors.New(
			"wallet is nil",
		)
	}

	pub, err := w.validatePublicIdentity()
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(pub))
	copy(result, pub)

	for i := range pub {
		pub[i] = 0
	}

	return result, nil
}

// IsValid performs structural wallet validation without decrypting the
// private key.
func (w *Wallet) IsValid() error {
	if w == nil {
		return errors.New(
			"wallet is nil",
		)
	}

	if w.Mnemonic != "" {
		return errors.New(
			"wallet contains forbidden plaintext mnemonic",
		)
	}

	if _, err := w.validatePublicIdentity(); err != nil {
		return err
	}

	if err := w.validateEncryptedWallet(); err != nil {
		return err
	}

	return nil
}
