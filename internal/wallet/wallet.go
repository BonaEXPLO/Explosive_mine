// internal/wallet/wallet.go
package wallet

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"

    "github.com/fxamacker/cbor/v2"
    "github.com/tyler-smith/go-bip39"

    "explosive/internal/address"
    "explosive/internal/encryption"
)

// Wallet represents a user wallet for the EXPLOSIVE blockchain.
type Wallet struct {
    PublicKeyHex  string                     `cbor:"public_key_hex"`
    Address       string                     `cbor:"address"`
    Mnemonic      string                     `cbor:"mnemonic,omitempty"` // Deprecated
    EncryptedPriv *encryption.EncryptedWallet `cbor:"encrypted_priv"`

    BalanceEXP float64 `cbor:"balance_exp"`
    BalanceIM  float64 `cbor:"balance_im"`
}

// validatePassword ensures a strong password policy.
func validatePassword(password string) error {
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters")
    }
    var hasUpper, hasLower, hasDigit, hasSymbol bool
    for _, c := range password {
        switch {
        case 'A' <= c && c <= 'Z':
            hasUpper = true
        case 'a' <= c && c <= 'z':
            hasLower = true
        case '0' <= c && c <= '9':
            hasDigit = true
        case strings.ContainsRune("!@#$%^&*()-_=+[]{}<>?/|", c):
            hasSymbol = true
        }
    }
    if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
        return errors.New("password must include uppercase, lowercase, digit, and symbol")
    }
    return nil
}

// CreateWallet generates a new wallet and encrypts the private key + mnemonic.
func CreateWallet(password string) (*Wallet, error) {
    if err := validatePassword(password); err != nil {
        return nil, err
    }

    entropy, err := bip39.NewEntropy(256)
    if err != nil {
        return nil, fmt.Errorf("failed to generate entropy: %w", err)
    }

    mnemonic, err := bip39.NewMnemonic(entropy)
    if err != nil {
        return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
    }

    seed := bip39.NewSeed(mnemonic, "")
    priv := ed25519.NewKeyFromSeed(seed[:32])
    pub := priv.Public().(ed25519.PublicKey)

    addr := address.GenerateEXPLOAddress(pub)

    encPriv, err := encryption.EncryptWallet(priv, mnemonic, password)
    for i := range priv {
        priv[i] = 0
    }
    if err != nil {
        return nil, err
    }

    return &Wallet{
        PublicKeyHex:  hex.EncodeToString(pub),
        Address:       addr,
        Mnemonic:      "",
        EncryptedPriv: encPriv,
        BalanceEXP:    0,
        BalanceIM:     0,
    }, nil
}

// RestoreWalletByMnemonic restores a wallet from a mnemonic.
func RestoreWalletByMnemonic(mnemonic, password string) (*Wallet, error) {
    if !bip39.IsMnemonicValid(mnemonic) {
        return nil, errors.New("invalid mnemonic")
    }
    if err := validatePassword(password); err != nil {
        return nil, err
    }

    seed := bip39.NewSeed(mnemonic, "")
    priv := ed25519.NewKeyFromSeed(seed[:32])
    pub := priv.Public().(ed25519.PublicKey)
    addr := address.GenerateEXPLOAddress(pub)

    encPriv, err := encryption.EncryptWallet(priv, mnemonic, password)
    for i := range priv {
        priv[i] = 0
    }
    if err != nil {
        return nil, err
    }

    return &Wallet{
        PublicKeyHex:  hex.EncodeToString(pub),
        Address:       addr,
        Mnemonic:      "",
        EncryptedPriv: encPriv,
        BalanceEXP:    0,
        BalanceIM:     0,
    }, nil
}

// RevealMnemonic returns the mnemonic if password is correct.
func (w *Wallet) RevealMnemonic(password string) (string, error) {
    if w.EncryptedPriv == nil {
        return "", errors.New("no encrypted data available")
    }
    _, mnemonic, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return "", err
    }
    return mnemonic, nil
}

// ChangePassword updates the wallet password.
func (w *Wallet) ChangePassword(oldPassword, newPassword string) error {
    if w.EncryptedPriv == nil {
        return errors.New("no encrypted data available")
    }
    if err := validatePassword(newPassword); err != nil {
        return errors.New("new password does not meet strength requirements")
    }

    priv, mnemonic, err := encryption.DecryptWallet(w.EncryptedPriv, oldPassword)
    if err != nil {
        return errors.New("old password incorrect")
    }

    newEnc, err := encryption.EncryptWallet(priv, mnemonic, newPassword)
    for i := range priv {
        priv[i] = 0
    }
    if err != nil {
        return fmt.Errorf("failed to re-encrypt wallet: %w", err)
    }
    w.EncryptedPriv = newEnc
    return nil
}

// DeleteWallet securely erases wallet after verification.
func (w *Wallet) DeleteWallet(mnemonic, password string) error {
    if w.EncryptedPriv == nil {
        return errors.New("no encrypted data available")
    }
    priv, storedMnemonic, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return errors.New("invalid password or corrupted data")
    }
    for i := range priv {
        priv[i] = 0
    }

    if mnemonic != storedMnemonic {
        return errors.New("mnemonic does not match")
    }

    *w = Wallet{}
    return nil
}

// ToCBORLine serializes wallet to CBOR + base64.
func (w *Wallet) ToCBORLine() (string, error) {
    data, err := cbor.Marshal(w)
    if err != nil {
        return "", fmt.Errorf("failed to serialize wallet: %w", err)
    }
    return base64.StdEncoding.EncodeToString(data), nil
}

// FromCBORLine deserializes base64 CBOR into wallet.
func FromCBORLine(line string) (*Wallet, error) {
    raw, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
        return nil, fmt.Errorf("failed to decode base64: %w", err)
    }
    var w Wallet
    if err := cbor.Unmarshal(raw, &w); err != nil {
        return nil, fmt.Errorf("failed to deserialize wallet: %w", err)
    }
    return &w, nil
}

// ExportEd25519Keys decrypts and returns keys in hex.
func (w *Wallet) ExportEd25519Keys(password string) (privHex, pubHex string, err error) {
    if w.EncryptedPriv == nil {
        return "", "", errors.New("no encrypted data in wallet")
    }

    privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return "", "", fmt.Errorf("failed to decrypt wallet: %w", err)
    }
    defer func() {
        for i := range privBytes {
            privBytes[i] = 0
        }
    }()

    priv := ed25519.PrivateKey(privBytes)
    pub := priv.Public().(ed25519.PublicKey)
    return hex.EncodeToString(priv), hex.EncodeToString(pub), nil
}

// SignTransaction signs txData using wallet's private key with HMAC check.
// Now returns the raw signature bytes ([]byte) instead of a hex string.
func SignTransaction(w *Wallet, password string, txData []byte) ([]byte, error) {
    if w.EncryptedPriv == nil {
        return nil, errors.New("wallet has no encrypted private key")
    }

    // DecryptWallet returns (privBytes, mnemonic, error) and validates HMAC internally
    privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        // HMAC mismatch or incorrect password triggers this
        return nil, fmt.Errorf("failed to decrypt private key: %w", err)
    }
    // Always zero private key after usage
    defer func() {
        for i := range privBytes {
            privBytes[i] = 0
        }
    }()

    // Ensure private key length is exactly 64 bytes for ed25519
    if len(privBytes) != ed25519.PrivateKeySize {
        return nil, errors.New("decrypted private key has invalid size")
    }

    priv := ed25519.PrivateKey(privBytes)
    signature := ed25519.Sign(priv, txData)

    // Return raw signature bytes (64 bytes)
    return signature, nil
}

// PublicKeyBytes returns the public key of the wallet as a byte slice.
// It temporarily decrypts the private key to derive the public key.
// ⚠️ Currently uses a dummy password for decryption; this will fail if the encryption checks the password.
func (w *Wallet) PublicKeyBytes(password string) ([]byte, error) {
    if w.EncryptedPriv == nil {
        return nil, errors.New("no encrypted private key available")
    }

    privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt private key: %w", err)
    }
    defer func() { for i := range privBytes { privBytes[i] = 0 } }()

    priv := ed25519.PrivateKey(privBytes)
    pub := priv.Public().(ed25519.PublicKey)
    return pub, nil
}
