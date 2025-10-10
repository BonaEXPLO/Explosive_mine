// internal/wallet/wallet.go
package wallet

import (
    "crypto/ed25519"
    "encoding/hex"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "github.com/tyler-smith/go-bip39"
    "github.com/fxamacker/cbor/v2" // <-- CBOR library
    "explosive/internal/address"
)

// Wallet represents a user wallet for the EXPLOSIVE blockchain.
// The mnemonic is no longer stored in plaintext; it is stored encrypted inside EncryptedPriv.
type Wallet struct {
    PublicKeyHex  string           `cbor:"public_key_hex"`  // hex encoded public key
    Address       string           `cbor:"address"`
    Mnemonic      string           `cbor:"mnemonic,omitempty"` // Deprecated, never stored plaintext
    EncryptedPriv *EncryptedWallet `cbor:"encrypted_priv"`      // Encrypted private key + mnemonic

    // For Ledger synchronization
    BalanceEXP float64 `cbor:"balance_exp"`
    BalanceIM  float64 `cbor:"balance_im"`
}

// validatePassword enforces a strong password policy for NEW passwords.
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

// CreateWallet creates a new wallet, encrypts the private key + mnemonic using the password.
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

    encPriv, err := EncryptWallet(priv, mnemonic, password)
    if err != nil {
        return nil, err
    }

    // Zero sensitive memory
    for i := range priv {
        priv[i] = 0
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

// RestoreWalletByMnemonic restores wallet from mnemonic and encrypts it with password.
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

    encPriv, err := EncryptWallet(priv, mnemonic, password)
    if err != nil {
        return nil, err
    }

    for i := range priv {
        priv[i] = 0
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

// RevealMnemonic returns the mnemonic only if the provided password decrypts the encrypted blob.
func (w *Wallet) RevealMnemonic(password string) (string, error) {
    if w.EncryptedPriv == nil {
        return "", errors.New("no encrypted data available")
    }
    _, mnemonic, err := DecryptWallet(w.EncryptedPriv, password)
    if err != nil {
        return "", err
    }
    return mnemonic, nil
}

// ChangePassword changes encryption password by decrypting with old password and re-encrypting with new.
func (w *Wallet) ChangePassword(oldPassword, newPassword string) error {
    if w.EncryptedPriv == nil {
        return errors.New("no encrypted data available")
    }
    if err := validatePassword(newPassword); err != nil {
        return errors.New("new password does not meet strength requirements")
    }

    priv, mnemonic, err := DecryptWallet(w.EncryptedPriv, oldPassword)
    if err != nil {
        return errors.New("old password incorrect")
    }

    newEnc, err := EncryptWallet(priv, mnemonic, newPassword)
    for i := range priv {
        priv[i] = 0
    }
    if err != nil {
        return fmt.Errorf("failed to re-encrypt wallet: %w", err)
    }
    w.EncryptedPriv = newEnc
    return nil
}

// DeleteWallet securely erases the wallet if the user proves ownership.
func (w *Wallet) DeleteWallet(mnemonic, password string) error {
    if w.EncryptedPriv == nil {
        return errors.New("no encrypted data available")
    }
    priv, storedMnemonic, err := DecryptWallet(w.EncryptedPriv, password)
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

// ToCBORLine serializes wallet to CBOR and encodes as base64 for line-based logs.
func (w *Wallet) ToCBORLine() (string, error) {
    data, err := cbor.Marshal(w)
    if err != nil {
        return "", fmt.Errorf("failed to serialize wallet: %w", err)
    }
    return base64.StdEncoding.EncodeToString(data), nil
}

// FromCBORLine deserializes a base64 CBOR line into a Wallet.
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
