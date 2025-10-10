// internal/ledger/miner.go
package ledger

import (
    "crypto/rand"
    "encoding/json"
    "errors"
    "fmt"
    "regexp"
    "strings"
    "unicode"

    "explosive/internal/address"
    "explosive/internal/encryption"
    "explosive/internal/guardian"
)

// Miner represents a mining account in EXPLOSIVE Network.
// ID = wallet address starting with "explo", 40 hex + 8 hex checksum = 53 chars
type Miner struct {
    ID                       string   // Wallet address
    EncryptedBundle          []byte   // AES-GCM + HMAC encrypted bundle (JSON: ID + 4 words)
    Salt                     []byte   // Salt for password-based encryption
    ConsciousnessFingerprint []string // 4 sacred words chosen by miner
}

// -----------------------------
// Password validation
// -----------------------------
func IsValidPassword(password string) bool {
    if len(password) < 8 {
        return false
    }
    upper := regexp.MustCompile(`[A-Z]`).MatchString(password)
    lower := regexp.MustCompile(`[a-z]`).MatchString(password)
    digit := regexp.MustCompile(`[0-9]`).MatchString(password)
    symbol := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)
    return upper && lower && digit && symbol
}

// -----------------------------
// Sacred words validation
// -----------------------------
func IsValidSacredWords(words []string) bool {
    if len(words) != 4 {
        return false
    }
    for _, w := range words {
        if !IsValidSacredWordFormat(w) {
            return false
        }
    }
    return true
}

// Accept words starting with uppercase, allow letters, '-', and spaces for compound words
func IsValidSacredWordFormat(word string) bool {
    word = cleanWord(strings.TrimSpace(word))
    if len(word) < 1 {
        return false
    }
    re := regexp.MustCompile(`^[A-Z][A-Za-z -]*$`)
    return re.MatchString(word)
}

// cleanWord removes invisible characters and non-printable Unicode
func cleanWord(word string) string {
    var b strings.Builder
    for _, r := range word {
        if !unicode.IsSpace(r) || r == ' ' {
            if r != '\r' && r != '\n' {
                b.WriteRune(r)
            }
        }
    }
    return b.String()
}

// Normalize words: trim spaces and clean
func normalizeWords(words []string) []string {
    out := make([]string, len(words))
    for i, w := range words {
        out[i] = cleanWord(strings.TrimSpace(w))
    }
    return out
}

// -----------------------------
// Create miner account
// -----------------------------
func CreateMiner(id, password string, words []string) (*Miner, string, error) {
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidPassword(password) {
        return nil, "", errors.New("password must have ≥8 chars, include upper, lower, digit, symbol")
    }
    if !IsValidSacredWords(words) {
        return nil, "", errors.New("invalid sacred words (must be 4 words, each starting with uppercase)")
    }

    words = normalizeWords(words)

    // Prevent duplicate sacred words fingerprint
    // Prevent duplicate sacred words fingerprint
dup, err := guardian.IsDuplicateFingerprint(words)
if err != nil {
    return nil, "", fmt.Errorf("failed to check fingerprint duplication: %w", err)
}
if dup {
    return nil, "", errors.New("these sacred words are already used by another miner")
}
    if err := guardian.RegisterFingerprint(words); err != nil {
        return nil, "", fmt.Errorf("failed to register sacred fingerprint: %w", err)
    }

    // Generate salt for encryption
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", fmt.Errorf("failed to generate salt: %w", err)
    }

    // Bundle JSON
    bundle := map[string]interface{}{
        "id":    id,
        "words": words,
    }
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return nil, "", fmt.Errorf("failed to marshal identity bundle: %w", err)
    }

    // Encrypt bundle with password-derived key
    encrypted, err := encryption.EncryptBundle(bundleJSON, password, salt)
    if err != nil {
        return nil, "", fmt.Errorf("failed to encrypt identity bundle: %w", err)
    }

    // Zero-out sensitive slice
    for i := range bundleJSON {
        bundleJSON[i] = 0
    }

    msg := guardian.EncourageMessageEphemeral(words)

    return &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }, msg, nil
}

// -----------------------------
// Restore miner (ID + 4 words)
// -----------------------------
func RestoreMiner(id string, words []string, newPassword string) (*Miner, string, error) {
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidSacredWords(words) {
        return nil, "", errors.New("invalid sacred words")
    }
    if !IsValidPassword(newPassword) {
        return nil, "", errors.New("new password must have ≥8 chars, include upper, lower, digit, symbol")
    }

    words = normalizeWords(words)

    // Generate new salt for encryption
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", fmt.Errorf("failed to generate salt: %w", err)
    }

    // Create new encrypted bundle
    bundle := map[string]interface{}{
        "id":    id,
        "words": words,
    }
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return nil, "", fmt.Errorf("failed to marshal identity bundle: %w", err)
    }

    encrypted, err := encryption.EncryptBundle(bundleJSON, newPassword, salt)
    if err != nil {
        return nil, "", fmt.Errorf("failed to encrypt identity bundle: %w", err)
    }

    for i := range bundleJSON {
        bundleJSON[i] = 0
    }

    msg := guardian.EncourageMessageEphemeral(words)

    return &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }, msg, nil
}

// -----------------------------
// Delete miner
// -----------------------------
func DeleteMiner(words []string, m *Miner) error {
    if !IsValidSacredWords(words) {
        return errors.New("invalid sacred words")
    }

    words = normalizeWords(words)
    m.ConsciousnessFingerprint = normalizeWords(m.ConsciousnessFingerprint)

    for i := 0; i < 4; i++ {
        if m.ConsciousnessFingerprint[i] != words[i] {
            return errors.New("sacred words do not match")
        }
    }

    // Zero-out encrypted bundle
    for i := range m.EncryptedBundle {
        m.EncryptedBundle[i] = 0
    }

    return nil
}

// -----------------------------
// Change password after restoration (no old password needed)
// -----------------------------
func (m *Miner) ChangePasswordAfterRestore(newPassword string) error {
    if !IsValidPassword(newPassword) {
        return errors.New("new password must have ≥8 chars, include upper, lower, digit, symbol")
    }

    bundle := map[string]interface{}{
        "id":    m.ID,
        "words": m.ConsciousnessFingerprint,
    }
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return fmt.Errorf("failed to marshal identity bundle: %w", err)
    }

    newSalt := make([]byte, 16)
    if _, err := rand.Read(newSalt); err != nil {
        return fmt.Errorf("failed to generate new salt: %w", err)
    }

    newEncrypted, err := encryption.EncryptBundle(bundleJSON, newPassword, newSalt)
    if err != nil {
        return fmt.Errorf("failed to encrypt with new password: %w", err)
    }

    for i := range bundleJSON {
        bundleJSON[i] = 0
    }

    m.EncryptedBundle = newEncrypted
    m.Salt = newSalt
    return nil
}

// -----------------------------
// Change password with old password verification
// -----------------------------
func (m *Miner) ChangePasswordWithOld(oldPassword, newPassword string) error {
    if !IsValidPassword(newPassword) {
        return errors.New("new password must have ≥8 chars, include upper, lower, digit, symbol")
    }

    decrypted, err := encryption.DecryptBundle(m.EncryptedBundle, oldPassword, m.Salt)
    if err != nil {
        return errors.New("invalid old password")
    }

    newSalt := make([]byte, 16)
    if _, err := rand.Read(newSalt); err != nil {
        return fmt.Errorf("failed to generate new salt: %w", err)
    }

    newEncrypted, err := encryption.EncryptBundle(decrypted, newPassword, newSalt)
    if err != nil {
        return fmt.Errorf("failed to encrypt with new password: %w", err)
    }

    for i := range decrypted {
        decrypted[i] = 0
    }

    m.EncryptedBundle = newEncrypted
    m.Salt = newSalt
    return nil
}

// -----------------------------
// Utilities
// -----------------------------
func FingerprintHash(words []string) string {
    return encryption.Sha3Hex([]byte(strings.Join(words, "-")))
}

// IsValidMinerID vérifie si une adresse EXPLO est valide (wrapper de address.IsValidMinerID)
func IsValidMinerID(addr string) bool {
    return address.IsValidMinerID(addr)
}

