// internal/ledger/miner.go
package ledger

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "regexp"
    "strings"

    "explosive/internal/address"
    "explosive/internal/encryption"
    "explosive/internal/guardian"

    "golang.org/x/crypto/argon2"
)

// -----------------------------
// Miner structure
// -----------------------------
type Miner struct {
    ID                       string   // Wallet address
    IP                       string   // Local hashed IP (never sent on network)
    EncryptedBundle          []byte   // AES-GCM + HMAC encrypted bundle
    Salt                     []byte   // Salt for password-based encryption
    ConsciousnessFingerprint []string // 4 sacred words
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

func IsValidSacredWordFormat(word string) bool {
    word = cleanWord(strings.TrimSpace(word))
    if len(word) < 1 {
        return false
    }
    re := regexp.MustCompile(`^[A-Z][A-Za-z -]*$`)
    return re.MatchString(word)
}

func cleanWord(word string) string {
    var b strings.Builder
    for _, r := range word {
        if r != '\r' && r != '\n' {
            b.WriteRune(r)
        }
    }
    return strings.TrimSpace(b.String())
}

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
func CreateMiner(id, password string, words []string, ipOrHash string, ledger *Ledger) (*Miner, string, error) {
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidPassword(password) {
        return nil, "", errors.New("password must have ≥8 chars, include upper, lower, digit, and symbol")
    }
    if !IsValidSacredWords(words) {
        return nil, "", errors.New("invalid sacred words (must be 4 words, each starting with uppercase)")
    }

    // ✅ Step 1: Device lock check
    //if err := guardian.CanCreateNewAccount(); err != nil { //return nil, "", err //}

    words = normalizeWords(words)

    // Ensure fingerprint uniqueness
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

    // Encrypt bundle (id + words)
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", fmt.Errorf("failed to generate salt: %w", err)
    }

    bundle := map[string]interface{}{"id": id, "words": words}
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return nil, "", fmt.Errorf("failed to marshal identity bundle: %w", err)
    }

    encrypted, err := encryption.EncryptBundle(bundleJSON, password, salt)
    if err != nil {
        return nil, "", fmt.Errorf("failed to encrypt identity bundle: %w", err)
    }

    for i := range bundleJSON {
        bundleJSON[i] = 0
    }

    msg := guardian.EncourageMessageEphemeral(words)

    miner := &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }

    if ledger != nil {
        key := []byte("miner:" + id)
        _ = ledger.PutObject(key, miner)
    }

    // ✅ Step 2: Register local device lock
    //if err := guardian.RegisterDeviceLock(id); err != nil { // return nil, "", fmt.Errorf("failed to register device lock: %w", err) //}

    return miner, msg, nil
}

// -----------------------------
// Restore miner account
// -----------------------------
func RestoreMiner(id string, words []string, newPassword string, ledger *Ledger) (*Miner, string, error) {
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidSacredWords(words) {
        return nil, "", errors.New("invalid sacred words")
    }
    if !IsValidPassword(newPassword) {
        return nil, "", errors.New("invalid new password format")
    }

    words = normalizeWords(words)
    var existing Miner

    // Try to load from Ledger (allow restoration)
    if ledger != nil {
        key := []byte("miner:" + id)
        _ = ledger.GetObject(key, &existing)
        if existing.ID == id && equalWords(existing.ConsciousnessFingerprint, words) {
            return &existing, guardian.EncourageMessageEphemeral(words), nil
        }
    }

    // Otherwise recreate local miner structure (for backward compatibility)
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", fmt.Errorf("failed to generate salt: %w", err)
    }

    bundle := map[string]interface{}{"id": id, "words": words}
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return nil, "", fmt.Errorf("failed to marshal identity bundle: %w", err)
    }

    encrypted, err := encryption.EncryptBundle(bundleJSON, newPassword, salt)
    if err != nil {
        return nil, "", fmt.Errorf("failed to encrypt bundle: %w", err)
    }

    msg := guardian.EncourageMessageEphemeral(words)

    miner := &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }

    if ledger != nil {
        key := []byte("miner:" + id)
        _ = ledger.PutObject(key, miner)
    }

    return miner, msg, nil
}

// -----------------------------
// Delete miner securely
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

    for i := range m.EncryptedBundle {
        m.EncryptedBundle[i] = 0
    }

    return nil
}

// -----------------------------
// Password change
// -----------------------------
func (m *Miner) ChangePasswordAfterRestore(newPassword string) error {
    if !IsValidPassword(newPassword) {
        return errors.New("new password must have ≥8 chars, include upper, lower, digit, symbol")
    }

    bundle := map[string]interface{}{"id": m.ID, "words": m.ConsciousnessFingerprint}
    bundleJSON, err := json.Marshal(bundle)
    if err != nil {
        return fmt.Errorf("failed to marshal bundle: %w", err)
    }

    newSalt := make([]byte, 16)
    if _, err := rand.Read(newSalt); err != nil {
        return fmt.Errorf("failed to generate salt: %w", err)
    }

    newEncrypted, err := encryption.EncryptBundle(bundleJSON, newPassword, newSalt)
    if err != nil {
        return fmt.Errorf("failed to re-encrypt bundle: %w", err)
    }

    for i := range bundleJSON {
        bundleJSON[i] = 0
    }

    m.EncryptedBundle = newEncrypted
    m.Salt = newSalt
    return nil
}

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

func IsValidMinerID(addr string) bool {
    return address.IsValidMinerID(addr)
}

func equalWords(a, b []string) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// -----------------------------
// Backup using Argon2id + AES-GCM (password optional)
// -----------------------------
func ExportMinerBackup(miner *Miner, password, outputPath string) error {
    type backupData struct {
        ID    string    `json:"id"`
        Words [4]string `json:"words"`
    }

    data := backupData{
        ID:    miner.ID,
        Words: [4]string{miner.ConsciousnessFingerprint[0], miner.ConsciousnessFingerprint[1], miner.ConsciousnessFingerprint[2], miner.ConsciousnessFingerprint[3]},
    }

    jsonBytes, err := json.Marshal(data)
    if err != nil {
        return fmt.Errorf("marshal backup: %w", err)
    }

    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return fmt.Errorf("generate salt: %w", err)
    }

    // Use password if provided, else deterministic key from ID
    keySource := []byte(miner.ID)
    if password != "" {
        keySource = []byte(password)
    }

    key := argon2.IDKey(keySource, salt, 3, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return fmt.Errorf("AES cipher: %w", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return fmt.Errorf("AES-GCM: %w", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return fmt.Errorf("generate nonce: %w", err)
    }

    ciphertext := gcm.Seal(nonce, nonce, jsonBytes, nil)
    final := append(salt, ciphertext...)

    if err := os.WriteFile(outputPath, final, 0600); err != nil {
        return fmt.Errorf("write backup file: %w", err)
    }

    return nil
}

func RestoreMinerBackup(password, inputPath string) (*Miner, error) {
    fileBytes, err := os.ReadFile(inputPath)
    if err != nil {
        return nil, fmt.Errorf("read backup: %w", err)
    }

    if len(fileBytes) < 16 {
        return nil, fmt.Errorf("backup too short")
    }

    salt := fileBytes[:16]
    ciphertext := fileBytes[16:]

    // First try with provided password
    keySource := []byte(password)
    key := argon2.IDKey(keySource, salt, 3, 64*1024, 4, 32)

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("AES cipher: %w", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("AES-GCM: %w", err)
    }

    if len(ciphertext) < gcm.NonceSize() {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce := ciphertext[:gcm.NonceSize()]
    encryptedData := ciphertext[gcm.NonceSize():]

    jsonBytes, err := gcm.Open(nil, nonce, encryptedData, nil)
    if err != nil {
        // If password failed or empty, retry using deterministic key from ID
        // We assume the ID is stored in plaintext somewhere for this deterministic recovery
        // Here we brute-force using Argon2id with common passwords? No, instead we just require ID
        return nil, fmt.Errorf("cannot decrypt backup: %w", err)
    }

    type backupData struct {
        ID    string    `json:"id"`
        Words [4]string `json:"words"`
    }

    var data backupData
    if err := json.Unmarshal(jsonBytes, &data); err != nil {
        return nil, fmt.Errorf("unmarshal backup: %w", err)
    }

    miner := &Miner{
        ID:                       data.ID,
        ConsciousnessFingerprint: []string{data.Words[0], data.Words[1], data.Words[2], data.Words[3]},
    }

    return miner, nil
}
