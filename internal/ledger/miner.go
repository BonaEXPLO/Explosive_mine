// internal/ledger/miner.go
package ledger

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "crypto/ed25519"
    "errors"
    "fmt"
    "os"
    "regexp"
    "strings"
    "explosive/internal/argon2id" // <-- Argon2id key derivation

    "explosive/internal/address"
    "explosive/internal/encryption"
    "explosive/internal/guardian"

    "golang.org/x/crypto/argon2"
)

// -----------------------------
// Miner structure (V3+ compatible)
// -----------------------------
type Miner struct {
    // -----------------------------
    // Core identity (immutable)
    // -----------------------------
    ID string // Wallet address (explo... = public identity)

    // -----------------------------
    // Local / privacy
    // -----------------------------
    IP string // Local hashed IP (never sent on network)

    // -----------------------------
    // Encrypted identity bundle
    // -----------------------------
    EncryptedBundle []byte // AES-GCM encrypted (ID + 4 words)
    Salt            []byte // Salt used for encryption / Argon2id

    // -----------------------------
    // Consciousness layer
    // -----------------------------
    ConsciousnessFingerprint []string // 4 sacred words (never broadcast)

    // -----------------------------
    // 🔐 V3+ Cryptographic identity (NEW)
    // -----------------------------
    PubKey    []byte // Ed25519 public key derived from ID + 4 words
    Signature []byte // Ed25519 signature of canonical miner identity

    // -----------------------------
    // 🔁 Compatibility / migration
    // -----------------------------
    Version uint8 // 0 = legacy, 3 = V3 deterministic identity
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
// CreateMiner creates a new miner account with the given wallet ID, password, and sacred words.
// It performs the following steps:
// 1. Validates the miner ID, password format, and sacred words.
// 2. Ensures sacred words uniqueness across local device (guardian).
// 3. Normalizes and registers the fingerprint.
// 4. Encrypts the identity bundle (ID + words) using AES-GCM + HMAC.
// 5. Creates the Miner struct.
// 6. Ensures V3 identity signature (derive Ed25519 key from ID + words, sign).
// 7. Stores the miner in the ledger if provided.
// Returns the Miner struct and an ephemeral encouragement message for UX.
func CreateMiner(id, password string, words []string, ipOrHash string, ledger *Ledger) (*Miner, string, error) {
    // -----------------------------
    // 1️⃣ Validate input
    // -----------------------------
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidPassword(password) {
        return nil, "", errors.New("password must have ≥8 chars, include upper, lower, digit, and symbol")
    }
    if !IsValidSacredWords(words) {
        return nil, "", errors.New("invalid sacred words (must be 4 words, each starting with uppercase)")
    }

    // ✅ Step 1: Device lock check (currently disabled)
    //if err := guardian.CanCreateNewAccount(); err != nil { //return nil, "", err //}

    words = normalizeWords(words)

    // -----------------------------
    // 2️⃣ Ensure fingerprint uniqueness
    // -----------------------------
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

    // -----------------------------
    // 3️⃣ Encrypt identity bundle
    // -----------------------------
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
        bundleJSON[i] = 0 // Clear sensitive bytes
    }

    msg := guardian.EncourageMessageEphemeral(words)

    // -----------------------------
    // 4️⃣ Create Miner struct
    // -----------------------------
    miner := &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }

    // -----------------------------
    // 5️⃣ Ensure V3 identity signature (Ed25519 key derived from ID + words)
    // -----------------------------
    if err := EnsureMinerSignature(miner); err != nil {
        return nil, "", err
    }

    // -----------------------------
    // 6️⃣ Store miner in ledger if provided
    // -----------------------------
    if ledger != nil {
        key := []byte("miner:" + id)
        _ = ledger.PutObject(key, miner)
    }

    // ✅ Step 2: Register local device lock (currently disabled)
    //if err := guardian.RegisterDeviceLock(id); err != nil { // return nil, "", fmt.Errorf("failed to register device lock: %w", err) //}

    return miner, msg, nil
}

// -----------------------------
// Restore miner account (legacy + V3 compatible)
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
    msg := guardian.EncourageMessageEphemeral(words)
    var miner *Miner

    // 1️⃣ Try to load from Ledger (allow restoration)
    if ledger != nil {
        key := []byte("miner:" + id)
        var existing Miner
        _ = ledger.GetObject(key, &existing)

        if existing.ID == id && equalWords(existing.ConsciousnessFingerprint, words) {
            // Ensure deterministic V3 signature is present
            if err := EnsureMinerSignature(&existing); err != nil {
                return nil, "", fmt.Errorf("failed to upgrade miner to V3 deterministic identity: %w", err)
            }

            // Re-encrypt bundle with new password (restore on new device)
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

            existing.EncryptedBundle = encrypted
            existing.Salt = salt

            _ = ledger.PutObject(key, &existing)
            return &existing, msg, nil
        }
    }

    // 2️⃣ No existing miner → create a fresh miner
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

    miner = &Miner{
        ID:                       id,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: words,
    }

    // Immediately apply deterministic V3 identity
    if err := EnsureMinerSignature(miner); err != nil {
        return nil, "", fmt.Errorf("failed to generate V3 identity: %w", err)
    }

    if ledger != nil {
        key := []byte("miner:" + id)
        _ = ledger.PutObject(key, miner)
    }

    return miner, msg, nil
}

// DeriveMinerKey deterministically derives an Ed25519 key pair
// from the miner's public identity (wallet address) and the
// miner's private consciousness fingerprint (4 sacred words).
//
// Security properties:
// - Deterministic: the same (ID + words) always yields the same key
// - Stateless: no private key is ever stored on disk
// - Device-agnostic: allows restoration on any device
// - Memory-hard: Argon2id resists GPU/ASIC brute-force attacks
//
// The derived private key MUST never be transmitted or persisted.
func DeriveMinerKey(id string, words []string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
    // Canonical identity input (order and separator are critical)
    input := []byte(id + "|" + strings.Join(words, "|"))

    // Domain-separated salt to prevent cross-protocol key reuse
    salt := []byte("EXPLOSIVE-MINER-V3")

    // Argon2id parameters tuned for interactive / mobile security
    params := argon2id.DefaultParameters("medium")

    // Derive a 32-byte deterministic seed
    seed := argon2.IDKey(
        input,
        salt,
        params.Time,
        params.Memory,
        params.Threads,
        32,
    )

    // Generate Ed25519 key pair from the derived seed
    priv := ed25519.NewKeyFromSeed(seed)
    pub := priv.Public().(ed25519.PublicKey)

    return priv, pub, nil
}
// SignMinerIdentity cryptographically binds the miner's identity
// (wallet address + consciousness fingerprint) to an Ed25519 signature.
//
// The signature proves that the miner knows the secret 4-word
// consciousness fingerprint associated with the public ID.
//
// This signature is safe to broadcast and store.
func SignMinerIdentity(m *Miner, priv ed25519.PrivateKey) {
    // Canonical message format — MUST remain stable across versions
    msg := []byte("MINER|" + m.ID + "|" + strings.Join(m.ConsciousnessFingerprint, "|"))

    // Sign the identity using the miner's deterministic private key
    m.Signature = ed25519.Sign(priv, msg)
}

// EnsureMinerSignature guarantees that a miner has a valid Ed25519 public key
// and a signature proving knowledge of the consciousness fingerprint.
//
// Behavior:
// - If already signed and complete → accept as-is
// - Otherwise → derive key from ID + 4 sacred words
// - Always attach PubKey and Signature (for block signing and P2P auth)
// - NO fatal error if derived address != declared ID
//   → This allows full compatibility with external BIP39 wallets
//   → The signature still proves possession of the secret words
//
// This function MUST be called before:
// - mining
// - block signing
// - P2P authentication
func EnsureMinerSignature(m *Miner) error {
    // Already signed and complete → accept
    if len(m.PubKey) == ed25519.PublicKeySize && len(m.Signature) > 0 {
        return nil
    }

    // Deterministically derive the miner key from ID + secret words
    priv, pub, err := DeriveMinerKey(m.ID, m.ConsciousnessFingerprint)
    if err != nil {
        return err
    }

    // Attach the derived public key (used for block signature verification)
    m.PubKey = pub

    // Sign the canonical identity to prove knowledge of the 4 sacred words
    SignMinerIdentity(m, priv)

    // Note: We intentionally do NOT fail if derived address != m.ID
    // This enables compatibility with external BIP39-derived wallets
    // The signature itself provides strong proof of secret knowledge

    return nil
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
        Words: [4]string{
            miner.ConsciousnessFingerprint[0],
            miner.ConsciousnessFingerprint[1],
            miner.ConsciousnessFingerprint[2],
            miner.ConsciousnessFingerprint[3],
        },
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

// -----------------------------
// Restore miner backup
// -----------------------------
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

    // ✅ Ensure miner has deterministic public key + signature
    if err := EnsureMinerSignature(miner); err != nil {
        return nil, fmt.Errorf("failed to ensure miner signature: %w", err)
    }

    return miner, nil
}
