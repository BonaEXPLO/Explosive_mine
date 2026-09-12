package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
        "regexp"
	"errors"
        "encoding/hex"
	"runtime/debug"
	"log"
	"fmt"
	"os"
	"strings"

	"explosive/internal/address"
	"explosive/internal/encryption"
	"explosive/internal/guardian"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
)

// Signer defines the interface for cryptographic signing (currently Ed25519, potentially post-quantum in the future)
type Signer interface {
	Sign(msg []byte) []byte
	Public() []byte
}

// Miner represents a miner identity (ON-CHAIN SAFE).
// ⚠ Sacred words are NEVER stored in plaintext here — only encrypted locally and referenced by hash on-chain.
type Miner struct {
	ID                       string   // Public EXPLO address
	IP                       string   // Local hashed IP (never broadcast)

	EncryptedBundle          []byte   // Encrypted local identity bundle
	Salt                     []byte
        ConsciousnessFingerprint []string // 4 sacred words (never broadcast)
	PubKey                   []byte
	Signature                []byte
	Version                  uint8    // 3 = deterministic V3

	FingerprintHash          string   // On-chain hash reference
}

// fingerprintBundle is used for CBOR marshal/unmarshal of the identity
type fingerprintBundle struct {
	ID    string   `cbor:"id"`
	Words []string `cbor:"words"`
}

// IsValidPassword checks password strength.
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

// cleanWord removes \r and \n characters (kept for strict compatibility)
func cleanWord(word string) string {
	var b strings.Builder
	for _, r := range word {
		if r != '\r' && r != '\n' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// prepareWords lightly cleans words before passing them to guardian
func prepareWords(words []string) []string {
	prepared := make([]string, len(words))
	for i, w := range words {
		prepared[i] = cleanWord(w)
	}
	return prepared
}

// IsValidSacredWords fully delegates validation to guardian (single source of truth)
func IsValidSacredWords(words []string) bool {
	if len(words) != 4 {
		return false
	}
	prepared := prepareWords(words)
	_, err := guardian.FingerprintHash(prepared)
	return err == nil
}

// CreateMiner creates a new miner account (LOCAL SAFE).
func CreateMiner(id, password string, words []string, ipHash string, ledger *Ledger) (*Miner, string, error) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("[PANIC RECOVER in CreateMiner] %v", r)
            debug.PrintStack()
        }
    }()

    if ledger == nil {
        return nil, "", errors.New("ledger required")
    }

    // 1️⃣ Validate identity inputs
    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidPassword(password) {
        return nil, "", errors.New("invalid password format")
    }

    preparedWords := prepareWords(words)

    // guardian = single source of truth
    fpHash, err := guardian.FingerprintHash(preparedWords)
    if err != nil {
        return nil, "", fmt.Errorf("invalid sacred words: %w", err)
    }

    normalizedWords := guardian.NormalizeWords(preparedWords)

    // 2️⃣ Prevent local duplication
    dup, err := guardian.IsDuplicateFingerprint(normalizedWords)
    if err != nil {
        return nil, "", err
    }
    if dup {
        return nil, "", errors.New("sacred words already used locally")
    }

    // 3️⃣ Register locally (NOT on-chain registration)
    fpHash, err = guardian.RegisterFingerprintLocal(normalizedWords)
    if err != nil {
        return nil, "", err
    }

    // 4️⃣ Encrypt deterministic identity bundle
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", err
    }

    bundle := fingerprintBundle{
        ID:    id,
        Words: normalizedWords,
    }

    raw, err := cbor.Marshal(bundle)
    if err != nil {
        return nil, "", err
    }

    encrypted, err := encryption.EncryptBundle(raw, password, salt)
    if err != nil {
        return nil, "", err
    }

    for i := range raw { raw[i] = 0 }

    // 5️⃣ Create miner identity
    miner := &Miner{
        ID:                       id,
        IP:                       ipHash,
        EncryptedBundle:          encrypted,
        Salt:                     salt,
        ConsciousnessFingerprint: normalizedWords,
        Version:                  3,
        FingerprintHash:          fpHash,
    }

    // 6️⃣ Deterministic identity signature
    if err := EnsureMinerSignature(miner); err != nil {
        return nil, "", err
    }

// 🔐 ON-CHAIN IDENTITY ANCHOR (consensus critical)
    commitment, restored, err := guardian.RegisterOrRestoreIdentity(
    normalizedWords,
    miner.ID,
    hex.EncodeToString(CurrentNetworkID[:]),
    miner.PubKey,
    miner.Signature,
)
if err != nil {
    return nil, "", err
}

// Safety: a newly created miner should not already exist on-chain
if restored {
    return nil, "", errors.New("identity already exists on-chain; use restore instead")
}

_ = commitment

    // 7️⃣ Persist identity locally
    key := append(PrefixMiner, []byte(id)...)
    if err := ledger.PutObject(key, miner); err != nil {
        return nil, "", err
    }

    // 8️⃣ Ephemeral message
    msg := guardian.EncourageMessageEphemeral(normalizedWords)

    // 9️⃣ Memory wipe
    for i := range words { words[i] = "" }
    pw := []byte(password)
    for i := range pw { pw[i] = 0 }

    return miner, msg, nil
}

func RestoreMinerUniversal(id string, words []string, password string, ledger *Ledger) (*Miner, string, error) {

    if ledger == nil {
        return nil, "", errors.New("ledger required")
    }

    if !address.IsValidEXPLOAddress(id) {
        return nil, "", errors.New("invalid miner ID")
    }
    if !IsValidPassword(password) {
        return nil, "", errors.New("invalid password")
    }

    preparedWords := prepareWords(words)

    fpHash, err := guardian.FingerprintHash(preparedWords)
    if err != nil {
        return nil, "", fmt.Errorf("invalid sacred words: %w", err)
    }

    normalizedWords := guardian.NormalizeWords(preparedWords)

    defer func() {
        for i := range words { words[i] = "" }
        pw := []byte(password)
        for i := range pw { pw[i] = 0 }
    }()

    // 1️⃣ Check if miner already exists locally
    key := append(PrefixMiner, []byte(id)...)
    var existing Miner
    if err := ledger.GetObject(key, &existing); err == nil {
        if existing.FingerprintHash != fpHash {
            return nil, "", errors.New("identity mismatch")
        }
        return &existing, guardian.EncourageMessageEphemeral(normalizedWords), nil
    }

    // 2️⃣ Rebuild deterministic identity
    miner := &Miner{
        ID:                       id,
        ConsciousnessFingerprint: normalizedWords,
        Version:                  3,
        FingerprintHash:          fpHash,
    }

    if err := EnsureMinerSignature(miner); err != nil {
        return nil, "", err
    }

// 🔐 ON-CHAIN IDENTITY VERIFICATION (consensus critical)
    commitment, restored, err := guardian.RegisterOrRestoreIdentity(
    normalizedWords,
    miner.ID,
    hex.EncodeToString(CurrentNetworkID[:]),
    miner.PubKey,
    miner.Signature,
)
if err != nil {
    return nil, "", err
}

// Safety: a newly created miner should not already exist on-chain
if !restored {
    return nil, "", errors.New("identity not found on-chain")
}

_ = commitment

    // 3️⃣ Encrypt local identity bundle
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, "", err
    }

    bundle := fingerprintBundle{
        ID:    id,
        Words: normalizedWords,
    }

    raw, err := cbor.Marshal(bundle)
    if err != nil {
        return nil, "", err
    }

    encrypted, err := encryption.EncryptBundle(raw, password, salt)
    if err != nil {
        return nil, "", err
    }

    for i := range raw { raw[i] = 0 }

    miner.EncryptedBundle = encrypted
    miner.Salt = salt

    if err := ledger.PutObject(key, miner); err != nil {
        return nil, "", err
    }

    msg := guardian.EncourageMessageEphemeral(normalizedWords)

    return miner, msg, nil
}


// ─────────────── Identity Chain Callbacks ───────────────
// These callbacks must be set once per runtime before any on-chain registration
func SetupGuardianIdentityHooks(ledger *Ledger) {
    guardian.IdentityExistsOnChain = func(commitment []byte) (bool, error) {
        // Check on the blockchain if this commitment already exists
        exists, err := ledger.HasCommitment(commitment) // ⚠ Implement HasCommitment in Ledger
        if err != nil {
            return false, err
        }
        return exists, nil
    }

    guardian.RegisterIdentityOnChain = func(commitment []byte, pubKey []byte, signature []byte) error {
        // Register the identity on the blockchain
        return ledger.AddCommitment(commitment, pubKey, signature) // ⚠ Implement AddCommitment in Ledger
    }
}
// DeriveMinerKey deterministically derives an Ed25519 key pair.
func DeriveMinerKey(id string, words []string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	input := []byte(id + "|" + strings.Join(words, "|"))
	salt := []byte("EXPLOSIVE-MINER-V3")

	seed := argon2.IDKey(
		input,
		salt,
		3,
		64*1024,
		2,
		32,
	)

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Zero-out sensitive memory
	for i := range input {
		input[i] = 0
	}
	for i := range seed {
		seed[i] = 0
	}

	return priv, pub, nil
}

func SignMinerIdentity(m *Miner, priv ed25519.PrivateKey) {
	msg := []byte("MINER|" + m.ID + "|" + strings.Join(m.ConsciousnessFingerprint, "|"))
	m.Signature = ed25519.Sign(priv, msg)

	// Zero-out private key after use
	for i := range priv {
		priv[i] = 0
	}
}

func EnsureMinerSignature(m *Miner) error {
	if len(m.PubKey) == ed25519.PublicKeySize && len(m.Signature) > 0 {
		return nil
	}

	priv, pub, err := DeriveMinerKey(m.ID, m.ConsciousnessFingerprint)
	if err != nil {
		return err
	}

	m.PubKey = pub
	SignMinerIdentity(m, priv)

	return nil
}

// DeleteMiner securely wipes the miner if words match.
func DeleteMiner(words []string, m *Miner) error {
	if !IsValidSacredWords(words) {
		return errors.New("invalid sacred words")
	}

	words =guardian.NormalizeWords(words)

	if !equalWords(words, guardian.NormalizeWords(m.ConsciousnessFingerprint)) {
		return errors.New("sacred words do not match")
	}

	for i := range m.EncryptedBundle {
		m.EncryptedBundle[i] = 0
	}

	// Zero-out words
	for i := range words {
		words[i] = ""
	}

	return nil
}

// ChangePasswordAfterRestore re-encrypts bundle with new password.
func (m *Miner) ChangePasswordAfterRestore(newPassword string) error {
	if !IsValidPassword(newPassword) {
		return errors.New("invalid new password")
	}

	bundle := map[string]interface{}{
		"id":    m.ID,
		"words": m.ConsciousnessFingerprint,
	}

	raw, err := cbor.Marshal(bundle)
	if err != nil {
		return err
	}

	newSalt := make([]byte, 16)
	if _, err := rand.Read(newSalt); err != nil {
		return err
	}

	newEncrypted, err := encryption.EncryptBundle(raw, newPassword, newSalt)
	if err != nil {
		return err
	}

	for i := range raw {
		raw[i] = 0
	}

	m.EncryptedBundle = newEncrypted
	m.Salt = newSalt
	return nil
}

// ChangePasswordWithOld re-encrypts after decrypting with old password.
func (m *Miner) ChangePasswordWithOld(oldPassword, newPassword string) error {
	if !IsValidPassword(newPassword) {
		return errors.New("invalid new password")
	}

	decrypted, err := encryption.DecryptBundle(m.EncryptedBundle, oldPassword, m.Salt)
	if err != nil {
		return errors.New("invalid old password")
	}

	newSalt := make([]byte, 16)
	if _, err := rand.Read(newSalt); err != nil {
		return err
	}

	newEncrypted, err := encryption.EncryptBundle(decrypted, newPassword, newSalt)
	if err != nil {
		return err
	}

	for i := range decrypted {
		decrypted[i] = 0
	}

	m.EncryptedBundle = newEncrypted
	m.Salt = newSalt
	return nil
}

// Utilities
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

// ExportMinerBackup creates a secure, portable backup of the miner identity.
// The sacred words are encrypted with AES-GCM using Argon2id-derived key from password.
// The backup is a single file containing salt + nonce + ciphertext.
// Returns error on any failure.
func ExportMinerBackup(miner *Miner, password, outputPath string) error {
	if password == "" {
		return errors.New("password is required for backup export")
	}

	type backupData struct {
		ID    string   `cbor:"id"`
		Words []string `cbor:"words"` // encrypted, never plaintext
	}

	data := backupData{
		ID:    miner.ID,
		Words: miner.ConsciousnessFingerprint,
	}

	raw, err := cbor.Marshal(data)
	if err != nil {
		return fmt.Errorf("cbor marshal failed: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		3,        // time
		64*1024,  // memory (64 MiB)
		4,        // threads
		32,       // key length
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("AES-GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, raw, nil)
	final := append(salt, ciphertext...)

	if err := os.WriteFile(outputPath, final, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Zero-out sensitive memory
	for i := range raw {
		raw[i] = 0
	}
	for i := range key {
		key[i] = 0
	}
	for i := range nonce {
		nonce[i] = 0
	}

	return nil
}

// RestoreMinerBackup restores a miner from a secure backup file.
// Requires the correct password to decrypt the sacred words and identity.
// Returns the restored Miner or error.
func RestoreMinerBackup(password, inputPath string) (*Miner, error) {
	if password == "" {
		return nil, errors.New("password is required to restore backup")
	}

	fileBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	if len(fileBytes) < 16 {
		return nil, errors.New("backup file too short")
	}

	salt := fileBytes[:16]
	ciphertext := fileBytes[16:]

	key := argon2.IDKey(
		[]byte(password),
		salt,
		3,
		64*1024,
		4,
		32,
	)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM creation failed: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	encryptedData := ciphertext[gcm.NonceSize():]

	raw, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	var data struct {
		ID    string   `cbor:"id"`
		Words []string `cbor:"words"`
	}
	if err := cbor.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("cbor unmarshal failed: %w", err)
	}

	// Zero-out sensitive memory
	for i := range raw {
		raw[i] = 0
	}
	for i := range key {
		key[i] = 0
	}

	miner := &Miner{
		ID:                       data.ID,
		ConsciousnessFingerprint: data.Words,
		Version:                  3,
	}

	if err := EnsureMinerSignature(miner); err != nil {
		return nil, fmt.Errorf("failed to ensure miner signature: %w", err)
	}

	return miner, nil
}
