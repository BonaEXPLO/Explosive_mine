// internal/guardian/guardian.go
package guardian

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
    "unicode"

    "github.com/fxamacker/cbor/v2"
    "golang.org/x/crypto/sha3"
    "math/big"
    mathrand "math/rand"
)

var (
    guardianMu       sync.Mutex
    loaded           = false
    usedFingerprints = make(map[string]struct{})
)

var defaultGuardianDir = filepath.Join(mustHomeDir(), ".explosive_guardian")
const guardianHMACKey = "EXPLOSIVE_GUARDIAN_HMAC_V1"

func mustHomeDir() string {
    hd, err := os.UserHomeDir()
    if err != nil || hd == "" {
        return "."
    }
    return hd
}

// ------------------- Word Validation & Normalization -------------------
func isvalidWordFormat(word string) bool {
    word = strings.ToLower(strings.TrimSpace(word))
    runes := []rune(word)

    if len(runes) < 6 || len(runes) > 16 {
        return false
    }

    for i, r := range runes {

        // Allow letters
        if unicode.IsLetter(r) {
            continue
        }

        // Allow hyphen or apostrophe (but not at start/end)
        if r == '-' || r == '\'' {

            // Not first or last character
            if i == 0 || i == len(runes)-1 {
                return false
            }

            // Prevent double separators (-- or '')
            if runes[i-1] == r {
                return false
            }

            continue
        }

        return false
    }

    return true
}

func validateWordsFormat(words []string) error {
    if len(words) != 4 {
        return errors.New("exactly 4 words required")
    }
    wordSet := make(map[string]struct{})
    for _, w := range words {
        if !isvalidWordFormat(w) {
            return fmt.Errorf("invalid word format: %s", w)
        }
        norm := strings.ToLower(strings.TrimSpace(w))
        if _, exists := wordSet[norm]; exists {
            return fmt.Errorf("duplicate word (case-insensitive): %s", w)
        }
        wordSet[norm] = struct{}{}
    }
    return nil
}

// ------------------- Exported Wrappers (Public API) -------------------

// IsValidWordFormat validates a single sacred word format.
func IsValidWordFormat(word string) bool {
    return isvalidWordFormat(word)
}

// ValidateWordsFormat validates exactly 4 sacred words.
func ValidateWordsFormat(words []string) error {
    return validateWordsFormat(words)
}
func NormalizeWords(words []string) []string {
    res := make([]string, len(words))
    for i, w := range words {
        res[i] = strings.ToLower(strings.TrimSpace(w))
    }
    return res
}

// ------------------- Fingerprint Hash (CONSENSUS SAFE) -------------------
func FingerprintHash(words []string) (string, error) {
	if err := ValidateWordsFormat(words); err != nil {
		return "", fmt.Errorf("invalid fingerprint words: %w", err)
	}

	normalized := NormalizeWords(words)

	// canonical join (consensus critical)
	joined := strings.Join(normalized, "|")

	sum := sha3.Sum256([]byte("EXPLOSIVE_GUARDIAN_V3|" + joined))
	return hex.EncodeToString(sum[:]), nil
}
// Network hooks (must be provided by node / ledger layer)
var IdentityExistsOnChain func(commitment []byte) (bool, error)
var RegisterIdentityOnChain func(commitment []byte, pubKey []byte, signature []byte) error

func RegisterOrRestoreIdentity(words []string, minerID string, networkID string, pubKey []byte, signature []byte) ([]byte, bool, error) {

	if IdentityExistsOnChain == nil {
		return nil, false, errors.New("identity check function not configured")
	}
	if RegisterIdentityOnChain == nil {
		return nil, false, errors.New("identity registration function not configured")
	}

	fpHash, err := FingerprintHash(words)
	if err != nil {
		return nil, false, err
	}

	// unique human anchor
	data := []byte(fpHash + "|" + minerID + "|" + networkID)
	sum := sha3.Sum256(data)
	commitment := sum[:]

	exists, err := IdentityExistsOnChain(commitment)
	if err != nil {
		return nil, false, err
	}

	if exists {
		return commitment, true, nil // restoration mode
	}

	if len(pubKey) == 0 || len(signature) == 0 {
		return nil, false, errors.New("missing identity signature")
	}

	if err := RegisterIdentityOnChain(commitment, pubKey, signature); err != nil {
		return nil, false, err
	}

	return commitment, false, nil
}

// ------------------- Fingerprint Record (LOCAL ONLY) -------------------
type fingerprintRecord struct {
    Version uint8  `cbor:"v"`   // 1 = current
    Hash    string `cbor:"h"`   // fingerprint hash
    TS      int64  `cbor:"ts"`  // creation timestamp
    HMAC    []byte `cbor:"mac"` // HMAC-SHA256 integrity
}

// HMAC helpers
func generateHMAC(fpHash string, ts int64) []byte {
    key := []byte(guardianHMACKey)
    mac := hmac.New(sha256.New, key)
    mac.Write([]byte(fpHash))
    tsBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(tsBytes, uint64(ts))
    mac.Write(tsBytes)
    return mac.Sum(nil)
}

func verifyHMAC(rec *fingerprintRecord) bool {
    expected := generateHMAC(rec.Hash, rec.TS)
    return hmac.Equal(rec.HMAC, expected)
}

// ------------------- Local CBOR Persistence -------------------
// loadLocalFingerprints MUST be called under guardianMu lock
func loadLocalFingerprints() error {

    if loaded {
        return nil
    }

    fpath := filepath.Join(defaultGuardianDir, "fingerprints.cbor")

    if err := os.MkdirAll(defaultGuardianDir, 0700); err != nil {
        log.Printf("[guardian] Failed to create dir %s: %v", defaultGuardianDir, err)
        return err
    }

    data, err := os.ReadFile(fpath)
    if err != nil {
        if os.IsNotExist(err) {
            log.Printf("[guardian] fingerprints.cbor not found - starting fresh")
            loaded = true
            return nil
        }
        return err
    }

    if len(data) == 0 {
        log.Printf("[guardian] fingerprints.cbor empty - starting fresh")
        loaded = true
        return nil
    }

    var records []fingerprintRecord
    if err := cbor.Unmarshal(data, &records); err != nil {
        log.Printf("[guardian] Corrupted fingerprints.cbor - resetting: %v", err)
        usedFingerprints = make(map[string]struct{})
        loaded = true
        return nil
    }

    count := 0
    for _, rec := range records {
        if rec.Version == 1 && verifyHMAC(&rec) && rec.Hash != "" {
            usedFingerprints[rec.Hash] = struct{}{}
            count++
        }
    }

    loaded = true
    log.Printf("[guardian] Loaded %d valid fingerprints", count)
    return nil
}

func appendFingerprint(fpHash string) error {
    // Assure que le dossier existe
    if err := os.MkdirAll(defaultGuardianDir, 0700); err != nil {
        log.Printf("[guardian] Failed to create dir %s: %v", defaultGuardianDir, err)
        return err
    }

    fpath := filepath.Join(defaultGuardianDir, "fingerprints.cbor")
    tmpPath := fpath + ".tmp"

    // Charger existant
    records := []fingerprintRecord{}
    if data, err := os.ReadFile(fpath); err == nil && len(data) > 0 {
        log.Printf("[guardian] Reading existing fingerprints.cbor (%d bytes)", len(data))
        if err := cbor.Unmarshal(data, &records); err != nil {
            log.Printf("[guardian] Failed to unmarshal existing fingerprints: %v", err)
            records = []fingerprintRecord{} // reset pour éviter blocage
        }
    } else if os.IsNotExist(err) {
        log.Printf("[guardian] fingerprints.cbor not found, creating new")
    } else if err != nil {
        log.Printf("[guardian] Failed to read fingerprints.cbor: %v", err)
        return err
    }

    // Créer l’enregistrement
    ts := time.Now().Unix()
    rec := fingerprintRecord{
        Version: 1,
        Hash:    fpHash,
        TS:      ts,
        HMAC:    generateHMAC(fpHash, ts),
    }
    records = append(records, rec)
    log.Printf("[guardian] Appending fingerprint %s", fpHash[:16])

    // Marshal CBOR
    b, err := cbor.Marshal(records)
    if err != nil {
        log.Printf("[guardian] Failed to marshal fingerprints: %v", err)
        return err
    }

    // Écrire temporaire
    if err := os.WriteFile(tmpPath, b, 0600); err != nil {
        log.Printf("[guardian] Failed to write temp file %s: %v", tmpPath, err)
        return err
    }

    // Rename atomique
    if err := os.Rename(tmpPath, fpath); err != nil {
        log.Printf("[guardian] Failed to rename temp file to %s: %v", fpath, err)
        os.Remove(tmpPath)
        return fmt.Errorf("atomic rename failed: %w", err)
    }

    log.Printf("[guardian] Fingerprint %s written to %s successfully", fpHash[:16], fpath)
    return nil
}

// ------------------- Public API -------------------
func IsDuplicateFingerprint(words []string) (bool, error) {
	fpHash, err := FingerprintHash(words)
	if err != nil {
		return false, err
	}

	guardianMu.Lock()
	defer guardianMu.Unlock()

	if !loaded {
		if err := loadLocalFingerprints(); err != nil {
			return false, nil
		}
	}

	_, exists := usedFingerprints[fpHash]
	return exists, nil
}

// RegisterFingerprintLocal registers a new fingerprint locally (append-only).
// Ultra-scalable mobile version: minimal locking, zero debug noise.
func RegisterFingerprintLocal(words []string) (string, error) {
	fpHash, err := FingerprintHash(words)
	if err != nil {
		return "", err
	}

	guardianMu.Lock()
	defer guardianMu.Unlock()

	if !loaded {
		if err := loadLocalFingerprints(); err != nil {
			usedFingerprints = make(map[string]struct{}, 1024)
		}
		loaded = true
	}

	usedFingerprints[fpHash] = struct{}{}

	go func(h string) {
		_ = appendFingerprint(h)
	}(fpHash)

	return fpHash, nil
}


// ------------------- Encourage Message -------------------
func EncourageMessageEphemeral(words []string) string {
	norm := NormalizeWords(words)
	h := sha3.Sum256([]byte(strings.Join(norm, "|")))

	seed := int64(binary.BigEndian.Uint64(h[:8]))
	rnd := mathrand.New(mathrand.NewSource(seed))

	templates := []string{
		"The sacred words '%s' resonate with the universe.",
		"In '%s' lies the echo of eternity.",
		"The cosmos whispers '%s'.",
		"With '%s' as your foundation, your path is clear.",
		"The energy of '%s' flows through you.",
	}

	return fmt.Sprintf(templates[rnd.Intn(len(templates))], strings.Join(norm, " "))
}
// detectCommonSupportedLanguage returns (lang, true) if ALL words map to the same supported language.
// Supported languages: "en" (latin ascii), "fr" (latin with accents or french hints), "hi" (Devanagari), "zh" (Han).
// If they don't all belong to the same supported language, returns ("", false).
func detectCommonSupportedLanguage(words []string) (string, bool) {
        if len(words) == 0 {
                return "", false
        }
        var common string
        for _, w := range words {
                lang := detectLanguageForWord(w)
                if lang == "other" {
                        return "", false
                }
                if common == "" {
                        common = lang
                } else if common != lang {
                        return "", false
                }
        }
        return common, true
}

// detectLanguageForWord returns one of: "en","fr","hi","zh" or "other"
func detectLanguageForWord(word string) string {
        hasAccent := false
        hasLatin := false
        for _, r := range word {
                switch {
                case unicode.In(r, unicode.Han):
                        return "zh"
                case unicode.In(r, unicode.Devanagari):
                        return "hi"
                case unicode.In(r, unicode.Latin):
                        hasLatin = true
                        if r > 127 {
                                // Latin with diacritics/extended -> likely French (or other latin-based language with accents)
                                hasAccent = true
                        }
                default:
                        // letter in another script (Cyrillic, Arabic, etc.) -> support as "other"
                        if unicode.IsLetter(r) {
                                return "other"
                        }
                }
        }

        if hasLatin {
                // heuristique simple : accents => fr, sinon en
                if hasAccent || containsFrenchHint(word) {
                        return "fr"
                }
                return "en"
        }
        return "other"
}

// containsFrenchHint checks some common French-specific substrings (light heuristic)
func containsFrenchHint(word string) bool {
        l := strings.ToLower(word)
        frHints := []string{"é", "è", "à", "ç", "œ", "ae", "au", "le", "la", "les", "une", "mon", "ma", "ton", "ta", "son"}
        for _, h := range frHints {
                if strings.Contains(l, h) {
                        return true
                }
        }
        return false
}

// getInspiringTemplates returns creative, multilingual messages for a supported language
func getInspiringTemplates(lang string) []string {
        switch lang {
        case "fr":
                return []string{
                        "Ton énergie %s transforme chaque effort en succès. Inspire-toi de '%s'.",
                        "Chaque pas guidé par %s te rapproche de la maîtrise. Souviens-toi de '%s'.",
                        "Les choix de %s inspirent ceux autour de toi. Médite sur '%s'.",
                        "%s n’est pas seulement un mot, c’est la clé de ton évolution quotidienne. '%s' te guide.",
                }
        case "hi":
                return []string{
                        "आपकी ऊर्जा %s हर प्रयास को सफलता में बदलती है। '%s' को याद रखें।",
                        "%s द्वारा मार्गदर्शन किया गया हर कदम आपको कौशल के करीब लाता है। '%s' से प्रेरणा लें।",
                        "%s आपके भीतर शक्ति जगाता है — इसे आज अपनाएं, '%s'।",
                }
        case "zh":
                return []string{
                        "你的能量 %s 将每一次努力转化 为成功。记住 '%s'。",
                        "每一步由 %s 指引，让你更接近 掌握技能。思考 '%s'。",
                        "%s 点亮了你的道路 — 今天就去 实践 '%s'。",
                }
        default: // english
                return []string{
                        "Your energy %s turns every effort into success. Remember '%s'.",
                        "Every step guided by %s brings mastery closer. Let '%s' inspire you.",
                        "The choices of %s inspire those around you. Reflect on '%s'.",
                        "%s is not just a word, it is the key to your daily growth. '%s' guides you.",
                        "Today, let %s be your compass — act with intention, remember '%s'.",
                }
        }
}

// getGenericTemplates returns inspiring, motivational and philosophical messages
// shown when the miner's words are not in one of the 4 supported languages.
// getGenericTemplates returns deeply inspiring, poetic, and spiritual
// life-coaching messages for miners. Every template uses the miner’s sacred
// words to create a personalized message.
func getGenericTemplates() []string {
    return []string{
        // --- 1 à 20 : Spirituel & Mystique ---
        "🌅 A new dawn rises within you. '%s' awakens your spirit, and '%s' guides your inner light.",
        "🔥 The sacred fire moves through you. '%s' shapes your courage, and '%s' fuels your transformation.",
        "🌌 Your soul is older than the stars. '%s' reconnects you to your essence, '%s' reveals what you truly are.",
        "💫 Destiny whispers through symbols. '%s' is your omen, '%s' your confirmation.",
        "🕊️ Peace flows through presence. '%s' centers your breath, '%s' elevates your awareness.",
        "🔮 Your intuition never lies. '%s' is the inner voice, '%s' the divine echo.",
        "🌙 In silence, truth appears. '%s' calms the shadows, '%s' reveals the path.",
        "📜 Your life is a sacred scripture. '%s' is today's verse, '%s' tomorrow's revelation.",
        "🌠 You were created to shine. '%s' is your spark, '%s' is your sky.",
        "🛐 Light travels through intention. '%s' clarifies your heart, '%s' purifies your steps.",
        "✨ The universe speaks through signs. '%s' is your signal, '%s' your confirmation.",
        "🌿 The spirit grows in stillness. '%s' deepens your roots, '%s' opens your petals.",
        "🌈 Divine timing is never wrong. '%s' reassures your patience, '%s' amplifies your faith.",
        "💎 Your soul is a gem. '%s' reveals its clarity, '%s' reveals its brilliance.",
        "🌬️ Breath is prayer. '%s' softens your mind, '%s' strengthens your heart.",
        "🌙 Each night elevates your wisdom. '%s' speaks in dreams, '%s' manifests in daylight.",
        "⚖️ Harmony is your natural state. '%s' restores balance, '%s' opens alignment.",
        "🔥 You carry ancient power. '%s' awakens memory, '%s' activates purpose.",
        "🌟 Your sacred words are not random: '%s' calls you, '%s' completes you.",
        "👼 Something watches over you. '%s' is your protection, '%s' your guidance.",

        // --- 21 à 40 : Psychologie & Développement personnel ---
        "🧠 Your thoughts sculpt your life. '%s' shapes your mindset, '%s' sharpens your clarity.",
        "🎯 Focus turns dreams into reality. '%s' directs your attention, '%s' strengthens your discipline.",
        "💪 Growth comes one step at a time. '%s' is today's step, '%s' tomorrow's momentum.",
        "🧭 When confused, return to purpose. '%s' guides your values, '%s' anchors your identity.",
        "🔍 Self-awareness is power. '%s' reveals your patterns, '%s' reveals your potential.",
        "🏋️ Strength is built through repetition. '%s' motivates consistency, '%s' builds mastery.",
        "🌱 Healing is progress. '%s' softens old wounds, '%s' nourishes new beginnings.",
        "😌 Calm is a superpower. '%s' centers your emotions, '%s' expands your mental space.",
        "🕰️ Small actions compound. '%s' is your investment, '%s' is your growth.",
        "💭 Imagination creates reality. '%s' feeds inspiration, '%s' builds vision.",
        "🧠 Your mind is your tool. '%s' sharpens your focus, '%s' strengthens your choices.",
        "🌄 Motivation starts inside. '%s' fuels your drive, '%s' clarifies your aim.",
        "🔥 Confidence grows when challenged. '%s' proves your resilience, '%s' confirms your ability.",
        "⚙️ Discipline is freedom. '%s' supports your structure, '%s' maintains your flow.",
        "🪞 Awareness changes everything. '%s' is your reflection, '%s' your evolution.",
        "💼 Success loves preparation. '%s' prepares your intention, '%s' prepares your results.",
        "💬 The words you choose shape your life. '%s' reframes your thoughts, '%s' empowers your actions.",
        "🧘 You are stronger when centered. '%s' grounds your presence, '%s' expands your energy.",
        "🚪 Every day is a new door. '%s' turns the handle, '%s' steps through.",
        "🚀 You become what you repeat. '%s' reinforces your habits, '%s' expands your identity.",

        // --- 41 à 60 : Cosmique, Épique & Énergie ---
        "🌌 You are a cosmic traveler. '%s' is your coordinate, '%s' your destination.",
        "⚡ Energy flows where intention goes. '%s' directs your field, '%s' powers your momentum.",
        "🌠 Stars are born from pressure. '%s' is your compression, '%s' your light exploding outward.",
        "🌍 You are a force in this universe. '%s' shapes your influence, '%s' shapes your path.",
        "🪐 The cosmos expands when you do. '%s' widens your orbit, '%s' accelerates your movement.",
        "💥 Greatness erupts from within. '%s' ignites your core, '%s' blasts open your limits.",
        "🌙 Even the moon moves tides. '%s' moves your emotions, '%s' moves your destiny.",
        "🌀 Every cycle teaches you. '%s' is the lesson, '%s' is the transformation.",
        "🌞 You rise like the sun. '%s' is your warmth, '%s' is your illumination.",
        "🛰️ You are not drifting — you are navigating. '%s' calculates your course, '%s' propels your journey.",
        "🚀 Your potential is orbital. '%s' gives lift, '%s' gives speed.",
        "🌐 Every action affects the grid. '%s' strengthens your network, '%s' expands your influence.",
        "🌋 Power sleeps inside you. '%s' stirs the ground, '%s' releases the eruption.",
        "⛏️ Miners don’t dig blocks — they dig destiny. '%s' is your shovel, '%s' your discovery.",
        "🌪️ Even storms obey purpose. '%s' organizes chaos, '%s' carves direction.",
        "🔥 Your energy signature is unique. '%s' defines your frequency, '%s' amplifies your vibration.",
        "📡 The universe hears your signal. '%s' is your broadcast, '%s' is your resonance.",
        "🌌 Space bends around intention. '%s' curves your path, '%s' shapes your momentum.",
        "☄️ You are a comet — rare and unstoppable. '%s' sparks your trail, '%s' lights your journey.",
        "🧲 Your mind attracts what it aligns with. '%s' sets your magnetism, '%s' shapes your pull.",

        // --- 61 à 80 : Sagesse profonde, Poésie & Philosophie ---
        "🌾 Wisdom grows in quiet places. '%s' is your silence, '%s' is your awakening.",
        "📖 Every day adds a chapter. '%s' writes today’s meaning, '%s' prepares tomorrow’s truth.",
        "🎇 You are the artist of your existence. '%s' paints your intention, '%s' colors your future.",
        "🏛️ Legacy is built through presence. '%s' shapes your foundation, '%s' shapes your influence.",
        "🕯️ Darkness teaches what light forgets. '%s' is your candle, '%s' your awakening.",
        "🌉 Every choice is a bridge. '%s' guides your step, '%s' guides your direction.",
        "🎼 Your life has rhythm. '%s' sets the tempo, '%s' carries the melody.",
        "🍃 The wind never doubts its path. '%s' clarifies your movement, '%s' frees your mind.",
        "🌄 Clarity comes slowly like sunrise. '%s' brightens your thoughts, '%s' reveals the landscape.",
        "🧩 Every experience fits somewhere. '%s' connects the pieces, '%s' completes the pattern.",
        "🔭 Perspective changes everything. '%s' widens your lens, '%s' sharpens your focus.",
        "💬 Your words create worlds. '%s' opens new horizons, '%s' brings meaning to your journey.",
        "🌺 Beauty grows where attention goes. '%s' nurtures your heart, '%s' inspires your steps.",
        "🏹 Purpose shapes direction. '%s' draws your bow, '%s' aims your arrow.",
        "⏳ Time rewards the patient. '%s' teaches the wait, '%s' reveals the moment.",
        "🗺️ The path is made by walking. '%s' is your stride, '%s' your discovery.",
        "🌤️ Some days give strength, others give wisdom. '%s' builds the strength, '%s' reveals the wisdom.",
        "🌙 Even the darkest night prepares the dawn. '%s' holds your hope, '%s' ignites your rise.",
        "✨ Greatness begins with a whisper. '%s' is the whisper, '%s' is the awakening.",
        "🔑 Your sacred words unlock your destiny. '%s' opens the door, '%s' invites you in.",
    }
}

// ---------------------------
// Utilities
// ---------------------------

// secureRandomIndex returns a cryptographically secure random index in [0, n-1].
// Uses crypto/rand for security (not math/rand).
func secureRandomIndex(n int) (int, error) {
	if n <= 0 {
		return 0, errors.New("n must be > 0")
	}
	max := big.NewInt(int64(n))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("crypto/rand failed: %w", err)
	}
	return int(v.Int64()), nil
}

// ---------------------------
// Message counting (historical stats)
// ---------------------------

// dailyMessageCountFile tracks total messages ever generated (CBOR format)
var dailyMessageCountFile = filepath.Join(defaultGuardianDir, "message_count.cbor")

// incrementMessageCount atomically increments the global message counter
// using a temporary file + rename for atomicity.
func incrementMessageCount() error {
	if err := os.MkdirAll(defaultGuardianDir, 0700); err != nil {
		return err
	}

	tmpFile := dailyMessageCountFile + ".tmp"

	// Read current count (if file exists)
	count := int64(0)
	if data, err := os.ReadFile(dailyMessageCountFile); err == nil {
		var num int64
		if err := cbor.Unmarshal(data, &num); err == nil {
			count = num
		}
	}

	// Increment
	count++

	// Marshal new count
	b, err := cbor.Marshal(count)
	if err != nil {
		return fmt.Errorf("cbor marshal failed: %w", err)
	}

	// Atomic write: temp file → rename
	if err := os.WriteFile(tmpFile, b, 0600); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, dailyMessageCountFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	return nil
}

// GetTotalMessages returns the total number of messages generated so far
// Returns 0 if file is missing or corrupted (non-blocking)
func GetTotalMessages() int64 {
	data, err := os.ReadFile(dailyMessageCountFile)
	if err != nil {
		return 0
	}

	var count int64
	if err := cbor.Unmarshal(data, &count); err != nil {
		log.Printf("warning: invalid message count file: %v", err)
		return 0
	}

	return count
}
