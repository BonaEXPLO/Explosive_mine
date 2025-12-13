// internal/guardian/guardian.go
package guardian

import (
        "bufio"
        "crypto/rand"
        "encoding/json"
        "errors"
        "fmt"
        "math/big"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"
        "unicode"
)

var (
        // default data folder for guardian persistence
        defaultGuardianDir  = filepath.Join(mustHomeDir(), ".explosive_guardian")
        fingerprintFileName = "fingerprints.jsonl"
)

// internal registry and mutex for thread-safety
var (
        registryMutex sync.RWMutex
        // usedSequences maps concatenated 4-word fingerprints (order-sensitive)
        usedSequences = map[string]struct{}{}
        loaded        = false
)

// mustHomeDir returns $HOME or "." if not available
func mustHomeDir() string {
        hd, err := os.UserHomeDir()
        if err != nil || hd == "" {
                return "."
        }
        return hd
}

// ---------------------------
// Persistence helpers
// ---------------------------
func ensurePersistenceDir() error {
        return os.MkdirAll(defaultGuardianDir, 0o700)
}

func fingerprintFilePath() string {
        return filepath.Join(defaultGuardianDir, fingerprintFileName)
}

func loadRegistryFromDisk() error {
        registryMutex.Lock()
        defer registryMutex.Unlock()
        if loaded {
                return nil
        }

        if err := ensurePersistenceDir(); err != nil {
                return err
        }

        fpath := fingerprintFilePath()
        f, err := os.OpenFile(fpath, os.O_RDONLY|os.O_CREATE, 0o600)
        if err != nil {
                return err
        }
        defer f.Close()

        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
                line := scanner.Text()
                var rec struct {
                        Words []string `json:"words"`
                }
                if err := json.Unmarshal([]byte(line), &rec); err != nil {
                        continue
                }
                if len(rec.Words) == 4 {
                        key := strings.Join(rec.Words, " ")
                        usedSequences[key] = struct{}{}
                }
        }
        loaded = true
        return nil
}

// ---------------------------
// Persistence helpers
// ---------------------------

func persistFingerprint(words []string) error {
    if err := ensurePersistenceDir(); err != nil {
        return err
    }
    fpath := fingerprintFilePath()

    f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
    if err != nil {
        return err
    }
    defer f.Close()

    rec := struct {
        Words []string `json:"words"`
        TS    int64    `json:"ts"`
    }{
        Words: words,
        TS:    time.Now().Unix(),
    }

    b, err := json.Marshal(rec)
    if err != nil {
        return err
    }

    if _, err := f.Write(append(b, '\n')); err != nil {
        return err
    }

    if err := f.Sync(); err != nil {
        return err
    }

    return nil
}
// ---------------------------
// Public API
// ---------------------------

// IsDuplicateFingerprint returns true if these 4 words (order-sensitive) are already used
func IsDuplicateFingerprint(words []string) (bool, error) {
    if len(words) != 4 {
        return false, errors.New("exactly 4 words required")
    }
    if err := loadRegistryFromDisk(); err != nil {
        return false, fmt.Errorf("failed to load registry: %w", err)
    }

    key := strings.Join(words, " ")
    registryMutex.RLock()
    _, ok := usedSequences[key]
    registryMutex.RUnlock()
    return ok, nil
}

// RegisterFingerprint records a new 4-word fingerprint
func RegisterFingerprint(words []string) error {
    if len(words) != 4 {
        return errors.New("exactly 4 words required")
    }

    if err := validateWordsFormat(words); err != nil {
        return err
    }

    key := strings.Join(words, " ")

    if err := loadRegistryFromDisk(); err != nil {
        return fmt.Errorf("failed to load registry: %w", err)
    }

    registryMutex.Lock()
    defer registryMutex.Unlock()

    if _, ok := usedSequences[key]; ok {
        return errors.New("fingerprint already used")
    }

    usedSequences[key] = struct{}{}
    return persistFingerprint(words)
}

// ValidateWordsFormat checks the 4-word rules (exported helper)
func validateWordsFormat(words []string) error {
        if len(words) != 4 {
                return errors.New("exactly 4 words required")
        }
        for i, w := range words {
                if !isValidWordFormat(w) {
                        return fmt.Errorf("word #%d is invalid: must start with uppercase, be at least 4 letters, and contain only letters", i+1)
                }
        }
        return nil
}

// isValidWordFormat enforces:
// - at least 4 runes
// - first rune is uppercase letter
// - all runes are Unicode letters (no digits, no punctuation, no spaces)
// ---------------------------
// Validation helpers
// ---------------------------

// isValidWordFormat enforces adaptive rules depending on script:
// - Latin: must start uppercase, ≥4 letters, letters only
// - Han/Devanagari: ≥4 runes, all letters, uppercase not required
// - Other scripts: ≥4 runes, all letters
func isValidWordFormat(word string) bool {
    word = strings.TrimSpace(word)
    runes := []rune(word)
    if len(runes) < 4 {
        return false
    }
    first := runes[0]

    switch {
    case unicode.In(first, unicode.Han), unicode.In(first, unicode.Devanagari):
        for _, r := range runes {
            if !unicode.IsLetter(r) {
                return false
            }
        }
        return true

    case unicode.In(first, unicode.Latin):
        if !unicode.IsUpper(first) {
            return false
        }
        for _, r := range runes {
            if !unicode.IsLetter(r) {
                return false
            }
        }
        return true

    default:
        for _, r := range runes {
            if !unicode.IsLetter(r) {
                return false
            }
        }
        return true
    }
}

// ---------------------------
// Intelligent Multilingual Mentor
// ---------------------------

// EncourageMessage generates a creative, inspiring message based on 4 sacred words.
// All valid words are accepted. If the 4 words are all recognized as belonging to
// the same supported language (en/fr/hi/zh), the message is in that language and more tailored.
// Otherwise a strong generic/inspiring English message is returned.
// EncourageMessageEphemeral generates an inspiring daily message based on 4 words,
// supports multilingual templates, accepts all words, and increments message counter.
func EncourageMessageEphemeral(words []string) string {
    joined := strings.Join(words, " ")

    // Accept words even if format invalid, but guide user
    if err := validateWordsFormat(words); err != nil {
        msg := fmt.Sprintf("Your words %s are accepted. 💡 Tip: Use capitalized words with 4+ letters for more tailored inspiration.", joined)
        _ = incrementMessageCount()
        return msg
    }

    // Language detection
    lang, allSupported := detectCommonSupportedLanguage(words)
    var templates []string
    if allSupported {
        templates = getInspiringTemplates(lang)
    } else {
        templates = getGenericTemplates()
    }

    // Choose random template and highlight word
    idx, err := secureRandomIndex(len(templates))
    if err != nil {
        idx = 0
    }
    wordIdx, _ := secureRandomIndex(len(words))
    msg := fmt.Sprintf(templates[idx], joined, words[wordIdx])

    // Increment global message counter
    _ = incrementMessageCount()

    return msg
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

// secureRandomIndex returns a secure random index in [0, n-1].
// ---------------------------
// Utilities
// ---------------------------
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
// Daily ephemeral message
// ---------------------------

// DailyMessageCountFile tracks total messages ever generated
var dailyMessageCountFile = filepath.Join(defaultGuardianDir, "message_count.json")

// ---------------------------
// Message counting (historical stats)
// ---------------------------
// ---------------------------
func incrementMessageCount() error {
    if err := ensurePersistenceDir(); err != nil {
        return err
    }

    count := 0
    if data, err := os.ReadFile(dailyMessageCountFile); err == nil {
        _ = json.Unmarshal(data, &count)
    }
    count++

    b, err := json.Marshal(count)
    if err != nil {
        return err
    }

    // 🔒 Correction : WriteFile avec Sync
    tmpFile := dailyMessageCountFile + ".tmp"
    if err := os.WriteFile(tmpFile, b, 0o600); err != nil {
        return err
    }
    return os.Rename(tmpFile, dailyMessageCountFile)
}

// GetTotalMessages returns number of messages guardian has given until now
func GetTotalMessages() int {
        data, err := os.ReadFile(dailyMessageCountFile)
        if err != nil {
                return 0
        }
        var count int
        _ = json.Unmarshal(data, &count)
        return count
}
