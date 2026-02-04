// internal/ledger/mine.go
// Package ledger
//
// This file implements the complete daily mining logic for the EXPLOSIVE blockchain.
// It is designed specifically for a fully decentralized, mobile-first environment
// where each miner operates independently without any central server or coordinator.
//
// Core responsibilities of this file include:
//  - Enforcing strict daily mining rules (one reward per miner per UTC day)
//  - Executing a real, CPU-bound Proof-of-Work suitable for smartphones
//  - Minting EXPLO rewards with halving support and total supply enforcement
//  - Managing symbolic IMANI and derived LUMEN values
//  - Creating, signing, and persisting real blocks containing mining rewards
//  - Providing on-chain cooldown verification and PoW validation helpers

package ledger

import (
    "errors"
    "fmt"
    "log"
    "math"
    "math/rand"
    "strconv"
    "strings"
    "time"
    "encoding/binary"
    "encoding/hex"

    "golang.org/x/crypto/sha3"
    "explosive/internal/address"
    "explosive/internal/common"
    "explosive/internal/guardian"
    "explosive/internal/halving"
    "explosive/internal/imanifund"
    "github.com/dgraph-io/badger/v4"
)

var currentPastabo uint64
// -----------------------------
// Constants
// -----------------------------
// These constants define global economic limits, mining cadence rules,
// and Proof-of-Work parameters tuned for mobile devices.
const (
    // Maximum symbolic LUMEN a miner can reach
    MaxLumen           = 50.0

    // Number of seconds in a UTC day, used for cooldown enforcement
    SecondsPerDay      = 24 * 60 * 60

    // Allowed donation range taken from the mining reward
    MinDonationPercent = 0.0
    MaxDonationPercent = 0.1

    // Daily Proof-of-Work parameters
    // These values are empirically tuned for mid-range smartphones.

    // Expected average PoW duration on a phone
    PoWDailyTargetSeconds = 30

    // Hard timeout to avoid infinite loops on very slow or overloaded devices
    PoWMaxDuration        = 2 * time.Minute

    // Default PoW difficulty expressed as leading zero hex digits
    PoWDefaultDifficulty  = 5

    // Maximum allowed PoW difficulty
    PoWMaxDifficulty      = 10

    // Ledger key under which PoW difficulty may be stored for future governance
    PoWDifficultyKey      = "pow:daily_difficulty"
)

// MinerState stores ephemeral, local mining session data.
// This state is NOT authoritative consensus data and may be replaced
// by on-chain inspection in the future.
type MinerState struct {
    // Timestamp of the last successful mining session (seconds)
    LastMineUnix int64

    // Symbolic IMANI accumulated by the miner
    IMANI        float64

    // Derived spiritual power computed from IMANI
    LUMEN        float64
}


// DB exposes the underlying BadgerDB instance.
// This is intentionally limited to trusted internal packages only.
func (l *Ledger) DB() *badger.DB {
    return l.db
}

// computeDailyPoW executes the daily Proof-of-Work challenge for a miner.
//
// Challenge definition:
//   SHA3-256(minerID | dayTimestamp | nonce)
// must produce a hash with at least `difficulty` leading zero hex digits.
//
// The dayTimestamp is truncated to the UTC day start, ensuring that:
//  - All miners share the same challenge window per day
//  - PoW cannot be reused across days
//
// This design enforces real CPU cost while remaining ASIC-resistant
// and suitable for mobile devices.
func computeDailyPoW(
    minerID string,
    prevBlockHash string,
    dayTimestamp int64,
    difficulty uint,
) (uint64, string, error) {

    if difficulty == 0 {
        return 0, "", errors.New("invalid PoW difficulty")
    }
    if prevBlockHash == "" {
        return 0, "", errors.New("missing previous block hash")
    }

    prefix := strings.Repeat("0", int(difficulty))
    start := time.Now()
    var nonce uint64

    for {
        if time.Since(start) > PoWMaxDuration {
            return 0, "", errors.New("daily PoW timeout")
        }

        hashHex := computePoWHash(
            prevBlockHash,
            minerID,
            dayTimestamp,
            nonce,
        )

        if strings.HasPrefix(hashHex, prefix) {
            log.Printf(
                "PoW solved — diff %d | nonce %d | %.2fs",
                difficulty,
                nonce,
                time.Since(start).Seconds(),
            )
            return nonce, hashHex, nil
        }

        nonce++
    }
}

// getDailyPoWDifficulty retrieves the current PoW difficulty.
//
// By default, a fixed value is used to guarantee predictable
// mobile performance. The value is optionally stored in the ledger
// to allow future decentralized adjustments without hard forks.
func getDailyPoWDifficulty(l *Ledger) uint {
    tip, err := l.GetLatestBlock()
    if err != nil || tip == nil {
        return PoWDefaultDifficulty
    }

    const lookbackLimit = 60
    recentBlocks := 0
    current := tip

    for i := 0; i < lookbackLimit && current != nil; i++ {
        recentBlocks++
        prev, _ := l.GetBlockByHash(current.Header.PrevHash)
        current = prev
    }

    difficulty := PoWDefaultDifficulty

    switch {
    case recentBlocks > 50:
        difficulty = 8
    case recentBlocks > 30:
        difficulty = 7
    case recentBlocks > 15:
        difficulty = 6
    }

    if difficulty < PoWDefaultDifficulty {
        difficulty = PoWDefaultDifficulty
    }
    if difficulty > PoWMaxDifficulty {
        difficulty = PoWMaxDifficulty
    }

    log.Printf("[PoW] difficulty=%d (recent blocks in lookback: %d)", difficulty, recentBlocks)
    return uint(difficulty)
}

// Mine executes a full daily mining session for a miner.
//
// Fundamental guarantees:
//  - One mining reward per miner per UTC day
//  - Real Proof-of-Work tied to miner identity
//  - No trusted third party or server
//  - Atomic, locally persisted state transitions
// Mine executes a single daily mining session for the given miner identity.
// This function enforces strict consensus rules, network anchoring, and zero local trust
// for critical decisions (cooldown, difficulty, supply cap, reward). Local state is used
// exclusively for UX feedback and symbolic metrics (IMANI/LUMEN).
func Mine(
    db *Ledger,
    miner *Miner,
    state *MinerState,          // UX/symbolic only – NEVER used for consensus decisions
    donationPercent float64,
    p2pNode common.P2PNode,
) error {
    now := time.Now().Unix()

    // 1. Identity verification – deterministic key derivation from sacred words
    if err := EnsureMinerSignature(miner); err != nil {
        return fmt.Errorf("miner identity verification failed: %w", err)
    }

    // 2. Donation bounds enforcement
    if donationPercent < MinDonationPercent || donationPercent > MaxDonationPercent {
        return errors.New("donation percent out of allowed range [0.0, 0.1]")
    }

    // 3. Strict on-chain cooldown check – local state is UX estimation only
    allowed, remainChain, chainErr := IsMiningAllowedFromChain(db, miner.ID, now)

if !allowed {
    hours := remainChain / 3600
    minutes := (remainChain % 3600) / 60
    fmt.Printf("⏳ Network day resets in %dh %02dm\n", hours, minutes)
    return errors.New("daily mining limit reached for this network day")
}
    if chainErr != nil {
        log.Printf("WARNING: on-chain cooldown verification failed: %v (proceeding with caution)", chainErr)
    } else if !allowed {
        hours := remainChain / 3600
        minutes := (remainChain % 3600) / 60
        fmt.Printf("⏳ On-chain cooldown active: %dh %02dm remaining\n", hours, minutes)
        return errors.New("mining cooldown enforced by on-chain state")
    }

    // 4. Miner address format validation
    if !address.IsValidEXPLOAddress(miner.ID) {
        return errors.New("invalid miner address format")
    }

    // 5. Retrieve current chain tip – fail fast if unavailable
prevBlock, err := db.GetLatestBlock()
if err != nil {
    return fmt.Errorf("failed to retrieve chain tip: %w", err)
}
if prevBlock == nil {
    return errors.New("genesis block missing – mining not possible")
}

// ✅ Miner only anchors to the parent hash
prevHash := prevBlock.BlockHash

// ✅ Use the previous block's hash and height directly
prevHash = prevBlock.BlockHash
nextHeight := prevBlock.Header.Height + 1

// Anti-double-mine check: verify the computed height is still available
existing, err := db.GetBlockByHeight(nextHeight)
if err == nil && existing != nil {
    fmt.Printf("⚠️ Height %d already taken — chain advanced during mining preparation\n", nextHeight)
    return errors.New("height already exists – retry mining")
}

// Small random jitter (mobile-only) to reduce collision probability
time.Sleep(time.Duration(rand.Intn(150)+50) * time.Millisecond)

dayStart := now / SecondsPerDay * SecondsPerDay

// 🔒 Enforce strict daily PoW per miner — CONSENSUS CRITICAL
alreadyMined, err := db.HasDailyPoW(miner.ID, dayStart)
if err != nil {
    return fmt.Errorf("failed to verify daily PoW index (consensus critical): %w", err)
}

if alreadyMined {
    remaining := (dayStart + SecondsPerDay) - now
    if remaining < 0 {
        remaining = 0
    }
    hours := remaining / 3600
    minutes := (remaining % 3600) / 60
    fmt.Printf("⏳ Daily PoW already mined today: wait %dh %02dm\n", hours, minutes)
    return errors.New("daily mining limit reached for this network day")
}

// 6. Network difficulty – computed from chain state
difficulty := getDailyPoWDifficulty(db)
log.Printf(
    "Mining session initiated — anchored to block %d (%s), difficulty %d",
    prevBlock.Header.Height,
    prevHash[:12]+"...",
    difficulty,
)

// 7. Execute network-anchored Proof-of-Work
nonce, powHash, err := computeDailyPoW(miner.ID, prevHash, dayStart, difficulty)
if err != nil {
    return fmt.Errorf("network-bound PoW computation failed: %w", err)
}

// ✅ Modern PoW: include PrevBlockHash for validation
dailyPoW := &MiningPoW{
    DayStart:      dayStart,
    Nonce:         nonce,
    Difficulty:    difficulty,
    HashHex:       powHash,
    PrevBlockHash: prevHash,
}

    // 8. Deterministic reward calculation via halving schedule (in pastabo units)
rewardPastabo, err := halving.GetCurrentRewardPastabo(db.DB())
if err != nil {
    return fmt.Errorf("failed to retrieve current halving reward: %w", err)
}

// Donation in pastabo (integer precision with rounding)
donationPastabo := uint64(float64(rewardPastabo) * donationPercent + 0.5)

// Convert rewardPastabo to uint64 to match donationPastabo type
rewardPastaboUint := uint64(rewardPastabo)
netRewardPastabo := rewardPastaboUint - donationPastabo

// IMANI minting ratio (symbolic float for UX only)
imaniMint := float64(donationPastabo) / float64(PastaboPerEXPLO) * 1000

// 9. Enforce global supply cap – fast meta-key lookup in pastabo
currentPastabo, err = db.GetTotalIssued()
if err != nil {
    return fmt.Errorf("failed to read current total issued: %w", err)
}

projectedPastabo, err := projectTotalSupply(db, netRewardPastabo)
if err != nil {
    return fmt.Errorf("supply cap projection failed: %w", err)
}

if projectedPastabo > MaxPastaboSupply {
    return errors.New("mining would exceed maximum EXPLO supply cap")
}

// Convert back to EXPLO for UX messages only
netRewardEXPLO := float64(netRewardPastabo) / float64(PastaboPerEXPLO)
donationEXPLO := float64(donationPastabo) / float64(PastaboPerEXPLO)
    // ────────────── Corrected Spiritual Fund & Height ──────────────

// 10. Update symbolic UX metrics (non-consensus critical)
state.IMANI += imaniMint
state.LUMEN = math.Min(math.Sqrt(state.IMANI), MaxLumen)

// 11. Spiritual fund operations with panic recovery

func() {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("panic in RegisterLumen: %v – continuing", r)
        }
    }()
    imanifund.RegisterLumen(miner.ID, state.LUMEN)
}()

addedToImani := false

func() {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("panic in AddDonation: %v – falling back", r)
        }
    }()
    if imanifund.AddDonation(miner.ID, donationEXPLO) == nil {
        addedToImani = true
    }
}()

if !addedToImani && donationEXPLO > 0 {
    if err := CreditDonpool(db, donationEXPLO); err != nil {
        log.Printf("fallback donation to donpool failed: %v", err)
    }
}

// 12. Create coinbase-style mining reward transaction
tx, err := NewMiningReward(
    miner.ID,
    netRewardEXPLO,
    imaniMint,
    time.Now().UnixMilli(),
)
if err != nil {
    return fmt.Errorf("failed to create mining reward transaction: %w", err)
}

// 13. Construct block (ledger will assign final Height)
block, err := NewBlock(
    nextHeight, // ✅ assign correct Height here to avoid nil pointer issues
    prevHash,
    miner.ID,
    []Transaction{*tx},
    0,
)
if err != nil {
    return fmt.Errorf("block construction failed: %w", err)
}

block.Header.DailyPoW = dailyPoW

// 14. Sign block using deterministic derived private key
priv, _, err := DeriveMinerKey(miner.ID, miner.ConsciousnessFingerprint)
if err != nil {
    return fmt.Errorf("failed to derive miner signing key: %w", err)
}
if err := block.SignBlock(priv); err != nil {
    return fmt.Errorf("block signing failed: %w", err)
}

block.BlockHash = block.ComputeFinalHash()

// 15. Re-fetch the current previous block right before validation
currentPrev, err := db.GetLatestBlock()
if err != nil {
    return fmt.Errorf("failed to re-fetch previous block before validation: %w", err)
}
if currentPrev == nil {
    return errors.New("genesis block missing during validation")
}

// Verify that the chain tip has not changed (hash-based)
if currentPrev.BlockHash != prevHash {
    fmt.Printf(
        "⚠️ Chain tip changed during PoW — expected parent %s, got %s\n",
        prevHash[:12], currentPrev.BlockHash[:12],
    )
    return errors.New("chain tip changed during mining — retry")
}

// ✅ Assign Height BEFORE any fmt.Printf or P2P broadcast
block.Header.Height = currentPrev.Header.Height + 1

// Consensus validation
if err := block.Validate(currentPrev, db); err != nil {
    return fmt.Errorf("self-mined block rejected by consensus validation: %w", err)
}

// 16. Persist validated block to ledger
if err := db.ApplyBlock(block); err != nil {
    return fmt.Errorf("ledger rejected mined block: %w", err)
}

// 🔐 Atomically update total issued supply (CONSENSUS CRITICAL)
var newTotal uint64
err = db.DB().Update(func(txn *badger.Txn) error {
    item, err := txn.Get(MetaTotalIssued)
    if err != nil {
        if err == badger.ErrKeyNotFound {
            currentPastabo = 0
        } else {
            return err
        }
    } else {
        err = item.Value(func(val []byte) error {
            currentPastabo = bytesToU64(val)
            return nil
        })
        if err != nil {
            return err
        }
    }

    if currentPastabo+netRewardPastabo > MaxPastaboSupply {
        return errors.New("mining would exceed maximum EXPLO supply cap")
    }

    newTotal = currentPastabo + netRewardPastabo
    return txn.Set(MetaTotalIssued, u64ToBytes(newTotal))
})
if err != nil {
    return fmt.Errorf("atomic supply update failed: %w", err)
}

// ✅ Safe logs and P2P broadcast
fmt.Printf(
    "⛓️ Block #%d mined — %.8f EXPLO issued (total %.2f EXPLO)\n",
    block.Header.Height,
    float64(netRewardPastabo)/float64(PastaboPerEXPLO),
    float64(newTotal)/float64(PastaboPerEXPLO),
)

if p2pNode != nil {
    blockHash := []byte(block.BlockHash)
    log.Printf("Broadcasting mined block #%d (hash prefix %x)", block.Header.Height, blockHash[:8])
    p2pNode.BroadcastBlockInv(blockHash, "BLOCK_FULL")
}

    // 18. Update local cooldown timer (UX only – next launch feedback)
    state.LastMineUnix = now

    // 19. Guardian inspirational message (UX)
    msg := guardian.EncourageMessageEphemeral(miner.ConsciousnessFingerprint)
    fmt.Printf("🌟 LUMEN %.2f / %.2f\n", state.LUMEN, MaxLumen)
    fmt.Println("💬 Guardian:", msg)

    return nil
}

// CreditDonpool credits the global donation pool as a fallback mechanism.
func CreditDonpool(db *Ledger, amount float64) error {
    if amount <= 0 {
        return nil
    }

    return db.DB().Update(func(txn *badger.Txn) error {
        var current float64

        item, err := txn.Get([]byte("donpool"))
        if err != nil {
            if err == badger.ErrKeyNotFound {
                current = 0
            } else {
                return err
            }
        } else {
            err = item.Value(func(val []byte) error {
                current, err = strconv.ParseFloat(string(val), 64)
                return err
            })
            if err != nil {
                return err
            }
        }

        newTotal := current + amount
        return txn.Set([]byte("donpool"), []byte(fmt.Sprintf("%.8f", newTotal)))
    })
}

// CreditSoul directly credits EXPLO to a miner balance.
// This is a legacy or utility-level function and should be used cautiously.
func CreditSoul(db *Ledger, minerID string, amount float64) error {
    balanceKey := []byte("balance:" + minerID)
    bal := &Balance{}
    if err := db.GetObject(balanceKey, bal); err != nil {
        bal = &Balance{}
    }
    bal.EXPLO += amount
    return db.PutObject(balanceKey, bal)
}

// -----------------------------
// On-chain Mining PoW & Cooldown helpers
// -----------------------------

// MiningPoW encapsulates the daily Proof-of-Work
// and is embedded directly inside a block header.
type MiningPoW struct {
    DayStart   int64  // UTC day start timestamp (seconds)
    Nonce      uint64 // Nonce that satisfies the PoW
    Difficulty uint   // Difficulty at mining time
    HashHex    string // Resulting SHA3-256 hash (hex)
    PrevBlockHash string `cbor:"prev_block_hash,omitempty"` // empty for legacy
}


// GetLastMiningTimestampFromChain walks the blockchain backwards
// to locate the most recent block mined by a specific miner.
//
// This method is intended to eventually replace MinerState.LastMineUnix.
func GetLastMiningTimestampFromChain(db *Ledger, minerID string) (int64, error) {
    block, err := db.GetLatestBlock()
    if err != nil {
        return 0, err
    }

    for block != nil {
        if block.Header.MinerAddress == minerID {
            return block.Header.Timestamp / 1000, nil // milliseconds → seconds
        }
        if block.Header.PrevHash == "" {
            break
        }
        block, err = db.GetBlockByHash(block.Header.PrevHash)
        if err != nil {
            return 0, err
        }
    }

    return 0, nil // Miner has never mined before
}

// IsMiningAllowedFromChain enforces exactly ONE mining per network UTC day
// based purely on on-chain indexed PoW (no sliding timestamp logic).
func IsMiningAllowedFromChain(db *Ledger, minerID string, now int64) (bool, int64, error) {

    dayStart := now / SecondsPerDay * SecondsPerDay

    alreadyMined, err := db.HasDailyPoW(minerID, dayStart)
    if err != nil {
        return false, 0, err
    }

    if !alreadyMined {
        return true, 0, nil
    }

    remaining := (dayStart + SecondsPerDay) - now
    if remaining < 0 {
        remaining = 0
    }

    return false, remaining, nil
}

// VerifyDailyPoWLegacy verifies legacy PoW (no network anchor, no difficulty enforcement)
func VerifyDailyPoWLegacy(minerID string, pow MiningPoW) bool {
    base := fmt.Sprintf("%s|%d|%d", minerID, pow.DayStart, pow.Nonce)
    hash := sha3.Sum256([]byte(base))
    hashHex := hex.EncodeToString(hash[:])

    prefix := strings.Repeat("0", int(pow.Difficulty))
    return hashHex == pow.HashHex && strings.HasPrefix(hashHex, prefix)
}

// VerifyDailyPoW verifies the daily PoW proof against the previous block hash.
// Returns true if valid, false otherwise.
func VerifyDailyPoW(minerID string, pow MiningPoW, prevBlockHash string) bool {

    // ---------------- Legacy blocks (no network anchor) ----------------
    if pow.PrevBlockHash == "" {

        base := fmt.Sprintf("%s|%d|%d", minerID, pow.DayStart, pow.Nonce)
        hash := sha3.Sum256([]byte(base))
        hashHex := hex.EncodeToString(hash[:])

        prefix := strings.Repeat("0", int(pow.Difficulty))
        return hashHex == pow.HashHex && strings.HasPrefix(hashHex, prefix)
    }

    // ---------------- Modern anchored PoW ----------------

    if pow.PrevBlockHash != prevBlockHash {
        return false
    }

    hashHex := computePoWHash(
        prevBlockHash,
        minerID,
        pow.DayStart,
        pow.Nonce,
    )

    prefix := strings.Repeat("0", int(pow.Difficulty))
    return hashHex == pow.HashHex && strings.HasPrefix(hashHex, prefix)
}

func computePoWHash(prevHash, minerID string, dayStart int64, nonce uint64) string {
    base := prevHash + "|" + minerID + "|" + strconv.FormatInt(dayStart, 10) + "|"
    input := base + strconv.FormatUint(nonce, 10)

    h := sha3.Sum256([]byte(input))
    return hex.EncodeToString(h[:])
}

func (l *Ledger) HasDailyPoW(minerID string, dayStart int64) (bool, error) {
    key := []byte(fmt.Sprintf("daily_pow:%s:%d", minerID, dayStart))
    _, err := l.GetBytes(key)
    if err == nil {
        return true, nil
    }
    if err == badger.ErrKeyNotFound {
        return false, nil
    }
    return false, fmt.Errorf("failed to check daily PoW index: %w", err)
}

func bytesToU64(b []byte) uint64 {
    if len(b) != 8 {
        return 0
    }
    return binary.BigEndian.Uint64(b)
}

