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
    "encoding/base64"
    "crypto/ed25519"
    "encoding/binary"
   "encoding/hex"

    "golang.org/x/crypto/sha3"
    "explosive/internal/address"
    "explosive/internal/common"
    "explosive/internal/guardian"
    "explosive/internal/halving"
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
    LastMineUnix int64   // Timestamp of last mining
    EXPLO        float64 // User-readable EXPLO balance
    IMANI        float64 // User-readable IMANI
    LUMEN        float64 // UX metric derived from IMANI
}

// ---------------- low level U64 ---------

func (l *Ledger) ReadUint64(key string) (uint64, error) {
    db := l.DB()
    if db == nil {
        return 0, errors.New("ledger DB is nil")
    }

    var val uint64
    err := db.View(func(txn *badger.Txn) error {
        var err error
        val, err = readU64(txn, key)
        return err
    })

    return val, err
}

func (l *Ledger) WriteUint64(key string, v uint64) error {
    db := l.DB()
    if db == nil {
        return errors.New("ledger DB is nil")
    }

    return db.Update(func(txn *badger.Txn) error {
        return writeU64(txn, key, v)
    })
}

func (l *Ledger) IncUint64(key string, delta uint64) error {
    db := l.DB()
    if db == nil {
        return errors.New("ledger DB is nil")
    }

    return db.Update(func(txn *badger.Txn) error {
        return incU64(txn, key, delta)
    })
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
    dayStart int64, // ✅ milliseconds
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
            dayStart, // ✅ ms
            nonce,
        )

        if strings.HasPrefix(hashHex, prefix) {
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
    const (
        minDifficulty = 4
        maxDifficulty = 6

        // Target average time between blocks.
        // This value can be adjusted after observing the real network.
        targetBlockTime = 5 * time.Minute

        // Only inspect a small number of recent blocks.
        // This remains efficient even with millions of blocks.
        lookbackLimit = 20
    )

    tip, err := l.GetLatestBlock()
    if err != nil || tip == nil {
        return minDifficulty
    }

    // Start with the minimum difficulty to remain accessible
    // to low-end smartphones and resource-constrained devices.
    difficulty := minDifficulty

    current := tip
    var totalInterval time.Duration
    var intervals int

    for i := 0; i < lookbackLimit && current != nil; i++ {
        prev, err := l.GetBlockByHash(current.Header.PrevHash)
        if err != nil || prev == nil {
            break
        }

        // Block timestamps are stored in Unix milliseconds.
        currentTime := time.UnixMilli(current.Header.Timestamp)
        prevTime := time.UnixMilli(prev.Header.Timestamp)

        interval := currentTime.Sub(prevTime)

        // Ignore invalid or abnormal block timestamps.
        if interval > 0 && interval < 24*time.Hour {
            totalInterval += interval
            intervals++
        }

        current = prev
    }

    if intervals > 0 {
        averageBlockTime := totalInterval / time.Duration(intervals)

        switch {
        // The network is producing blocks too quickly:
        // increase the cryptographic difficulty to strengthen
        // the network against excessive block production.
        case averageBlockTime < targetBlockTime/2:
            difficulty = minDifficulty + 2

        case averageBlockTime < targetBlockTime:
            difficulty = minDifficulty + 1

        // The network is producing blocks slowly:
        // keep the minimum difficulty so that low-end smartphones
        // can continue participating in mining.
        default:
            difficulty = minDifficulty
        }
    }

    // Enforce the minimum difficulty boundary.
    if difficulty < minDifficulty {
        difficulty = minDifficulty
    }

    // Enforce the maximum difficulty boundary.
    if difficulty > maxDifficulty {
        difficulty = maxDifficulty
    }

    log.Printf(
        "[PoW] difficulty=%d | sampled_blocks=%d | avg_block_time=%s",
        difficulty,
        intervals,
        func() string {
            if intervals == 0 {
                return "unknown"
            }

            return (totalInterval / time.Duration(intervals)).
                Round(time.Second).
                String()
        }(),
    )

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

// 🔐 Derive deterministic miner key (authoritative identity)
priv, pub, err := DeriveMinerKey(miner.ID, miner.ConsciousnessFingerprint)
if err != nil {
    return fmt.Errorf("failed to derive miner identity key: %w", err)
}

// 🔐 ON-CHAIN IDENTITY ANCHOR (consensus-critical)
commitment, _, err := guardian.RegisterOrRestoreIdentity(
    miner.ConsciousnessFingerprint,
    miner.ID,
    hex.EncodeToString(CurrentNetworkID[:]),
    pub, // clé publique dérivée = autorité
    miner.Signature,
)
if err != nil {
    return fmt.Errorf("failed to register/restore miner identity: %w", err)
}

// 🔗 Persist identity in ledger state
exists, err := db.HasCommitment(commitment)
if err != nil {
    return err
}
if !exists {
    err = db.AddCommitment(commitment, pub, []byte(miner.ID))
    if err != nil {
        return fmt.Errorf("failed to anchor identity on-chain: %w", err)
    }
}

// 🔗 Link fingerprint → miner address
fpHash, err := guardian.FingerprintHash(miner.ConsciousnessFingerprint)
if err != nil {
    return err
}

fingerKey := []byte("fingerprint:" + fpHash)
normalized := strings.ToLower(strings.TrimSpace(miner.ID))

err = db.PutObject(fingerKey, []byte(normalized))
if err != nil {
    return err
}

// ────────────── Load miner persistent balance for UX state ──────────────
balKey := []byte("balance:" + miner.ID)
bal := &Balance{}
if err := db.GetObject(balKey, bal); err == nil {
    // IMANI stored in Pastabo-scale internally → convert for UX
    state.IMANI = float64(bal.IMANI) / float64(PastaboPerEXPLO)
} else {
    state.IMANI = 0
}
state.LUMEN = math.Min(math.Sqrt(state.IMANI), MaxLumen)

    // 2. Donation bounds enforcement
    if donationPercent < MinDonationPercent || donationPercent > MaxDonationPercent {
        return errors.New("donation percent out of allowed range [0.0, 0.1]")
    }

// 3. ────────────── Strict Daily Cooldown (On-chain indexed) ──────────────
nowMs := time.Now().UnixMilli()

// Network-wide UTC day anchor (CONSENSUS - milliseconds)
dayStart := (nowMs / 86400000) * 86400000

used, err := db.HasDailyPoW(miner.ID, dayStart)
if err != nil {
    return fmt.Errorf("failed to check daily PoW index: %w", err)
}

if used {
    next := dayStart + 86400000
    remainingMs := next - nowMs

    hours := remainingMs / (3600 * 1000)
    minutes := (remainingMs % (3600 * 1000)) / (60 * 1000)

    fmt.Printf(
        "⏳ Miner %s has already mined today. Next mining allowed in %dh %02dm\n",
        miner.ID[:8], hours, minutes,
    )
    return fmt.Errorf("daily mining limit reached for this miner")
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

// Small random jitter (mobile-only) to reduce collision probability
time.Sleep(time.Duration(rand.Intn(150)+50) * time.Millisecond)


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

    rewardPastabo, err := halving.GetCurrentRewardPastabo(db.DB())
if err != nil {
    return fmt.Errorf("failed to retrieve current halving reward: %w", err)
}

// -----------------------------
// 8. Deterministic reward calculation via halving schedule (Pastabo units)
// -----------------------------
rewardPastabo, err = halving.GetCurrentRewardPastabo(db.DB())
if err != nil {
    return fmt.Errorf("failed to retrieve current halving reward: %w", err)
}
// Donation in Pastabo (integer precision)
donationPastabo := uint64(float64(rewardPastabo) * donationPercent + 0.5)

// Net reward (Pastabo) for miner
netRewardPastabo := rewardPastabo - donationPastabo

// ⚠️ Ensure net reward is at least 1 Pastabo to avoid zero issuance
if netRewardPastabo == 0 {
    if rewardPastabo > 0 {
        netRewardPastabo = 1
        donationPastabo = rewardPastabo - 1
    } else {
        return errors.New("halving reward is zero — cannot mine")
    }
}

// 9. Enforce global supply cap – fast meta-key lookup

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

// ✅ UX feedback
fmt.Printf("⛏️ Reward for this mining session: %.8f EXPLO (donation: %.8f EXPLO)\n",
    netRewardEXPLO, donationEXPLO)

    // 10.────────────── Corrected Spiritual Fund & Heig
// -----------------------------
// 11. Spiritual fund operations (CONSENSUS SAFE)
// -----------------------------
var donationTx *Transaction

if donationPastabo > 0 {
    timestamp := time.Now().UnixMilli()
    payload := fmt.Sprintf(
        "IMANI|%s|%d|%d",
        miner.ID,
        donationPastabo, // Pastabo authoritative
        timestamp,
    )

// Derive miner key for signing (used only for authenticity, not address)

    signature := ed25519.Sign(priv, []byte(payload))

    donationTx = &Transaction{
        From:          miner.ID, // ✅ Credit direct on miner ID
        To:            "IMANI_POOL",
        AmountEXP:     float64(donationPastabo) / float64(PastaboPerEXPLO), // UX display
        AmountIM:      0,
        AmountPastabo: donationPastabo, // CONSENSUS
        IsReward:      false,
        Note:          "Signed IMANI donation",
        Timestamp:     timestamp,
        Nonce:         time.Now().UnixNano(),
        Signature:     signature,
    }

    // ✅ Compute TxHash immediately after signing
    donationTx.TxHash = donationTx.ComputeHash()
}

// -----------------------------
// 12. Create coinbase-style mining reward transaction
// -----------------------------
// IMANI reward = donationPastabo * 1000 (guaranteed)
imaniPastabo := donationPastabo * 1000

// ✅ Create a reward (coinbase) transaction with no sender
rewardTx := &Transaction{
    From:          "", // MUST be empty for coinbase / reward tx
    To:            miner.ID,
    AmountEXP:     float64(netRewardPastabo) / float64(PastaboPerEXPLO), // miner receives net reward
    AmountIM:      0,
    AmountIMPastabo: imaniPastabo, // authoritative IMANI
    AmountPastabo: netRewardPastabo,
    IsReward:      true,
    Note:          "Mining reward",
    Timestamp:     time.Now().UnixMilli(),
    Nonce:         time.Now().UnixNano(),
    Signature:     nil, // optional for reward tx
}
rewardTx.TxHash = rewardTx.ComputeHash()
// -----------------------------
// 13. Construct block (robust & consensus-ready)
// -----------------------------
newHeight := prevBlock.Header.Height + 1

// Include all transactions: reward + optional donation
txs := []Transaction{*rewardTx}
if donationTx != nil {
    txs = append(txs, *donationTx)
}

// Instantiate the block with full structure, anchored to the previous hash
block, err := NewBlock(
    newHeight,  // Deterministic height based on previous block
    prevHash,   // Parent block hash (consensus-critical)
    miner.ID,   // Miner address producing this block
    txs,        // Transactions included in the block
    0,          // PoW placeholder, updated after mining
)
if err != nil {
    return fmt.Errorf("block construction failed: %w", err)
}

// Attach consensus-critical metadata
block.Header.MinerFingerprintHash = fpHash  // Miner fingerprint hash for on-chain identity verification
block.Header.DailyPoW = dailyPoW           // Daily PoW structure anchoring block to mining session

// Ensure each reward transaction carries IMANI amount correctly
// This enforces deterministic recording of IMANI rewards in Pastabo units
for i := range block.Transactions {
    if block.Transactions[i].IsReward && block.Transactions[i].AmountIMPastabo == 0 {
        block.Transactions[i].AmountIMPastabo = imaniPastabo
    }
}

// -----------------------------
// 14. Sign block
// -----------------------------

if err := block.SignBlock(priv); err != nil {
    return fmt.Errorf("block signing failed: %w", err)
}

block.BlockHash = block.ComputeFinalHash()

// -----------------------------
// 14a. Enforce MinerAddress ↔ PubKey binding (audit/consensus)
// -----------------------------
pubKeyBytes, err := base64.StdEncoding.DecodeString(block.PublicKey)
if err != nil {
    return fmt.Errorf("failed to decode block public key: %w", err)
}
if len(pubKeyBytes) != ed25519.PublicKeySize {
    return fmt.Errorf("invalid miner pubkey length")
}

// Store canonical mapping: MinerAddress -> PubKey
err = db.PutObject([]byte("miner_pubkey:"+block.Header.MinerAddress), pubKeyBytes)
if err != nil {
    return fmt.Errorf("failed to store miner pubkey: %w", err)
}

// Optional: verify block signature matches pubkey
sigBytes, err := base64.StdEncoding.DecodeString(block.Signature)
if err != nil {
    return fmt.Errorf("failed to decode block signature: %w", err)
}
if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), block.ComputeHashData(), sigBytes) {
    return fmt.Errorf("block signature does not match miner pubkey")
}
// -----------------------------
// 15. Re-check chain tip (atomic safety)
// -----------------------------

// Re-fetch the current chain tip from the ledger to ensure no concurrent changes occurred
currentPrev, err := db.GetLatestBlock()
if err != nil {
    return fmt.Errorf("failed to re-fetch previous block before validation: %w", err)
}

// Guard against missing genesis block (should never happen in a healthy ledger)
if currentPrev == nil {
    return errors.New("genesis block missing during validation")
}

// Compare hashes to verify that the ledger tip has not changed during mining
// This prevents accidental orphaning or double-mining due to concurrent block insertion
if currentPrev.BlockHash != prevHash {
    return fmt.Errorf(
        "chain tip changed during mining (expected %s, got %s) — retry",
        prevHash[:12]+"...", currentPrev.BlockHash[:12]+"...",
    )
}

// -----------------------------
// 16. Consensus validation
// -----------------------------

if err := block.Validate(currentPrev, db); err != nil {
    return fmt.Errorf("self-mined block rejected: %w", err)
}

if err := db.ApplyBlock(block); err != nil {
    return fmt.Errorf("ledger rejected mined block: %w", err)
}

err = halving.IncrementMinerCount(db.DB())
if err != nil {
    return fmt.Errorf("failed to increment miner count: %w", err)
}

level, err := halving.UpdateHalvingLevelIfNeeded(db.DB())
if err != nil {
    return fmt.Errorf("failed to update halving level: %w", err)
}

// -----------------------------
// 16a. Persist miner balance & update UX (atomic, single commit)
// -----------------------------
// Reload balance (ledger is source of truth)
balKey = []byte("balance:" + miner.ID)
bal = &Balance{}

_ = db.GetObject(balKey, bal)

state.EXPLO = float64(bal.EXPLO) / float64(PastaboPerEXPLO)
state.IMANI = float64(bal.IMANI) / float64(PastaboPerEXPLO)
state.LUMEN = math.Min(math.Sqrt(state.IMANI), MaxLumen)

// Update human-readable UX state for mobile/wallet display
state.EXPLO = float64(bal.EXPLO) / float64(PastaboPerEXPLO)
state.IMANI = float64(bal.IMANI) / float64(PastaboPerEXPLO)
state.LUMEN = math.Min(math.Sqrt(state.IMANI), MaxLumen)

// -----------------------------
// Display current halving level (UX / info)
// -----------------------------
fmt.Println()
fmt.Println("════════════ 🔥 HALVING LEVEL 🔥 ════════════")
fmt.Printf("📊 Level : %d\n", level)
fmt.Println("════════════════════════════════════════════")
fmt.Println()

// Optional: log total supply from ledger for display
totalPastabo, _ := db.ReadUint64("meta:circulating_pastabo")
fmt.Printf(
    "⛓️ Block #%d mined — %.8f EXPLO issued (Total Supply: %.8f EXPLO)\n",
    block.Header.Height,
    float64(netRewardPastabo)/float64(PastaboPerEXPLO),
    float64(totalPastabo)/float64(PastaboPerEXPLO),
)

// Broadcast block to P2P network
if p2pNode != nil {
    p2pNode.BroadcastBlockInv([]byte(block.BlockHash), "BLOCK_FULL")
}

// Update last mine timestamp for UX
state.LastMineUnix = now

// -----------------------------
// Display mining summary (UX)
// -----------------------------
fmt.Println()
fmt.Println("════════════ 💎 MINING SUMMARY 💎 ════════════")
fmt.Printf("⛓️  Block Height : %d\n", block.Header.Height)
fmt.Printf("🎁 Reward        : %.8f EXPLO\n", float64(netRewardPastabo)/float64(PastaboPerEXPLO))
fmt.Printf("💸 Donation      : %.8f EXPLO\n", donationEXPLO)
fmt.Println("──────────────────────────────────────────────")
fmt.Printf("🔹 EXPLO : %.8f\n", float64(netRewardPastabo)/float64(PastaboPerEXPLO))
fmt.Printf("✨ IMANI : %.4f\n", state.IMANI)
fmt.Printf("🌟 LUMEN : %.4f / %.2f\n", state.LUMEN, MaxLumen)
fmt.Println("══════════════════════════════════════════════")
fmt.Println()

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
func CreditSoul(db *Ledger, minerID string, amountPastabo uint64) error {
    balanceKey := []byte("balance:" + minerID)
    bal := &Balance{}
    if err := db.GetObject(balanceKey, bal); err != nil {
        bal = &Balance{}
    }

    bal.EXPLO += amountPastabo // ← plus de float, uniquement uint64
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

    key := []byte("miner_last_ts:" + minerID)

    data, err := db.GetBytes(key)
    if err == nil {
        return int64(bytesToU64(data)), nil
    }

    if err != badger.ErrKeyNotFound {
        return 0, err
    }

    // -------- Fallback for legacy chains (one-time scan) --------
    block, err := db.GetLatestBlock()
    if err != nil {
        return 0, err
    }

    for block != nil {

        if block.Header.MinerAddress == minerID {

            ts := block.Header.Timestamp / 1000

            // cache for future calls (safe write)
            buf := make([]byte, 8)
            binary.BigEndian.PutUint64(buf, uint64(ts))

            _ = db.db.Update(func(txn *badger.Txn) error {
                return txn.Set(key, buf)
            })

            return ts, nil
        }

        if block.Header.PrevHash == "" {
            break
        }

        block, err = db.GetBlockByHash(block.Header.PrevHash)
        if err != nil {
            return 0, err
        }
    }

    return 0, nil
}

// IsMiningAllowedFromChain enforces exactly ONE mining per network UTC day
// based purely on on-chain indexed PoW (no sliding timestamp logic).
func IsMiningAllowedFromChain(db *Ledger, minerID string, now int64) (bool, int64, error) {

    last, err := GetLastMiningTimestampFromChain(db, minerID)
    if err != nil {
        return false, 0, err
    }

    if last == 0 {
        return true, 0, nil
    }

    nextAllowed := (last/SecondsPerDay + 1) * SecondsPerDay

    if now >= nextAllowed {
        return true, 0, nil
    }

    return false, nextAllowed - now, nil
}

// VerifyDailyPoWLegacy verifies legacy PoW (no network anchor, no difficulty enforcement)
func VerifyDailyPoWLegacy(minerID string, pow MiningPoW) bool {

    base := minerID + "|" +
        strconv.FormatInt(pow.DayStart, 10) + "|" + // ✅ ms
        strconv.FormatUint(pow.Nonce, 10)

    hash := sha3.Sum256([]byte(base))
    hashHex := hex.EncodeToString(hash[:])

    if hashHex != pow.HashHex {
        return false
    }

    prefix := strings.Repeat("0", int(pow.Difficulty))
    return strings.HasPrefix(hashHex, prefix)
}

// VerifyDailyPoW verifies the daily PoW proof against the previous block hash.
// Returns true if valid, false otherwise.
func VerifyDailyPoW(minerID string, pow MiningPoW, prevBlockHash string) bool {

    // 🔹 Legacy mode
    if pow.PrevBlockHash == "" {

        base := minerID + "|" +
            strconv.FormatInt(pow.DayStart, 10) + "|" + // ✅ ms
            strconv.FormatUint(pow.Nonce, 10)

        hash := sha3.Sum256([]byte(base))
        hashHex := hex.EncodeToString(hash[:])

        if hashHex != pow.HashHex {
            return false
        }

        prefix := strings.Repeat("0", int(pow.Difficulty))
        return strings.HasPrefix(hashHex, prefix)
    }

    // 🔒 Anchored PoW
    if pow.PrevBlockHash != prevBlockHash {
        return false
    }

    hashHex := computePoWHash(
        prevBlockHash,
        minerID,
        pow.DayStart, // ✅ ms
        pow.Nonce,
    )

    if hashHex != pow.HashHex {
        return false
    }

    prefix := strings.Repeat("0", int(pow.Difficulty))
    return strings.HasPrefix(hashHex, prefix)
}

func computePoWHash(prevHash, minerID string, dayStart int64, nonce uint64) string {
    base := prevHash + "|" + minerID + "|" + strconv.FormatInt(dayStart, 10) + "|" // ✅ ms
    input := base + strconv.FormatUint(nonce, 10)

    h := sha3.Sum256([]byte(input))
    return hex.EncodeToString(h[:])
}

func (l *Ledger) HasDailyPoW(minerID string, dayStart int64) (bool, error) {
    key := []byte(fmt.Sprintf("daily_pow:%s:%d", minerID, dayStart)) // ✅ ms
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

// AddDonationSigned adds an IMANI donation for a miner, ensuring proper signature validation.
// The donation must be signed with the miner's deterministic Ed25519 key.
// AddDonationSigned creates a signed IMANI donation transaction for the miner
// and submits it to the ledger for application. It does NOT directly modify balances
// or the IMANI pool.
// AddDonationSigned adds a signed IMANI donation to the pool.
// The donation must be signed with the miner's deterministic Ed25519 key.
// Returns error if validation or persistence fails.
func (l *Ledger) AddDonationSigned(
    miner *Miner,
    amountPastabo uint64,
    signature []byte,
    timestamp int64,
) error {
    if miner == nil {
        return errors.New("miner cannot be nil")
    }

    if amountPastabo == 0 {
        return errors.New("donation must be positive")
    }

    // Anti-replay: timestamp must be recent (30s window)
    now := time.Now().UnixMilli()
    if now-timestamp > 30000 || timestamp > now {
        return errors.New("invalid or expired timestamp")
    }

    payload := fmt.Sprintf("IMANI|%s|%d|%d",
        miner.ID,
        amountPastabo,
        timestamp,
    )

    if !ed25519.Verify(miner.PubKey, []byte(payload), signature) {
        return errors.New("invalid signature for IMANI donation")
    }

    tx := &Transaction{
        From:          miner.ID,
        To:            "IMANI_POOL",
        AmountPastabo: amountPastabo,                                         // Consensus unit
        AmountEXP:     float64(amountPastabo) / float64(PastaboPerEXPLO),    // UX layer only
        AmountIM:      0,
        IsReward:      false,
        Timestamp:     timestamp,
        Nonce:         timestamp, // deterministic nonce
        Signature:     signature,
        Note:          "Signed IMANI donation",
    }

    // Canonical hash for ledger integrity
    tx.TxHash = tx.ComputeHash()

    // Apply + persist atomically
    _, err := l.ApplyAndPersistTransaction(tx)
    if err != nil {
        log.Printf("⚠️ AddDonationSigned failed | miner=%s amount=%.8f err=%v",
            miner.ID[:12], tx.AmountEXP, err)
        return err
    }

    log.Printf("✅ IMANI donation signed | miner=%s amount=%.8f EXPLO",
        miner.ID[:12], tx.AmountEXP)

    return nil
}

// SignDonation creates the Ed25519 signature of an IMANI donation
// Returns both the signature and the timestamp used, so AddDonationSigned can verify
func SignDonation(miner *Miner, amountPastabo uint64) ([]byte, int64, error) {

    priv, _, err := DeriveMinerKey(miner.ID, miner.ConsciousnessFingerprint)
    if err != nil {
        return nil, 0, err
    }

    timestamp := time.Now().UnixMilli()

    payload := fmt.Sprintf("IMANI|%s|%d|%d",
        miner.ID,
        amountPastabo,
        timestamp,
    )

    sig := ed25519.Sign(priv, []byte(payload))
    return sig, timestamp, nil
}


type MinerLite struct {
    ID    string
    IMANI float64
}

// GetEligibleMiners scans all registered miners and returns their
// IMANI balance converted to EXPLO (human-readable layer).
//
// IMPORTANT:
// - IMANI is stored internally in Pastabo units for consensus safety.
// - This function exposes IMANI in EXPLO (float64) for UX-level logic only.
// - No consensus-critical computation should rely on this function.
func (l *Ledger) GetEligibleMiners() []MinerLite {
    var eligible []MinerLite

    _ = l.DB().View(func(txn *badger.Txn) error {
        it := txn.NewIterator(badger.DefaultIteratorOptions)
        defer it.Close()

        prefix := []byte(PrefixMiner)
        for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
            key := it.Item().Key()
            addr := string(key[len(prefix):])

            bal := &Balance{}
            if err := l.GetObject([]byte("balance:"+addr), bal); err != nil {
                // Skip corrupted or missing balances safely
                continue
            }

            // Convert internal Pastabo → EXPLO (UX layer)
            imaniEXPLO := float64(bal.IMANI) / float64(PastaboPerEXPLO)

            eligible = append(eligible, MinerLite{
                ID:    addr,
                IMANI: imaniEXPLO,
            })
        }
        return nil
    })

    return eligible
}

// GetIMANIPool returns the current IMANI fund pool balance
// expressed in EXPLO (human-readable layer).
//
// Internally, the pool is stored in Pastabo units for consensus safety.
// This function performs a safe conversion to EXPLO.
func (l *Ledger) GetIMANIPool() float64 {
    pastabo, err := l.ReadUint64("meta:imani_pool")
    if err != nil {
        return 0
    }
    return float64(pastabo) / float64(PastaboPerEXPLO)
}

// DeductIMANIPool deducts an amount from the IMANI fund pool.
//
// IMPORTANT:
// - Input amount is in EXPLO (UX/human layer)
// - Conversion to Pastabo is done internally
// - All consensus-critical arithmetic uses uint64 Pastabo
func (l *Ledger) DeductIMANIPool(amount float64) error {
    if amount <= 0 {
        return fmt.Errorf("invalid IMANI pool deduction amount: must be positive")
    }

    // Convert EXPLO → Pastabo (consensus layer)
    deductPastabo := uint64(amount * float64(PastaboPerEXPLO))
    // Optional: add rounding safety if needed
    // deductPastabo := uint64(math.Round(amount * float64(PastaboPerEXPLO)))

    currentPastabo, err := l.ReadUint64("meta:imani_pool")
    if err != nil {
        return fmt.Errorf("failed to read IMANI pool: %w", err)
    }

    if currentPastabo < deductPastabo {
        return fmt.Errorf("insufficient IMANI pool balance")
    }

    return l.WriteUint64("meta:imani_pool", currentPastabo-deductPastabo)
}


// GetTotalReceivedFromIMANI returns the total EXPLO a miner has received
// from IMANI blessings / fund distributions (human-readable layer).
//
// IMPORTANT:
// - Value is derived from TotalIMANIReceived field stored in Pastabo units
// - Returns 0 if miner not found or balance corrupted
func (l *Ledger) GetTotalReceivedFromIMANI(minerID string) float64 {
    bal := &Balance{}
    key := []byte("balance:" + minerID)

    if err := l.GetObject(key, bal); err != nil {
        return 0
    }

    return float64(bal.TotalIMANIReceived) / float64(PastaboPerEXPLO)
}

// IsDuplicateFingerprintOnChain checks if the given sacred words fingerprint is already registered on-chain.
// Returns true if it exists, false otherwise.
// This is consensus-critical to prevent duplicate miner identities.
func (l *Ledger) IsDuplicateFingerprintOnChain(words []string) (bool, error) {
    fpHash, err := guardian.FingerprintHash(words)
    if err != nil {
        return false, fmt.Errorf("fingerprint hash failed: %w", err)
    }

    key := []byte("fingerprint:" + fpHash)

    // Fast existence check
    _, err = l.GetBytes(key)
    if err == nil {
        return true, nil // déjà pris
    }
    if err == badger.ErrKeyNotFound {
        return false, nil // libre
    }

    return false, fmt.Errorf("on-chain lookup failed: %w", err)
}
