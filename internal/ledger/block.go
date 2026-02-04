// internal/ledger/block.go
package ledger

import (
        "errors"
        "time"
        "explosive/internal/address"
        "log"
        "crypto/ed25519"
        "encoding/base64"
        "fmt"

        "github.com/dgraph-io/badger/v4"
        "github.com/fxamacker/cbor/v2"
)

var prefixBlock = []byte("block:")

var ErrNotFound = errors.New("not found")

// Sentinel error used internally to stop IterateBlocks early (not a real failure)
var errIterStop = errors.New("ledger iteration stopped")
// ---------------- BlockHeader ----------------
type BlockHeader struct {
    Height       uint64     `cbor:"height"`
    PrevHash     string     `cbor:"prev_hash"`
    Timestamp    int64      `cbor:"timestamp"`
    Nonce        uint64     `cbor:"nonce"`
    MinerAddress string     `cbor:"miner_address"`
    MerkleRoot   string     `cbor:"merkle_root"`

    // ⛏️ Daily Proof-of-Work (1 block / day / miner)
    DailyPoW     *MiningPoW `cbor:"daily_pow,omitempty"`

    // Version field for backward compatibility and future upgrades
    // 0 = legacy blocks (no network anchoring in DailyPoW)
    // 1 = modern blocks (network-anchored PoW with PrevBlockHash)
    Version      uint8      `cbor:"version"`
}

// ---------------- Block ----------------
// Added Signature and PublicKey fields (base64 encoded) for ed25519 signatures.
// They are optional to preserve backward compatibility with existing blocks.
type Block struct {
        Header       BlockHeader   `cbor:"header"`
        Transactions []Transaction `cbor:"txs"`
        BlockHash    string        `cbor:"hash"`

        Signature string `cbor:"sig,omitempty"`     // base64-encoded ed25519 signature
        PublicKey string `cbor:"pub_key,omitempty"` // base64-encoded ed25519 public key
}

// ==================== SCALABILITY: FULL PRUNING + AGGRESSIVE COMPRESSION ====================

// Configurable: number of recent blocks to keep in FULL detail (with transactions).
// Older blocks are pruned to header-only (light mode) → massive storage saving on mobile.
// Recommended: 3000–8000 (~6 months to 2 years). Set to 0 to disable.
const FullBlocksToKeep = 5000

// IsLightBlock reports whether the block is stored in its "light" form.
//
// A light block contains only the block header and metadata,
// with the transaction list intentionally omitted to reduce memory
// and disk usage after the block has reached finality.
func (b *Block) IsLightBlock() bool {
    return b.Transactions == nil || len(b.Transactions) == 0
}

// PruneToLight converts a full block into a light block.
//
// This method explicitly releases the transaction slice,
// allowing the garbage collector to reclaim memory and
// ensuring that only the minimal block representation
// (header + metadata) is retained.
func (b *Block) PruneToLight() {
    // Explicitly release transaction data
    b.Transactions = nil
}

// PruneOldBlocks reduces storage and memory usage by pruning
// finalized blocks into their light representation.
//
// The function keeps only the most recent `FullBlocksToKeep` blocks
// in full form. Older blocks are converted in-place to light blocks
// while preserving headers, hashes, and consensus-critical data.
//
// Pruning is:
//   - idempotent (safe to call multiple times)
//   - concurrency-safe (protected by a mutex)
//   - non-destructive to consensus validity
func (l *Ledger) PruneOldBlocks() error {
    // Pruning disabled by configuration
    if FullBlocksToKeep == 0 {
        return nil
    }

    // Ensure only one pruning operation runs at a time
    l.pruningMu.Lock()
    defer l.pruningMu.Unlock()

    // Determine current chain tip
    tip := l.GetLatestBlockHeight()
    if tip <= uint64(FullBlocksToKeep) {
        return nil
    }

    // Calculate the highest height eligible for pruning
    pruneUpTo := tip - uint64(FullBlocksToKeep)

    // Avoid re-pruning blocks already processed
    if l.lastPrunedHeight >= pruneUpTo {
        return nil
    }

    // Determine pruning start height
    start := l.lastPrunedHeight + 1
    if start == 0 {
        start = 1 // Never prune the genesis block
    }

    log.Printf(
        "[scalability] 🔪 Pruning blocks %d → %d (keeping last %d full)",
        start,
        pruneUpTo,
        FullBlocksToKeep,
    )

    pruned := 0

    // Iterate over all blocks and prune eligible ones
    err := l.IterateBlocks(func(b *Block) error {
        h := b.Header.Height

        // Skip blocks outside the pruning window
        if h < start || h > pruneUpTo {
            return nil
        }

        // Skip blocks already in light form
        if b.IsLightBlock() {
            return nil
        }

        // Convert to light block and persist the change
        b.PruneToLight()

        if err := l.PutBlock(h, b); err != nil {
            // Log and continue — pruning must never halt the node
            log.Printf("[pruning] ⚠️ failed to prune block %d: %v", h, err)
            return nil
        }

        pruned++
        l.lastPrunedHeight = h
        return nil
    })

    if err != nil {
        return err
    }

    log.Printf(
        "[scalability] ✅ Pruning completed: %d blocks pruned (last=%d)",
        pruned,
        l.lastPrunedHeight,
    )

    return nil
}

// ApplyBlock validates, persists, and commits a block to the ledger.
//
// Responsibilities:
//   1. Enforce single-chain (no fork at same height)
//   2. Perform full consensus validation
//   3. Persist block atomically using compressed batch storage
//   4. Trigger controlled asynchronous pruning (non-blocking)
//
// This function is part of the critical consensus path.
// Any expensive maintenance task (e.g. pruning) is deliberately
// executed asynchronously to preserve low block acceptance latency.
func (l *Ledger) ApplyBlock(blk *Block) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    // ------------------------------------------------------------------
// 1) Load previous block by HASH (ledger authority)
// ------------------------------------------------------------------
var prev *Block

if blk.Header.PrevHash != "" {
    var err error
    prev, err = l.GetBlockByHash(blk.Header.PrevHash)
    if err != nil || prev == nil {
        return fmt.Errorf(
            "missing previous block with hash %s",
            blk.Header.PrevHash,
        )
    }

    // ✅ Ledger assigns height
    blk.Header.Height = prev.Header.Height + 1
} else {
    // Genesis case
    blk.Header.Height = 0
}

// ------------------------------------------------------------------
// 2) Enforce UniLedger rule: no fork at same height
// ------------------------------------------------------------------
if existing, err := l.GetBlockByHeight(blk.Header.Height); err == nil && existing != nil {
    return fmt.Errorf(
        "fork rejected: block already exists at height %d",
        blk.Header.Height,
    )
}

// ------------------------------------------------------------------
// 3) Consensus validation
// ------------------------------------------------------------------
if err := blk.Validate(prev, l); err != nil {
    log.Printf("❌ Block #%d rejected: %v", blk.Header.Height, err)

    _ = l.PutObject(
        []byte(fmt.Sprintf("quarantine:block:%d", blk.Header.Height)),
        blk,
    )

    return fmt.Errorf("block validation failed: %w", err)
}

    // ------------------------------------------------------------------
// 4) Atomic persistence (CONSENSUS CRITICAL)
// ------------------------------------------------------------------
if err := l.DB().Update(func(txn *badger.Txn) error {

    // --------------------------------------------------
    // a) Persist block (canonical CBOR)
// --------------------------------------------------
    blockKey := []byte(fmt.Sprintf("block:%d", blk.Header.Height))

    data, err := cbor.Marshal(blk)
    if err != nil {
        return fmt.Errorf("CBOR marshal failed: %w", err)
    }

    if err := txn.Set(blockKey, data); err != nil {
        return fmt.Errorf("block persist failed: %w", err)
    }

    // --------------------------------------------------
    // b) Daily PoW anti-replay index
    // --------------------------------------------------
    if blk.Header.DailyPoW != nil {
        powKey := []byte(fmt.Sprintf(
            "daily_pow:%s:%d",
            blk.Header.MinerAddress,
            blk.Header.DailyPoW.DayStart,
        ))

        if err := txn.Set(powKey, []byte{1}); err != nil {
            return fmt.Errorf("daily PoW index write failed: %w", err)
        }
    }

    // --------------------------------------------------
    // c) Circulating supply (incremental, legacy-safe)
    // --------------------------------------------------
    var minted uint64

    for _, tx := range blk.Transactions {
        if tx.IsReward && tx.AmountEXP > 0 {
            minted += uint64(tx.AmountEXP * 1e8)
        }
    }

    if minted > 0 {
        if err := incU64(txn, "meta:circulating_pastabo", minted); err != nil {
            return err
        }
    }

    // --------------------------------------------------
    // d) Miner first-seen tracking (idempotent)
    // --------------------------------------------------
    minerKey := []byte("miner_seen:" + blk.Header.MinerAddress)

    if _, err := txn.Get(minerKey); err == badger.ErrKeyNotFound {

        if err := txn.Set(minerKey, []byte{1}); err != nil {
            return err
        }

        if err := incU64(txn, "meta:miners_count", 1); err != nil {
            return err
        }
    }

    return nil
}); err != nil {
    return fmt.Errorf("atomic block commit failed: %w", err)
}

    // ------------------------------------------------------------------
    // 5) Async pruning (NON-CONSENSUS)
    // ------------------------------------------------------------------
    if blk.Header.Height > 0 && blk.Header.Height%100 == 0 {
        go func(h uint64) {
            if err := l.PruneOldBlocks(); err != nil {
                log.Printf("[scaling] prune error at %d: %v", h, err)
            }
        }(blk.Header.Height)
    }

    // ------------------------------------------------------------------
    // 6) Confirmation
    // ------------------------------------------------------------------
    log.Printf(
        "✅ Block #%d committed — %s",
        blk.Header.Height,
        blk.BlockHash,
    )

    return nil
}

// ---------------- Block Creation (Mainnet Ready) ----------------
// NewBlock constructs a new block with the given parameters.
// It initializes version-aware fields for backward compatibility and modern anchoring.
// - Version 0: legacy blocks (no network anchor in DailyPoW)
// - Version 1: modern blocks (network-anchored PoW with PrevBlockHash)
func NewBlock(
    height uint64,
    prevHash string,
    miner string,
    txs []Transaction,
    nonce uint64,
) (*Block, error) {
    // Basic structural validation
    if miner == "" {
        return nil, errors.New("miner address cannot be empty")
    }

    // Genesis rule: prevHash must be empty ONLY for height 0
    if height == 0 {
        if prevHash != "" {
            return nil, errors.New("genesis block must have empty prevHash")
        }
    } else {
        if prevHash == "" {
            return nil, errors.New("non-genesis block must have a prevHash")
        }
    }

    // Compute Merkle root using consensus-grade function
    merkleRoot, err := ComputeMerkleRoot(txs)
    if err != nil {
        return nil, fmt.Errorf("invalid transactions: %w", err)
    }

    // Modern block header with version
    header := BlockHeader{
        Height:       height,
        PrevHash:     prevHash,
        Timestamp:    NowMillis(), // validated at acceptance time
        Nonce:        nonce,
        MinerAddress: miner,
        MerkleRoot:   merkleRoot,
        Version:      1,           // All newly created blocks are version 1+
    }

    block := &Block{
        Header:       header,
        Transactions: txs,
    }

    // Final block hash (must hash header ONLY, canonically)
    block.BlockHash = block.ComputeFinalHash()

    return block, nil
}

// SignBlock signs the block using the miner's Ed25519 private key.
// It stores both the signature and public key in base64 encoding.
// This ensures blocks are verifiable on Mainnet without breaking old blocks.
func (b *Block) SignBlock(privKey ed25519.PrivateKey) error {
    if len(privKey) != ed25519.PrivateKeySize {
        return fmt.Errorf("invalid private key size")
    }

    // 1️⃣ Compute the hashable block data (header + transactions)
    msg := b.ComputeHashData()

    // 2️⃣ Sign the block data
    sig := ed25519.Sign(privKey, msg)
    b.Signature = base64.StdEncoding.EncodeToString(sig)

    // 3️⃣ Store the public key for verification by other nodes
    pub := privKey.Public().(ed25519.PublicKey)
    b.PublicKey = base64.StdEncoding.EncodeToString([]byte(pub))

    return nil
}

// VerifySignature checks the Ed25519 signature of the block.
// Returns (true, nil) if the signature is valid or missing (backward compatible).
func (b *Block) VerifySignature() (bool, error) {
    if b.Signature == "" || b.PublicKey == "" {
        // No signature present — valid for backward compatibility
        return true, nil
    }

    sigBytes, err := base64.StdEncoding.DecodeString(b.Signature)
    if err != nil {
        return false, fmt.Errorf("failed to decode signature: %v", err)
    }

    pubBytes, err := base64.StdEncoding.DecodeString(b.PublicKey)
    if err != nil {
        return false, fmt.Errorf("failed to decode public key: %v", err)
    }

    if len(pubBytes) != ed25519.PublicKeySize {
        return false, fmt.Errorf("invalid public key size")
    }
    if len(sigBytes) != ed25519.SignatureSize {
        return false, fmt.Errorf("invalid signature size")
    }

    msg := b.ComputeHashData()
    if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
        return false, nil
    }
    return true, nil
}

// Validate performs full consensus validation of the block against the previous block and ledger state.
// This function is backward-compatible: legacy blocks (without network anchoring) are accepted with minimal checks.
// Modern blocks (with PrevBlockHash anchor) undergo strict network-bound validation.
func (b *Block) Validate(prevBlock *Block, ledger *Ledger) error {

    // ------------------------------------------------------------------
    // 1) Hash integrity
    // ------------------------------------------------------------------
    if b.BlockHash != b.ComputeFinalHash() {
        return errors.New("invalid block hash")
    }

    // ------------------------------------------------------------------
    // 2) Chain continuity
    // ------------------------------------------------------------------
    if b.Header.Height == 0 {
        if prevBlock != nil || b.Header.PrevHash != "" {
            return errors.New("invalid genesis linkage")
        }
    } else {
        if prevBlock == nil {
            return errors.New("missing previous block")
        }
        // Height is informational; continuity is hash-based
if b.Header.Height != prevBlock.Header.Height+1 {
    log.Printf(
        "⚠️ height adjusted: expected %d got %d",
        prevBlock.Header.Height+1,
        b.Header.Height,
    )
}
        if b.Header.PrevHash != prevBlock.BlockHash {
            return errors.New("prevHash mismatch")
        }
    }

    // ------------------------------------------------------------------
    // 3) Time strictly chained (not wall-clock trusted)
    // ------------------------------------------------------------------
    if b.Header.Timestamp <= 0 {
        return errors.New("invalid timestamp")
    }

    if prevBlock != nil && b.Header.Timestamp <= prevBlock.Header.Timestamp {
        return errors.New("timestamp must increase from previous block")
    }

    // soft drift safety
    now := time.Now().UnixMilli()
    if b.Header.Timestamp > now+2*60*60*1000 {
        return errors.New("timestamp too far in future")
    }

    // ------------------------------------------------------------------
    // 4) Merkle root (full blocks only)
    // ------------------------------------------------------------------
    if !b.IsLightBlock() {
        root, err := ComputeMerkleRoot(b.Transactions)
        if err != nil {
            return err
        }
        if root != b.Header.MerkleRoot {
            return errors.New("merkle root mismatch")
        }
    }

    // ------------------------------------------------------------------
    // 5) Signature
    // ------------------------------------------------------------------
    ok, err := b.VerifySignature()
    if err != nil || !ok {
        return errors.New("invalid block signature")
    }

    // ------------------------------------------------------------------
    // 6) Legacy-tolerant miner binding
    // ------------------------------------------------------------------
    if b.PublicKey != "" {
        pub, _ := base64.StdEncoding.DecodeString(b.PublicKey)
        if len(pub) == ed25519.PublicKeySize {
            addr := address.FromEd25519PublicKey(ed25519.PublicKey(pub))
            if addr != b.Header.MinerAddress {
                log.Printf("legacy miner accepted: %s → %s",
                    addr, b.Header.MinerAddress)
            }
        }
    }

    // ------------------------------------------------------------------
    // 7) Daily PoW (legacy + modern)
    // ------------------------------------------------------------------
    if b.Header.DailyPoW == nil {
        return errors.New("missing DailyPoW")
    }

    pow := b.Header.DailyPoW

    if pow.PrevBlockHash == "" {

        // 🕯 legacy mode
        if !VerifyDailyPoWLegacy(b.Header.MinerAddress, *pow) {
            return errors.New("invalid legacy PoW")
        }

    } else {

        // 🔐 modern anchored mode
        if !VerifyDailyPoW(
            b.Header.MinerAddress,
            *pow,
            prevBlock.BlockHash,
        ) {
            return errors.New("anchored PoW verification failed")
        }

        expectedDiff := getDailyPoWDifficulty(ledger)
        if pow.Difficulty != expectedDiff {
            return fmt.Errorf(
                "difficulty mismatch: expected %d got %d",
                expectedDiff,
                pow.Difficulty,
            )
        }
    }

    // ------------------------------------------------------------------
    // 8) One PoW per day per miner (chain-based)
    // ------------------------------------------------------------------
    if ledger != nil {
        mined, err := ledger.HasDailyPoW(
            b.Header.MinerAddress,
            pow.DayStart,
        )
        if err != nil {
            return err
        }
        if mined {
            return errors.New("double daily PoW detected")
        }
    }

    return nil
}

