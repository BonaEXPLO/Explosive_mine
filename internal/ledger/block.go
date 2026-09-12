// internal/ledger/block.go
package ledger

import (
        "errors"
        "time"
        "log"
        "strings"
        "encoding/binary"
        "crypto/ed25519"
        "encoding/base64"
        "fmt"

        "github.com/dgraph-io/badger/v4"
        "explosive/internal/address"
        "explosive/internal/compressor"
        "github.com/fxamacker/cbor/v2"
)

var prefixBlock = []byte("block:")

var ErrNotFound = errors.New("not found")

// Sentinel error used internally to stop IterateBlocks early (not a real failure)
var errIterStop = errors.New("ledger iteration stopped")
// ---------------- BlockHeader ----------------
type BlockHeader struct {
        Height       uint64               `cbor:"height"`
        PrevHash     string               `cbor:"prev_hash"`
        Timestamp    int64                `cbor:"timestamp"`
        Nonce        uint64               `cbor:"nonce"`
        MinerAddress string               `cbor:"miner_address"`
        MerkleRoot   string               `cbor:"merkle_root"`

        // ⛏️ Daily Proof-of-Work (1 block / day / miner)
        DailyPoW     *MiningPoW           `cbor:"daily_pow,omitempty"`

        // SHA3-256 hash of the miner's consciousness fingerprint (4 sacred words)
        // Included in the block for consensus: allows ApplyBlock to verify uniqueness
        // without relying on GetMiner() (local state).
        // Required for blocks with version ≥ 1.
        // Empty ("") for legacy blocks (version 0).
        MinerFingerprintHash string       `cbor:"miner_fphash,omitempty"`

        // Version field for backward compatibility and future upgrades
        // 0 = legacy blocks (no network anchoring in DailyPoW, no fingerprint hash)
        // 1 = modern blocks (network-anchored PoW + fingerprint hash required)
        Version      uint8                `cbor:"version"`

        DistributionMeta DistributionMetadata `cbor:"dist_meta,omitempty"`

        // 🔐 PubKey du mineur (base64-encoded, immuable)
        MinerPubKey  string               `cbor:"miner_pubkey,omitempty"`
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

// -------------------------- Guardian State --------------------------
type guardianState struct {
    Owner      string `cbor:"o"`
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

// GuardianValidateBlockProducer verifies that the block producer
// owns the registered identity
// CONSENSUS CRITICAL — MinerAddress is the true owner.

func (l *Ledger) GuardianValidateBlockProducer(blk *Block) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}
	if blk == nil {
		return fmt.Errorf("nil block")
	}

	// -----------------------------
	// 1. Normalize miner address
	// -----------------------------
	minerAddr := strings.ToLower(strings.TrimSpace(blk.Header.MinerAddress))
	if minerAddr == "" {
		return fmt.Errorf("missing miner address")
	}

	// Optional: enforce address prefix format (EXPLOSIVE standard)
	if !strings.HasPrefix(minerAddr, "explo") {
		return fmt.Errorf("invalid miner address format")
	}

	// -----------------------------
	// 2. Fingerprint rules
	// -----------------------------
	fpHash := strings.ToLower(strings.TrimSpace(blk.Header.MinerFingerprintHash))

	if blk.Header.Version >= 1 && fpHash == "" {
		return fmt.Errorf("missing fingerprint hash (required since version 1)")
	}

	// Version 0 compatibility (legacy blocks)
	if fpHash == "" {
		return nil
	}

	// Basic sanity check (64 hex chars if SHA-256)
	if len(fpHash) != 64 {
		return fmt.Errorf("invalid fingerprint hash length")
	}

	// -----------------------------
	// 3. Ownership validation
	// -----------------------------
	ownerKey := []byte("guardian:fp_owner:" + fpHash)

	err := l.db.View(func(txn *badger.Txn) error {

		item, err := txn.Get(ownerKey)
		if err == badger.ErrKeyNotFound {
			// First time we see this fingerprint → allowed
			return nil
		}
		if err != nil {
			return fmt.Errorf("guardian lookup failed: %w", err)
		}

		ownerBytes, err := item.ValueCopy(nil)
		if err != nil {
			return fmt.Errorf("guardian read failed: %w", err)
		}

		storedOwner := strings.ToLower(strings.TrimSpace(string(ownerBytes)))
		if storedOwner == "" {
			return fmt.Errorf("guardian state corrupted (empty owner)")
		}

		if storedOwner != minerAddr {
			return fmt.Errorf(
				"fingerprint already bound to another miner (fp=%s)",
				fpHash[:12]+"...",
			)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
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

// ApplyBlock validates and atomically commits a block to the ledger.
//
// This function represents the final consensus gate before a block
// becomes part of the canonical chain. It enforces:
//
//   • Single-chain (UniLedger) fork prevention
//   • Deterministic height assignment (ledger authority)
//   • Full consensus validation (including Guardian rules)
//   • Atomic state transitions (Badger transaction)
//   • Supply cap enforcement
//   • Miner indexing and identity tracking
//
// The entire state transition is executed inside a single Badger
// transaction to guarantee atomicity and deterministic replay.
//
// Non-consensus side effects (pruning, blessings distribution)
// are executed asynchronously after commit.
func (l *Ledger) ApplyBlock(blk *Block) error {
	// ------------------------------------------------------------------
	// Basic sanity check
	// ------------------------------------------------------------------
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}
	if blk == nil {
		return fmt.Errorf("nil block")
	}

	// ------------------------------------------------------------------
	// 1️⃣ Resolve previous block
	// ------------------------------------------------------------------
	var prev *Block
	if blk.Header.PrevHash != "" {
		var err error
		prev, err = l.GetBlockByHash(blk.Header.PrevHash)
		if err != nil || prev == nil {
			return fmt.Errorf("missing previous block %s: %w", blk.Header.PrevHash, err)
		}
		blk.Header.Height = prev.Header.Height + 1
	} else {
		blk.Header.Height = 0
	}

	// ------------------------------------------------------------------
	// 2️⃣ Fork protection
	// ------------------------------------------------------------------
	if existing, err := l.GetBlockByHeight(blk.Header.Height); err == nil && existing != nil {
		return fmt.Errorf("fork rejected at height %d", blk.Header.Height)
	}

	// ------------------------------------------------------------------
	// 3️⃣ Consensus validation (includes PoW + time rules)
	// ------------------------------------------------------------------
	if err := blk.Validate(prev, l); err != nil {
		log.Printf("❌ Block #%d rejected: %v", blk.Header.Height, err)
		return fmt.Errorf("block validation failed: %w", err)
	}

	// ------------------------------------------------------------------
	// 4️⃣ Guardian validation
	// ------------------------------------------------------------------
	if blk.Header.Version >= 1 {
		if err := l.GuardianValidateBlockProducer(blk); err != nil {
			return fmt.Errorf("guardian validation failed: %w", err)
		}
	}

	// ------------------------------------------------------------------
	// 5️⃣ TIME-JACKING HARD FIX
	// DayStart must fall within the current network UTC day window.
	// Prevents miners from backdating or forward-dating their PoW.
	// ------------------------------------------------------------------
	now := time.Now().UnixMilli()
	if blk.Header.DailyPoW != nil {
		day := blk.Header.DailyPoW.DayStart

		// Reject extreme future timestamps.
		if day > now+10*60*1000 {
			return fmt.Errorf("PoW timestamp too far in future")
		}

		// Reject PoW not anchored to the previous block (anti time-jacking).
		if prev != nil && blk.Header.DailyPoW.PrevBlockHash != prev.BlockHash {
			return fmt.Errorf("PoW not anchored to previous block (anti time-jacking)")
		}
	}

	// ------------------------------------------------------------------
	// 6️⃣ Atomic commit
	// ------------------------------------------------------------------
	err := l.db.Update(func(txn *badger.Txn) error {

		rawData, err := cbor.Marshal(blk)
		if err != nil {
			return fmt.Errorf("CBOR marshal failed: %w", err)
		}

		compressedData, err := compressor.CompressZSTD(rawData)
		if err != nil {
			log.Printf("[WARN] Compression failed block #%d", blk.Header.Height)
			compressedData = rawData
		}

		if err := txn.Set(blockKeyByHeight(blk.Header.Height), compressedData); err != nil {
			return err
		}

		// ------------------------------------------------------------------
		// 7️⃣ Process transactions — reward + IMANI minting
		// ------------------------------------------------------------------
		var minted uint64
		rewardCount := 0

		for _, tx := range blk.Transactions {
			if err := l.persistTransactionIndexes(txn, &tx); err != nil {
				return err
			}

			if tx.IsReward {
				rewardCount++
				if rewardCount > 1 {
					return fmt.Errorf("multiple reward transactions not allowed")
				}

				if tx.To != blk.Header.MinerAddress {
					return fmt.Errorf("invalid reward recipient")
				}

				minted += tx.AmountPastabo

				// Load existing balance.
				balKey := []byte("balance:" + tx.To)
				var bal Balance

				item, err := txn.Get(balKey)
				if err == nil {
					val, _ := item.ValueCopy(nil)
					_ = cbor.Unmarshal(val, &bal)
				}

				// Credit EXPLO reward.
				bal.EXPLO += tx.AmountPastabo

				// FIX: Credit IMANI alongside EXPLO in the same atomic operation.
				// IMANI represents the miner's accumulated consciousness on-chain.
				// It must be minted here so it is reconstructed correctly when a
				// miner restores their identity on a new device via block sync.
				// Without this fix, IMANI would be lost on every device change.
				if tx.AmountIMPastabo > 0 {
					bal.IMANI += tx.AmountIMPastabo
					bal.TotalIMANIReceived += tx.AmountIMPastabo
				}

				enc, _ := cbor.Marshal(&bal)
				if err := txn.Set(balKey, enc); err != nil {
					return err
				}
			}
		}

		// ------------------------------------------------------------------
		// 8️⃣ Strict 1 block per day per miner rule
		// ------------------------------------------------------------------
		if blk.Header.DailyPoW != nil {
			key := []byte(fmt.Sprintf(
				"daily_pow:%s:%d",
				blk.Header.MinerAddress,
				blk.Header.DailyPoW.DayStart,
			))

			_, err := txn.Get(key)
			if err != badger.ErrKeyNotFound {
				return fmt.Errorf("double mining attempt detected (1/day rule)")
			}

			if err := txn.Set(key, []byte{1}); err != nil {
				return err
			}

			// Audit trail for governance and dispute resolution.
			audit := []byte(fmt.Sprintf(
				"daily_pow_audit:%s:%d:%d",
				blk.Header.MinerAddress,
				blk.Header.DailyPoW.DayStart,
				blk.Header.Height,
			))
			_ = txn.Set(audit, []byte{1})
		}

		// ------------------------------------------------------------------
		// 9️⃣ Supply cap enforcement — inviolable 50M EXPLO ceiling
		// ------------------------------------------------------------------
		if minted > 0 {
			key := []byte("meta:circulating_pastabo")

			item, err := txn.Get(key)
			var current uint64
			if err == nil {
				val, _ := item.ValueCopy(nil)
				current = binary.BigEndian.Uint64(val)
			}

			if current+minted > MaxPastaboSupply {
				return fmt.Errorf("supply cap exceeded")
			}

			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, current+minted)

			if err := txn.Set(key, buf); err != nil {
				return err
			}
		}

		// ------------------------------------------------------------------
		// 🔟 Update chain tip
		// ------------------------------------------------------------------
		tipBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(tipBuf, blk.Header.Height)

		return txn.Set(MetaChainTip, tipBuf)
	})

	if err != nil {
		return fmt.Errorf("atomic block commit failed: %w", err)
	}

	// ------------------------------------------------------------------
	// Async post-commit tasks (non-blocking, non-consensus-critical)
	// ------------------------------------------------------------------
	if blk.Header.Height%100 == 0 {
		go l.PruneOldBlocks()
	}
	go l.TryDistributeBlessings(blk)

	log.Printf("✅ Block #%d committed", blk.Header.Height)
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

    // ------------------------------------------------------------------
    // 1) Basic validation
    // ------------------------------------------------------------------
    if miner == "" {
        return nil, errors.New("miner address cannot be empty")
    }

    // ------------------------------------------------------------------
    // 2) Genesis vs non-genesis rules
    // ------------------------------------------------------------------
    isGenesis := prevHash == ""

    if isGenesis {
        if len(txs) == 0 {
            return nil, errors.New("genesis block must contain at least one transaction")
        }
    } else {
        if prevHash == "" {
            return nil, errors.New("non-genesis block must have a prevHash")
        }
    }

    // ------------------------------------------------------------------
    // 3) Merkle root (VERSIONED CONSENSUS)
    // ------------------------------------------------------------------
    merkleRoot, err := ComputeMerkleRoot(txs, 1)
    if err != nil {
        return nil, fmt.Errorf("invalid transactions: %w", err)
    }

    // ------------------------------------------------------------------
    // 4) Block header construction
    // ------------------------------------------------------------------
    header := BlockHeader{
        Height:       height,
        PrevHash:     prevHash,
        Timestamp:    NowMillis(),
        Nonce:        nonce,
        MinerAddress: miner,
        MerkleRoot:   merkleRoot,
        Version:      1, // force modern consensus
    }

    // ------------------------------------------------------------------
    // 5) Build block
    // ------------------------------------------------------------------
    block := &Block{
        Header:       header,
        Transactions: txs,
    }

    // ------------------------------------------------------------------
    // 6) Final hash (canonical header-only hashing)
    // ------------------------------------------------------------------
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

    // 🔒 Enforce signature for modern blocks
    if b.Header.Version >= 1 {
        if b.Signature == "" || b.PublicKey == "" {
            return false, fmt.Errorf("missing signature for version >=1 block")
        }
    }

    // Legacy compatibility
    if b.Signature == "" || b.PublicKey == "" {
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
    // 1) Hash integrity (full block canonical hash)
    // ------------------------------------------------------------------
    if b.BlockHash != b.ComputeFinalHash() {
        return errors.New("invalid block hash")
    }

    // ------------------------------------------------------------------
    // 2) Chain continuity
    // ------------------------------------------------------------------
    if b.Header.Height == 0 {
        // Genesis block
        if prevBlock != nil || b.Header.PrevHash != "" {
            return errors.New("invalid genesis linkage")
        }
    } else {
        if prevBlock == nil {
            return errors.New("missing previous block")
        }

        if b.Header.Height != prevBlock.Header.Height+1 {
            return fmt.Errorf(
                "height mismatch: expected %d got %d",
                prevBlock.Header.Height+1,
                b.Header.Height,
            )
        }

        if b.Header.PrevHash != prevBlock.BlockHash {
            return errors.New("prevHash mismatch")
        }
    }

    // ------------------------------------------------------------------
    // 3) Time validation (anti time-jacking)
    // ------------------------------------------------------------------
    if b.Header.Timestamp <= 0 {
        return errors.New("invalid timestamp")
    }

    if prevBlock != nil && b.Header.Timestamp <= prevBlock.Header.Timestamp {
        return errors.New("timestamp must increase from previous block")
    }

    now := time.Now().UnixMilli()

    // Max future drift: 30 minutes
    if b.Header.Timestamp > now+30*60*1000 {
        return errors.New("timestamp too far in future")
    }

    // ------------------------------------------------------------------
    // 4) Merkle root validation (versioned, consensus-safe)
    // ------------------------------------------------------------------
    if !b.IsLightBlock() {
        root, err := ComputeMerkleRoot(b.Transactions, b.Header.Version)
        if err != nil {
            return err
        }

        if root != b.Header.MerkleRoot {
            return errors.New("merkle root mismatch")
        }
    }

    // ------------------------------------------------------------------
    // 5) Signature validation (Ed25519)
    // ------------------------------------------------------------------
    ok, err := b.VerifySignature()
    if err != nil || !ok {
        return errors.New("invalid block signature")
    }

    // ------------------------------------------------------------------
    // 6) Miner binding (EXPLOSIVE identity model)
    // ------------------------------------------------------------------
    if b.Header.MinerAddress == "" {
        return errors.New("missing miner address")
    }

    // Deterministic address format validation
    if !address.IsValidEXPLOAddress(b.Header.MinerAddress) {
        return errors.New("invalid miner address format")
    }

    // Modern blocks require a valid public key
    if b.Header.Version >= 1 {
        if b.PublicKey == "" {
            return errors.New("missing public key")
        }

        pubBytes, err := base64.StdEncoding.DecodeString(b.PublicKey)
        if err != nil {
            return fmt.Errorf("invalid public key encoding")
        }

        if len(pubBytes) != ed25519.PublicKeySize {
            return errors.New("invalid public key size")
        }
    }

    // ------------------------------------------------------------------
    // 7) Daily PoW (strict consensus rules)
    // ------------------------------------------------------------------
    if b.Header.DailyPoW == nil {
        return errors.New("missing DailyPoW")
    }

    pow := b.Header.DailyPoW

    if b.Header.Version >= 1 {
        // Must be anchored to previous block
        if pow.PrevBlockHash == "" {
            return errors.New("missing anchored PrevBlockHash in PoW")
        }

        if prevBlock != nil && pow.PrevBlockHash != prevBlock.BlockHash {
            return errors.New("PoW not anchored to previous block")
        }

        if prevBlock == nil {
            return errors.New("missing previous block for PoW validation")
        }

        if !VerifyDailyPoW(
            b.Header.MinerAddress,
            *pow,
            prevBlock.BlockHash,
        ) {
            return errors.New("invalid PoW")
        }

        expectedDiff := getDailyPoWDifficulty(ledger)
        if pow.Difficulty != expectedDiff {
            return fmt.Errorf(
                "difficulty mismatch: expected %d got %d",
                expectedDiff,
                pow.Difficulty,
            )
        }

    } else {
        // Legacy validation
        if !VerifyDailyPoWLegacy(b.Header.MinerAddress, *pow) {
            return errors.New("invalid legacy PoW")
        }
    }

    // ------------------------------------------------------------------
    // 8) Anti Time-Jacking on DayStart
    // ------------------------------------------------------------------
    expectedDayStart := (b.Header.Timestamp / 86400000) * 86400000

    if pow.DayStart != expectedDayStart {
        return errors.New("invalid DayStart (not aligned with timestamp)")
    }

    // Prevent extreme future timestamps
    if pow.DayStart > now+60*60*1000 {
        return errors.New("invalid future PoW timestamp")
    }

    // ------------------------------------------------------------------
    // 9) One PoW per day per miner (chain-level enforcement)
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
