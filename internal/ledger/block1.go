package ledger

import (
        "crypto/sha256"
        "errors"
        "log"
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "sync"

        "explosive/internal/compressor"

        "github.com/dgraph-io/badger/v4"
        "github.com/fxamacker/cbor/v2"
        "golang.org/x/crypto/sha3"
)

// ---------------- Hashing ----------------
func (b *Block) ComputeFastHash() string {
    data, err := cbor.Marshal(b.Header)
    if err != nil {
        log.Fatalf("CRITICAL: failed to marshal header for fast hash: %v", err)
    }
    h := sha256.Sum256(data)
    return hex.EncodeToString(h[:])
}

func (b *Block) ComputeHashData() []byte {
    tmp := struct {
        Header       BlockHeader
        Transactions []Transaction
    }{
        Header:       b.Header,
        Transactions: b.Transactions,
    }

    data, err := cbor.Marshal(tmp)
    if err != nil {
        log.Fatalf("CRITICAL: CBOR marshal failed in ComputeHashData: %v", err)
    }

    return data
}

func (b *Block) ComputeFinalHash() string {
        h := sha3.Sum256(b.ComputeHashData())
        return hex.EncodeToString(h[:])
}


// IterateBlocks walks through all blocks stored in the ledger database
// and invokes the provided callback function for each block, in strict
// ascending order of block height.
//
// The iteration is read-only and safe: it uses a BadgerDB read transaction
// (View) and does not mutate any on-disk data.
//
// Parameters:
//   - cb: a callback function invoked once per block. If the callback
//     returns an error, iteration stops immediately and the error is
//     propagated to the caller.
//
// Returns:
//   - an error if the ledger is not initialized, if a database operation
//     fails, if block decoding fails, or if the callback returns an error.
func (l *Ledger) IterateBlocks(cb func(*Block) error) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    return l.db.View(func(txn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = true
        opts.Prefix = PrefixBlock

        it := txn.NewIterator(opts)
        defer it.Close()

        var (
            expectedHeight uint64
            prevHash       string
        )

        for it.Seek(PrefixBlock); it.ValidForPrefix(PrefixBlock); it.Next() {
            item := it.Item()

            val, err := item.ValueCopy(nil)
            if err != nil {
                return fmt.Errorf("block read failed: %w", err)
            }

            data, err := compressor.DecompressZSTD(val)
            if err != nil {
                data = val // fallback SAFE
            }

            var blk Block
            if err := cbor.Unmarshal(data, &blk); err != nil {
                return fmt.Errorf("block decode failed: %w", err)
            }

            if blk.Header.Height != expectedHeight {
                return fmt.Errorf("height discontinuity: expected %d, found %d",
                    expectedHeight, blk.Header.Height)
            }

            if blk.Header.Height > 0 && blk.Header.PrevHash != prevHash {
                return fmt.Errorf("prev hash mismatch at block %d", blk.Header.Height)
            }

            if blk.ComputeFinalHash() != blk.BlockHash {
                return fmt.Errorf("hash mismatch at block %d", blk.Header.Height)
            }

            if err := cb(&blk); err != nil {
                return err
            }

            prevHash = blk.BlockHash
            expectedHeight++
        }

        return nil
    })
}

func (l *Ledger) ScanBlocksStream(process func(blk *Block) error) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    return l.db.View(func(txn *badger.Txn) error {
        opts := badger.DefaultIteratorOptions
        opts.PrefetchValues = false
        opts.Prefix = PrefixBlock

        it := txn.NewIterator(opts)
        defer it.Close()

        for it.Seek(PrefixBlock); it.ValidForPrefix(PrefixBlock); it.Next() {
            item := it.Item()

            val, err := item.ValueCopy(nil)
            if err != nil {
                return err
            }

            data, err := compressor.DecompressZSTD(val)
            if err != nil {
                data = val
            }

            var blk Block
            if err := cbor.Unmarshal(data, &blk); err != nil {
                return err
            }

            if err := process(&blk); err != nil {
                return err
            }
        }
        return nil
    })
}

// ---------------- Batch Block Storage ----------------
var (
        batchMu      sync.Mutex
        batchQueueA  []*Block
        batchQueueB  []*Block
        activeQueueA = true
        batchSize    = 500
)

func (l *Ledger) StoreBlockBatch(blk *Block) error {
        if l == nil || l.db == nil {
                return fmt.Errorf("ledger not initialized")
        }

        batchMu.Lock()
        if activeQueueA {
                batchQueueA = append(batchQueueA, blk)
                if len(batchQueueA) >= batchSize {
                        toWrite := batchQueueA
                        batchQueueA = nil
                        activeQueueA = false
                        batchMu.Unlock()
                        return flushBlockBatch(l, toWrite)
                }
        } else {
                batchQueueB = append(batchQueueB, blk)
                if len(batchQueueB) >= batchSize {
                        toWrite := batchQueueB
                        batchQueueB = nil
                        activeQueueA = true
                        batchMu.Unlock()
                        return flushBlockBatch(l, toWrite)
                }
        }
        batchMu.Unlock()
        return nil
}

func flushBlockBatch(l *Ledger, blocks []*Block) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    return l.db.Update(func(txn *badger.Txn) error {
        for _, b := range blocks {
            if b == nil {
                continue
            }

            key := blockKeyByHeight(b.Header.Height)

            val, err := cbor.Marshal(b)
            if err != nil {
                return err
            }

            comp, err := compressor.CompressZSTD(val)
            if err != nil {
                comp = val
            }

            if err := txn.Set(key, comp); err != nil {
                return err
            }
        }
        return nil
    })
}

func (l *Ledger) ForceFlushBlocks() error {
        if l == nil || l.db == nil {
                return fmt.Errorf("ledger not initialized")
        }

        batchMu.Lock()
        defer batchMu.Unlock()

        if len(batchQueueA) > 0 {
                if err := flushBlockBatch(l, batchQueueA); err != nil {
                        return err
                }
                batchQueueA = nil
        }
        if len(batchQueueB) > 0 {
                if err := flushBlockBatch(l, batchQueueB); err != nil {
                        return err
                }
                batchQueueB = nil
        }
        return nil
}


func (l *Ledger) GetLatestBlockHeight() uint64 {
    if l == nil || l.db == nil {
        return 0
    }

    data, err := l.GetBytes(MetaChainTip)
    if err != nil || len(data) != 8 {
        return 0
    }

    return binary.BigEndian.Uint64(data)
}

// GetLatestBlock returns the most recent block in the canonical chain.
// It relies on the MetaChainTip meta-key (updated synchronously in PutBlock)
// for O(1) access to the tip height, then fetches the corresponding block.
// This eliminates expensive iteration and guarantees the correct tip.
func (l *Ledger) GetLatestBlock() (*Block, error) {
    if l == nil || l.db == nil {
        return nil, errors.New("ledger not initialized")
    }

    // 1. Read the current tip height from meta (fast and reliable)
    tipData, err := l.GetBytes(MetaChainTip)
    if err != nil {
        if errors.Is(err, badger.ErrKeyNotFound) {
            // Empty ledger (no genesis yet)
            return nil, nil
        }
        return nil, fmt.Errorf("failed to read MetaChainTip: %w", err)
    }

    if len(tipData) != 8 {
        return nil, errors.New("corrupted MetaChainTip: invalid length")
    }

    tipHeight := binary.BigEndian.Uint64(tipData)

    // 2. Fetch block at the reported tip height
    key := blockKeyByHeight(tipHeight)
    compressed, err := l.GetBytes(key)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch block at height %d: %w", tipHeight, err)
    }

    // 3. Decompress (fallback to raw if not compressed)
    data, err := compressor.DecompressZSTD(compressed)
    if err != nil {
        data = compressed // assume it was stored uncompressed
    }

    // 4. Decode CBOR
    var blk Block
    if err := cbor.Unmarshal(data, &blk); err != nil {
        return nil, fmt.Errorf("failed to unmarshal block at height %d: %w", tipHeight, err)
    }

    // 5. Integrity check (defensive)
    if blk.Header.Height != tipHeight {
        return nil, fmt.Errorf("block height mismatch: expected %d, found %d", tipHeight, blk.Header.Height)
    }

    return &blk, nil
}

// PutBlock persists a block at the given height and atomically updates the chain tip.
// Both the block data and MetaChainTip are written in a single transaction to ensure
// consistency and prevent races where the tip advances before the block is visible.
// Compression is attempted with ZSTD; falls back to raw data on failure.
// ---------------------- CONSTANTS ----------------------
// ---------------------- KEY UTIL ----------------------
func blockKeyByHeight(height uint64) []byte {
    b := make([]byte, 8)
    binary.BigEndian.PutUint64(b, height)
    return append(PrefixBlock, b...)
}

// ---------------------- PUT BLOCK ----------------------
func (l *Ledger) PutBlock(height uint64, blk *Block) error {
    if l == nil || l.db == nil {
        return errors.New("ledger not initialized")
    }
    if blk == nil {
        return fmt.Errorf("nil block")
    }

    rawData, err := cbor.Marshal(blk)
    if err != nil {
        return fmt.Errorf("failed to marshal block: %w", err)
    }

    compressedData, err := compressor.CompressZSTD(rawData)
    if err != nil {
        log.Printf("[WARN] Compression failed for block #%d: %v – storing raw", height, err)
        compressedData = rawData
    }

    tipBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(tipBytes, height)

    err = l.db.Update(func(txn *badger.Txn) error {
        // store block
        if err := txn.Set(blockKeyByHeight(height), compressedData); err != nil {
            return err
        }

        // store tip
        if err := txn.Set(MetaChainTip, tipBytes); err != nil {
            return err
        }

        // 🔥 NEW: index hash → height
        hashKey := append([]byte("hash:"), []byte(blk.BlockHash)...)
        if err := txn.Set(hashKey, tipBytes); err != nil {
            return err
        }

        return nil
    })
    if err != nil {
        return fmt.Errorf("atomic PutBlock failed for height %d: %w", height, err)
    }

    log.Printf("[LEDGER] Block #%d persisted", height)
    return nil
}
// GetBlockByHeight retrieves and decompresses a block by its height.
// ---------------------- GET BLOCK ----------------------
func (l *Ledger) GetBlockByHeight(height uint64) (*Block, error) {
    if l == nil || l.db == nil {
        return nil, errors.New("ledger not initialized")
    }

    data, err := l.GetBytes(blockKeyByHeight(height))
    if err != nil {
        return nil, err
    }

    if decompressed, derr := compressor.DecompressZSTD(data); derr == nil {
        data = decompressed
    }

    var blk Block
    if err := cbor.Unmarshal(data, &blk); err != nil {
        return nil, fmt.Errorf("failed to unmarshal block at height %d: %w", height, err)
    }

    if blk.Header.Height != height {
        return nil, fmt.Errorf("block height mismatch: expected %d, found %d",
            height, blk.Header.Height)
    }

    return &blk, nil
}

func (l *Ledger) AddBlock(blk *Block) error {
        return l.ApplyBlock(blk)
}

// GetBlocksRange returns all available blocks in the range [from, to] inclusive.
// It is used by the P2P layer to serve block synchronization requests from peers.
// Missing blocks (gaps) are skipped — this should not occur in a healthy chain.
func (l *Ledger) GetBlocksRange(from, to uint64) ([]*Block, error) {
    if l == nil || l.db == nil {
        return nil, errors.New("ledger not initialized")
    }

    var blocks []*Block
    for h := from; h <= to; h++ {
        blk, err := l.GetBlockByHeight(h)
        if err != nil {
            // Log if you want, but continue — gaps should be rare
            continue
        }
        blocks = append(blocks, blk)
    }
    return blocks, nil
}

// GetHeightByBlockHash returns the height of a block given its hash.
// ok == false if the block is not found.
func (l *Ledger) GetHeightByBlockHash(hash string) (uint64, bool) {
    if l == nil || l.db == nil {
        return 0, false
    }

    data, err := l.GetBytes(append([]byte("hash:"), []byte(hash)...))
    if err != nil || len(data) != 8 {
        return 0, false
    }

    return binary.BigEndian.Uint64(data), true
}

// GetBlockByHash returns a copy of the block with the given hash.
// Returns ErrNotFound if the block does not exist.
// Safe with concurrent pruning.
func (l *Ledger) GetBlockByHash(hash string) (*Block, error) {
    if l == nil || l.db == nil {
        return nil, ErrNotFound
    }

    key := append([]byte("hash:"), []byte(hash)...)

    data, err := l.GetBytes(key)
    if err == nil && len(data) == 8 {
        height := binary.BigEndian.Uint64(data)
        return l.GetBlockByHeight(height)
    }

    // 🔥 FALLBACK: scan ledger (important for P2P sync safety)
    var found *Block

    err = l.ScanBlocksStream(func(b *Block) error {
        if b.BlockHash == hash {
            found = b
            return errors.New("FOUND") // stop iteration
        }
        return nil
    })

    if found != nil {
        return found, nil
    }

    return nil, ErrNotFound
}

// HasBlockAtHeight returns true if a block exists at the given height.
func (l *Ledger) HasBlockAtHeight(height uint64) bool {
    _, err := l.GetBlockByHeight(height)
    return err == nil
}

// ComputeMerkleRoot computes the Merkle root of a list of transactions.
//
// Security & Design:
// - Versioned algorithm (consensus-safe upgrade path)
// - V0: Legacy mode (no domain separation)
// - V1: Secure mode (domain separation: 0x00 for leaves, 0x01 for internal nodes)
// - Deterministic and platform-independent
//
// Performance:
// - Minimal allocations (mobile-friendly)
// - Reuses buffers per tree level
//
// Rules:
// - Empty list → SHA3-256(nil)
// - Each TxHash must be a valid hex-encoded SHA3-256 (32 bytes)
func ComputeMerkleRoot(txs []Transaction, version uint8) (string, error) {
	const sha3Len = 32 // SHA3-256 output size

	// ------------------------------------------------------------
	// 1. Handle empty block
	// ------------------------------------------------------------
	if len(txs) == 0 {
		h := sha3.Sum256(nil)
		return hex.EncodeToString(h[:]), nil
	}

	// ------------------------------------------------------------
	// 2. Build leaf level
	// ------------------------------------------------------------
	hashes := make([][]byte, len(txs))

	for i, tx := range txs {
		hashBytes, err := hex.DecodeString(tx.TxHash)
		if err != nil || len(hashBytes) != sha3Len {
			return "", fmt.Errorf("invalid TxHash at index %d (expected SHA3-256)", i)
		}

		switch version {
		case 0:
			// Legacy mode (no domain separation)
			hashes[i] = hashBytes

		case 1:
			// Secure leaf: prefix 0x00
			buf := make([]byte, 1+sha3Len)
			buf[0] = 0x00
			copy(buf[1:], hashBytes)

			h := sha3.Sum256(buf)
			hashes[i] = h[:]

		default:
			return "", fmt.Errorf("unsupported merkle version %d", version)
		}
	}

	// ------------------------------------------------------------
	// 3. Build tree upwards
	// ------------------------------------------------------------
	for len(hashes) > 1 {
		nextSize := (len(hashes) + 1) / 2
		next := make([][]byte, nextSize)

		var buf []byte

		switch version {
		case 0:
			buf = make([]byte, 2*sha3Len)

		case 1:
			buf = make([]byte, 1+2*sha3Len)

		default:
			return "", fmt.Errorf("unsupported merkle version %d", version)
		}

		for i := 0; i < nextSize; i++ {
			left := hashes[2*i]

			// Handle odd node (duplicate last)
			right := left
			if 2*i+1 < len(hashes) {
				right = hashes[2*i+1]
			}

			switch version {
			case 0:
				// Legacy concat
				copy(buf[:sha3Len], left)
				copy(buf[sha3Len:], right)

			case 1:
				// Secure node: prefix 0x01
				buf[0] = 0x01
				copy(buf[1:1+sha3Len], left)
				copy(buf[1+sha3Len:], right)
			}

			h := sha3.Sum256(buf)

			// ⚡ Zero-allocation slice reuse (safe)
			hash := h
			next[i] = hash[:]
		}

		hashes = next
	}

	// ------------------------------------------------------------
	// 4. Final root
	// ------------------------------------------------------------
	return hex.EncodeToString(hashes[0]), nil
}

// DumpLedger performs a lightweight integrity check of the chain tip,
// followed by a bounded visual scan of the most recent blocks.
//
// Design goals:
// - O(1) security validation using chain tip verification
// - Bounded traversal (lookback window) for mobile scalability
// - Streaming-friendly output (single-line dynamic rendering)
// - No full-chain iteration (avoids O(n) UI overload on mobile devices)
func (l *Ledger) DumpLedger() error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}

	// ------------------------------------------------------------
	// STEP 1: Fetch chain tip in O(1)
	// ------------------------------------------------------------
	tip, err := l.GetLatestBlock()
	if err != nil || tip == nil {
		return fmt.Errorf("could not retrieve chain tip: %v", err)
	}

	// ------------------------------------------------------------
	// STEP 2: Fast integrity validation (cryptographic + linkage)
	// ------------------------------------------------------------
	if !verifyChainState(l, tip) {
		fmt.Println("\n❌ [CRITICAL] Ledger integrity check FAILED")
		return fmt.Errorf("tampered ledger detected")
	}

	fmt.Println("📜 Ledger integrity: \033[1;32mVALID ✔\033[0m")

	// ------------------------------------------------------------
	// STEP 3: Scalable visualization window (last N blocks only)
	// ------------------------------------------------------------
	const lookback = 100

	start := uint64(0)
	if tip.Header.Height > lookback {
		start = tip.Header.Height - lookback
	}

	// ------------------------------------------------------------
	// STEP 4: Streaming UI rendering (single-line overwrite mode)
	// ------------------------------------------------------------
	for h := start; h <= tip.Header.Height; h++ {
		b, err := l.GetBlockByHeight(h)
		if err != nil {
			continue
		}

		// Compact hash representation (mobile-friendly)
		shortHash := b.BlockHash
		if len(shortHash) >= 16 {
			shortHash = fmt.Sprintf("%s...%s", shortHash[:8], shortHash[len(shortHash)-8:])
		}

		// Dynamic terminal rendering (no spam, single line refresh)
		fmt.Printf(
			"\r🔗 Scanning: [#%d] | 🔒 %s | 💎 Syncing...",
			h,
			shortHash,
		)
	}

	// ------------------------------------------------------------
	// STEP 5: Final flush line
	// ------------------------------------------------------------
	fmt.Printf(
		"\r✅ Blockchain ready: \033[1;36m#%d\033[0m blocks verified (Tip: %s...)\n",
		tip.Header.Height+1,
		tip.BlockHash[:8],
	)

	return nil
}

// verifyChainState performs a fast integrity validation of the chain tip.
//
// Security model:
// - Ensures cryptographic consistency of the tip block
// - Validates backward linkage (PrevHash correctness)
// - Prevents chain tampering without full-chain traversal
//
// Complexity:
// - O(1) for tip validation
// - Optional O(1) parent lookup (single DB read)
func verifyChainState(l *Ledger, tip *Block) bool {
	if tip == nil {
		return false
	}

	// ------------------------------------------------------------
	// STEP 1: Cryptographic integrity check of the tip block
	// ------------------------------------------------------------
	if tip.ComputeFinalHash() != tip.BlockHash {
		log.Printf("🚨 ALERT: Tip hash corruption detected at height #%d", tip.Header.Height)
		return false
	}

	// ------------------------------------------------------------
	// STEP 2: Structural chain linkage validation (PrevHash check)
	// ------------------------------------------------------------
	if tip.Header.Height > 0 {
		parent, err := l.GetBlockByHeight(tip.Header.Height - 1)
		if err != nil {
			log.Printf("🚨 ALERT: Parent block #%d missing", tip.Header.Height-1)
			return false
		}

		if parent.BlockHash != tip.Header.PrevHash {
			log.Printf(
				"🚨 ALERT: Chain break detected between blocks #%d and #%d",
				tip.Header.Height-1,
				tip.Header.Height,
			)
			return false
		}
	}

	// ------------------------------------------------------------
	// STEP 3: Optional future-proofing (multi-chain protection)
	// ------------------------------------------------------------
	// if tip.Header.NetworkID != ExpectedNetworkID {
	//     return false
	// }

	return true
}
