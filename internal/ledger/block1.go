package ledger

import (
        "bytes"
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
        data, _ := cbor.Marshal(b.Header)
        h := sha256.Sum256(data)
        return hex.EncodeToString(h[:])
}

func (b *Block) ComputeHashData() []byte {
        // IMPORTANT: exclude signature and public key from the signed/hashable data.
        // Only header + transactions are used for hashing/signing.
        tmp := struct {
                Header       BlockHeader
                Transactions []Transaction
        }{
                Header:       b.Header,
                Transactions: b.Transactions,
        }
        data, _ := cbor.Marshal(tmp)
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

    // Defensive check: ensure the ledger and its database are initialized
    // before attempting any iteration.
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    // Temporary in-memory map used to collect all blocks indexed by height.
    // This allows us to later iterate in strict height order, regardless of
    // how BadgerDB physically stores the keys.
    blocks := make(map[uint64]*Block)

    // Open a read-only transaction on the database.
    err := l.db.View(func(txn *badger.Txn) error {

        // Create an iterator with default options.
        it := txn.NewIterator(badger.DefaultIteratorOptions)
        defer it.Close()

        // Iterate over all keys that share the block prefix.
        for it.Seek(prefixBlock); it.ValidForPrefix(prefixBlock); it.Next() {
            item := it.Item()

            // Copy the raw value from BadgerDB.
            val, err := item.ValueCopy(nil)
            if err != nil {
                return err
            }

            // Decompress the stored block data (ZSTD-compressed).
            data, err := compressor.DecompressZSTD(val)
            if err != nil {
                return err
            }

            // Decode the CBOR-encoded block into a Block structure.
            var blk Block
            if err := cbor.Unmarshal(data, &blk); err != nil {
                return err
            }

            // Store the block indexed by its height.
            blocks[blk.Header.Height] = &blk
        }

        return nil
    })
    if err != nil {
        return err
    }

    // Determine the maximum block height present in the database.
    // This allows us to iterate deterministically from height 0 upward.
    var max uint64
    for h := range blocks {
        if h > max {
            max = h
        }
    }

    // Iterate blocks in strict ascending height order.
    // Missing heights are skipped silently, allowing for sparse storage
    // or pruned blocks without breaking iteration.
    for h := uint64(0); h <= max; h++ {
        blk, ok := blocks[h]
        if !ok {
            continue
        }

        // Invoke the callback for the current block.
        // Any error returned by the callback aborts iteration.
        if err := cb(blk); err != nil {
            return err
        }
    }

    return nil
}

func (l *Ledger) ScanBlocksStream(process func(blk *Block) error) error {
        if l == nil || l.db == nil {
                return fmt.Errorf("ledger not initialized")
        }

        return l.db.View(func(txn *badger.Txn) error {
                opts := badger.DefaultIteratorOptions
                opts.PrefetchValues = false
                it := txn.NewIterator(opts)
                defer it.Close()

                for it.Seek(prefixBlock); it.ValidForPrefix(prefixBlock); it.Next() {
                        item := it.Item()
                        val, err := item.ValueCopy(nil)
                        if err != nil {
                                return err
                        }

                        data, err := compressor.DecompressZSTD(val)
                        if err != nil {
                                return err
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
        return l.db.Update(func(txn *badger.Txn) error {
                for _, b := range blocks {
                        key := blockKeyByHeight(b.Header.Height)

                        // marshal + compress
                        val, err := cbor.Marshal(b)
                        if err != nil {
                                return err
                        }
                        comp, err := compressor.CompressZSTD(val)
                        if err != nil {
                                // fallback to raw if compression fails
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
        var lastHeight uint64
        _ = l.IterateBlocks(func(b *Block) error {
                if b.Header.Height > lastHeight {
                        lastHeight = b.Header.Height
                }
                return nil
        })
        return lastHeight
}


// GetLatestBlock returns the most recent block.
func (l *Ledger) GetLatestBlock() (*Block, error) {
        var last *Block

        err := l.db.View(func(txn *badger.Txn) error {
                opts := badger.DefaultIteratorOptions
                opts.Reverse = true
                it := txn.NewIterator(opts)
                defer it.Close()

                // Seek to the end of the prefix range
                it.Seek(append(prefixBlock, 0xFF))
                for it.Valid() {
                        item := it.Item()
                        k := item.Key()
                        if !bytes.HasPrefix(k, prefixBlock) {
                                break
                        }

                        val, err := item.ValueCopy(nil)
                        if err != nil {
                                return err
                        }

                        data, err := compressor.DecompressZSTD(val)
                        if err != nil {
                                return err
                        }

                        var blk Block
                        if err := cbor.Unmarshal(data, &blk); err != nil {
                                return fmt.Errorf("failed to decode block: %w", err)
                        }

                        last = &blk
                        break
                }

                if last == nil {
                        return fmt.Errorf("no blocks in ledger")
                }
                return nil
        })

        if err != nil {
                return nil, err
        }
        return last, nil
}

// blockKeyByHeight returns the DB key for a block at a specific height.
func blockKeyByHeight(height uint64) []byte {
        b := make([]byte, 8)
        binary.BigEndian.PutUint64(b, height)
        return append(prefixBlock, b...)
}

// PutBlock stores a block compressed with ZSTD asynchronously.
func (l *Ledger) PutBlock(height uint64, blk *Block) error {
        bufVal, err := cbor.Marshal(blk)
        if err != nil {
                return err
        }
        compData, err := compressor.CompressZSTD(bufVal)
        if err != nil {
                compData = bufVal
        }
        l.AsyncPut(blockKeyByHeight(height), compData)

        hb := make([]byte, 8)
        binary.BigEndian.PutUint64(hb, height)
        return l.PutBytes(MetaChainTip, hb)
}

// GetBlockByHeight retrieves and decompresses a block by its height.
func (l *Ledger) GetBlockByHeight(height uint64) (*Block, error) {
        data, err := l.GetBytes(blockKeyByHeight(height))
        if err != nil {
                return nil, err
        }

        data, err = compressor.DecompressZSTD(data)
        if err != nil {
                return nil, err
        }

        var blk Block
        if err := cbor.Unmarshal(data, &blk); err != nil {
                return nil, err
        }
        return &blk, nil
}

func (l *Ledger) AddBlock(blk *Block) error {
        return l.ApplyBlock(blk)
}


// DumpLedger prints all blocks, detects corrupted blocks, and flags forks.
// Maintains chronological order and preserves all blocks.
func (l *Ledger) DumpLedger() error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    fmt.Println("📜 ====== LEDGER DUMP START ======")
    var prevHash string
    corruptionDetected := false
    forksDetected := false
    blockHeights := make(map[uint64][]string)
    count := 0

    // Iterate all blocks in ascending order
    err := l.IterateBlocks(func(b *Block) error {
        isCorrupt := false

        // Track blocks by height to detect forks
        blockHeights[b.Header.Height] = append(blockHeights[b.Header.Height], b.BlockHash)
        if len(blockHeights[b.Header.Height]) > 1 {
            forksDetected = true
        }

        // Determine expected hash
        expected := b.ComputeFinalHash()
        if b.Header.Height == 0 {
            expected = GenesisHash
        }

        // Validate block hash
        if b.BlockHash != expected {
            fmt.Printf("❌ Block #%d has invalid hash!\n", b.Header.Height)
            fmt.Printf("   Expected: %s\n", expected)
            fmt.Printf("   Found   : %s\n", b.BlockHash)
            isCorrupt = true
            corruptionDetected = true
        }

        // Validate previous hash (except genesis)
        if b.Header.Height > 0 && b.Header.PrevHash != prevHash {
            fmt.Printf("❌ Block #%d has mismatched PrevHash!\n", b.Header.Height)
            fmt.Printf("   Expected PrevHash: %s\n", prevHash)
            fmt.Printf("   Found PrevHash   : %s\n", b.Header.PrevHash)
            isCorrupt = true
            corruptionDetected = true
        }

        // Print block info
        label := ""
        if isCorrupt {
            label = "(CORRUPTED)"
        } else if len(blockHeights[b.Header.Height]) > 1 {
            label = "(FORK)"
        }

        fmt.Printf("🔗 Block #%d %s\n", b.Header.Height, label)
        fmt.Printf("   ⏱️  Timestamp: %d\n", b.Header.Timestamp)
        fmt.Printf("   👤 Miner: %s\n", b.Header.MinerAddress)
        fmt.Printf("   🔑 PrevHash: %s\n", b.Header.PrevHash)
        fmt.Printf("   � Hash: %s\n", b.BlockHash)
        fmt.Printf("   💰 Transactions: %d\n", len(b.Transactions))
        fmt.Println("   -----------------------------")

        prevHash = b.BlockHash
        count++
        return nil
    })
    if err != nil {
        return fmt.Errorf("failed to iterate blocks: %v", err)
    }

    if count == 0 {
        fmt.Println("⚠️ No blocks found in the ledger.")
    } else {
        fmt.Printf("✅ %d blocks found in the ledger.\n", count)
    }

    if forksDetected {
        fmt.Println("⚠️ Forks detected — multiple blocks exist at the same height. They are logged but preserved.")
    }

    fmt.Println("📜 ====== LEDGER DUMP END ======")

    if corruptionDetected {
        fmt.Println("🚨 Ledger corruption detected! Local ledger operations are now blocked.")
        return fmt.Errorf("ledger is corrupted — halting local operations")
    }

    return nil
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
func (l *Ledger) GetHeightByBlockHash(hash string) (height uint64, ok bool) {
    err := l.IterateBlocks(func(b *Block) error {
        if b.BlockHash == hash {
            height = b.Header.Height
            ok = true
            return errIterStop // clean early exit
        }
        return nil
    })

    if err != nil && err != errIterStop {
        log.Printf("[ledger] GetHeightByBlockHash error: %v", err)
    }

    return height, ok
}

// GetBlockByHash returns a copy of the block with the given hash.
// Returns ErrNotFound if the block does not exist.
// Safe with concurrent pruning.
func (l *Ledger) GetBlockByHash(hash string) (*Block, error) {
    var result *Block

    err := l.IterateBlocks(func(b *Block) error {
        if b.BlockHash == hash {
            // Defensive copy (safe against pruning races)
            blkCopy := *b

            if len(b.Transactions) > 0 {
                blkCopy.Transactions = make([]Transaction, len(b.Transactions))
                copy(blkCopy.Transactions, b.Transactions)
            }

            result = &blkCopy
            return errIterStop
        }
        return nil
    })

    if err != nil && err != errIterStop {
        return nil, err
    }

    if result == nil {
        return nil, ErrNotFound
    }

    return result, nil
}

// HasBlockAtHeight returns true if a block exists at the given height.
func (l *Ledger) HasBlockAtHeight(height uint64) bool {
    _, err := l.GetBlockByHeight(height)
    return err == nil
}

// ComputeMerkleRoot computes the Merkle root of a list of transactions using SHA3-256.
//
// Rules:
// - Deterministic across all platforms and Go runtimes
// - Empty transaction list returns SHA3-256(nil)
// - Each transaction must have a valid, hex-encoded SHA3-256 hash (32 bytes)
// - Odd number of nodes at any level: last hash is duplicated
func ComputeMerkleRoot(txs []Transaction) (string, error) {
        const sha3Len = 32 // SHA3-256 produces 32 bytes

        // Empty block: hash of nil
        if len(txs) == 0 {
                h := sha3.Sum256(nil)
                return hex.EncodeToString(h[:]), nil
        }

        // Collect and validate transaction hashes
        hashes := make([][]byte, 0, len(txs))
        for i, tx := range txs {
                if tx.TxHash == "" {
                        return "", fmt.Errorf("empty TxHash at index %d", i)
                }

                hashBytes, err := hex.DecodeString(tx.TxHash)
                if err != nil {
                        return "", fmt.Errorf("invalid TxHash hex at index %d: %w", i, err)
                }

                if len(hashBytes) != sha3Len {
                        return "", fmt.Errorf(
                                "TxHash wrong length at index %d: got %d bytes, expected %d (SHA3-256)",
                                i, len(hashBytes), sha3Len,
                        )
                }

                hashes = append(hashes, hashBytes)
        }

        // Compute Merkle tree iteratively
        for len(hashes) > 1 {
                nextLevel := make([][]byte, 0, (len(hashes)+1)/2)
                for i := 0; i < len(hashes); i += 2 {
                        left := hashes[i]
                        right := left
                        if i+1 < len(hashes) {
                                right = hashes[i+1]
                        }

                        // Concatenate and hash
                        combined := append(append([]byte{}, left...), right...)
                        h := sha3.Sum256(combined)
                        nextLevel = append(nextLevel, h[:])
                }
                hashes = nextLevel
        }

        return hex.EncodeToString(hashes[0]), nil
}
