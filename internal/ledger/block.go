// internal/ledger/block.go
package ledger

import (
        "bytes"
        "crypto/sha256"
        "errors"
        "os"
        "time"
        "path/filepath"
        "log"
        "crypto/ed25519"
        "encoding/base64"
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "sync"

        "explosive/internal/compressor"

        "github.com/dgraph-io/badger/v4"
        "github.com/fxamacker/cbor/v2"
        "golang.org/x/crypto/sha3"
)

var prefixBlock = []byte("block:")

var ErrNotFound = errors.New("not found")

// ---------------- BlockHeader ----------------
type BlockHeader struct {
        Height       uint64 `cbor:"height"`
        PrevHash     string `cbor:"prev_hash"`
        Timestamp    int64  `cbor:"timestamp"`
        Nonce        uint64 `cbor:"nonce"`
        MinerAddress string `cbor:"miner_address"`
        MerkleRoot   string `cbor:"merkle_root"`
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

// ---------------- Block Creation ----------------
func NewBlock(height uint64, prevHash string, miner string, txs []Transaction, nonce uint64) *Block {
        header := BlockHeader{
                Height:       height,
                PrevHash:     prevHash,
                Timestamp:    NowMillis(),
                Nonce:        nonce,
                MinerAddress: miner,
                MerkleRoot:   ComputeMerkleRoot(txs),
        }

        b := &Block{
                Header:       header,
                Transactions: txs,
        }
        b.BlockHash = b.ComputeFinalHash()
        return b
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

// ---------------- Actual Merkle Root ----------------
func ComputeMerkleRoot(txs []Transaction) string {
    if len(txs) == 0 {
        return ""
    }

    // Convert each transaction to a SHA256 hash
    hashes := make([][]byte, len(txs))
    for i, tx := range txs {
        h := sha256.Sum256([]byte(tx.Hash()))
        hashes[i] = h[:]
    }

    // Build the Merkle tree
    for len(hashes) > 1 {
        var newLevel [][]byte
        for i := 0; i < len(hashes); i += 2 {
            left := hashes[i]
            var right []byte
            if i+1 < len(hashes) {
                right = hashes[i+1]
            } else {
                right = left // duplicate last hash if odd number
            }
            combined := append(left, right...)
            h := sha256.Sum256(combined)
            newLevel = append(newLevel, h[:])
        }
        hashes = newLevel
    }

    return hex.EncodeToString(hashes[0])
}

// ---------------- Mainnet Block Validation ----------------
func (b *Block) Validate(prevBlock *Block) error {
    // 1️⃣ Verify block hash
    if b.BlockHash != b.ComputeFinalHash() {
        return fmt.Errorf("invalid block hash")
    }

    // 2️⃣ Verify previous hash
    if b.Header.Height == 0 {
        if prevBlock != nil {
            return fmt.Errorf("genesis block should not have previous block")
        }
    } else {
        if prevBlock == nil {
            return fmt.Errorf("missing previous block for height %d", b.Header.Height)
        }
        if b.Header.PrevHash != prevBlock.BlockHash {
            return fmt.Errorf("prevHash mismatch — fork attempt")
        }
    }

    // 3️⃣ Verify MerkleRoot
    if ComputeMerkleRoot(b.Transactions) != b.Header.MerkleRoot {
        return fmt.Errorf("invalid Merkle root")
    }

    // 4️⃣ Verify signature (backward compatible)
    ok, err := b.VerifySignature()
    if err != nil {
        return fmt.Errorf("signature verification error: %v", err)
    }
    if !ok {
        return fmt.Errorf("block signature invalid")
    }

    return nil
}

// ---------------- Mainnet Ready ApplyBlock ----------------
// ApplyBlock validates and commits a block into the ledger database.
// It prevents forks, isolates corrupted blocks, and preserves scalability.
func (l *Ledger) ApplyBlock(blk *Block) error {
    if l == nil || l.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    // 1️⃣ Check for fork at the same height
    existing, err := l.GetBlockByHeight(blk.Header.Height)
    if err == nil && existing != nil {
        return fmt.Errorf("block at height %d already exists — fork rejected", blk.Header.Height)
    }

    // 2️⃣ Retrieve previous block (if not genesis)
    var prev *Block
    if blk.Header.Height > 0 {
        prev, err = l.GetBlockByHeight(blk.Header.Height - 1)
        if err != nil {
            return fmt.Errorf("failed to get previous block: %v", err)
        }
    }

    // 3️⃣ Validate hash, MerkleRoot, PrevHash, and miner signature
    if err := blk.Validate(prev); err != nil {
        log.Printf("❌ Block #%d validation failed: %v", blk.Header.Height, err)

        // Automatically isolate corrupted block
        corruptedName := fmt.Sprintf("corrupted_%d_%s", blk.Header.Height, time.Now().Format("20060102_150405"))
        oldPath := filepath.Join(l.dbPath, fmt.Sprintf("block_%d", blk.Header.Height))
        newPath := filepath.Join(l.dbPath, corruptedName)
        _ = os.Rename(oldPath, newPath)

        log.Printf("⚠️ Block #%d renamed to %s for forensic audit", blk.Header.Height, corruptedName)
        return fmt.Errorf("block validation failed and was quarantined: %v", err)
    }

    // 4️⃣ Store the block atomically
    if err := l.StoreBlockBatch(blk); err != nil {
        return fmt.Errorf("failed to store block: %v", err)
    }

    // 5️⃣ Log confirmation using existing ComputeFinalHash()
    computedHash := blk.ComputeFinalHash()
    log.Printf("✅ Block #%d committed successfully — Hash: %s", blk.Header.Height, computedHash)

    return nil
}

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


// ---------------- Concurrent Block Iteration ----------------
func (l *Ledger) IterateBlocks(cb func(*Block) error) error {
        if l == nil || l.db == nil {
                return fmt.Errorf("ledger not initialized")
        }

        return l.db.View(func(txn *badger.Txn) error {
                opts := badger.DefaultIteratorOptions
                opts.PrefetchValues = true
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

                        if err := cb(&blk); err != nil {
                                return err
                        }
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
