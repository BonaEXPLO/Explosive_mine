// internal/ledger/snapshot.go
package ledger

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"explosive/internal/compressor"
)

// ------------------------------------------------------------
// CONSTANTS
// ------------------------------------------------------------

const (
	snapshotMagic   = uint32(0x58454C53) // "SLEX"
	snapshotVersion = uint32(5)          // V5 with Merkle root
	metaSlotSize    = 16 * 1024
	tmpSuffix       = ".tmp"

	maxBlockSize = 4 * 1024 * 1024 // 4MB safety
)

// ------------------------------------------------------------
// TYPES
// ------------------------------------------------------------

type NetworkID [32]byte

var CurrentNetworkID NetworkID

type SnapshotMetaV5 struct {
	ChainTip       uint64     `cbor:"chain_tip"`
	TotalIssued    uint64     `cbor:"total_issued"`
	BlockCount     uint64     `cbor:"block_count"`
	Timestamp      int64      `cbor:"timestamp"`
	NetworkID      [32]byte   `cbor:"network_id"`
	StreamChecksum []byte     `cbor:"stream_checksum"`
	BlockHashChain []byte     `cbor:"block_hash_chain"`
	MerkleRoots    [][]byte   `cbor:"merkle_roots"`
}

type Snapshot struct {
	ChainTip    uint64
	TotalIssued uint64
	BlockCount  uint64
	Path        string
	Version     uint32
}

// ------------------------------------------------------------
// CREATE SNAPSHOT (V5 with Merkle)
// ------------------------------------------------------------

func (l *Ledger) CreateSnapshot(path string) (*Snapshot, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}

	if err := l.Sync(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}

	tmpPath := path + tmpSuffix

	if err := l.createSnapshotV5(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	tip, _ := l.GetChainTipHeight()
	total, _ := l.GetTotalIssued()

	return &Snapshot{
		ChainTip:    tip,
		TotalIssued: total,
		BlockCount:  tip + 1,
		Path:        path,
		Version:     snapshotVersion,
	}, nil
}

func (l *Ledger) createSnapshotV5(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Header
	if err := binary.Write(f, binary.LittleEndian, snapshotMagic); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, snapshotVersion); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(metaSlotSize)); err != nil {
		return err
	}

	// Reserve metadata slot
	if _, err := f.Write(make([]byte, metaSlotSize)); err != nil {
		return err
	}

	streamHash, _ := blake2b.New256(nil)
	blockChainAcc, _ := blake2b.New256(nil)

	writer := io.MultiWriter(f, streamHash)
	enc := cbor.NewEncoder(writer)

	var expected uint64 = 0
	merkleRoots := make([][]byte, 0)

	err = l.IterateBlocks(func(b *Block) error {
		if b.Header.Height != expected {
			return fmt.Errorf("height mismatch at %d", expected)
		}

		// ✅ FIX: version-aware merkle root (IMPORTANT)
		merkle, err := ComputeMerkleRoot(b.Transactions, b.Header.Version)
		if err != nil {
			return fmt.Errorf("merkle root failed at block %d: %w", b.Header.Height, err)
		}

		merkleRoots = append(merkleRoots, []byte(merkle))
		b.Header.MerkleRoot = merkle

		raw, err := cbor.Marshal(b)
		if err != nil {
			return err
		}

		perHash := blake2b.Sum256(raw)
		blockChainAcc.Write(perHash[:])

		comp, err := compressor.CompressZSTD(raw)
		if err != nil {
			return err
		}

		if err := enc.Encode(comp); err != nil {
			return err
		}

		expected++
		return nil
	})

	if err != nil {
		return err
	}

	tip, _ := l.GetChainTipHeight()
	total, _ := l.GetTotalIssued()

	meta := SnapshotMetaV5{
		ChainTip:       tip,
		TotalIssued:    total,
		BlockCount:     tip + 1,
		Timestamp:      NowMillis(),
		NetworkID:      CurrentNetworkID,
		StreamChecksum: streamHash.Sum(nil),
		BlockHashChain: blockChainAcc.Sum(nil),
		MerkleRoots:    merkleRoots,
	}

	opts := cbor.CanonicalEncOptions()
	mode, _ := opts.EncMode()
	metaBytes, err := mode.Marshal(meta)
	if err != nil {
		return err
	}

	if len(metaBytes) > metaSlotSize {
		return fmt.Errorf("metadata too large")
	}

	if _, err := f.Seek(12, io.SeekStart); err != nil {
		return err
	}

	if _, err := f.Write(metaBytes); err != nil {
		return err
	}

	padding := metaSlotSize - len(metaBytes)
	if padding > 0 {
		f.Write(bytes.Repeat([]byte{0}, padding))
	}

	return f.Sync()
}

// ------------------------------------------------------------
// RESTORE SNAPSHOT (V5)
// ------------------------------------------------------------

func (l *Ledger) RestoreSnapshot(path string) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}

	// Backup before restore
	backup := fmt.Sprintf("%s.backup-%d", path, time.Now().Unix())
	_, _ = l.CreateSnapshot(backup)

	if err := l.WipeLedgerForRestore(); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var magic, version, slotLen uint32

	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return err
	}
	if magic != snapshotMagic {
		return fmt.Errorf("invalid snapshot magic")
	}

	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		return err
	}
	if version != snapshotVersion {
		return fmt.Errorf("unsupported snapshot version")
	}

	if err := binary.Read(f, binary.LittleEndian, &slotLen); err != nil {
		return err
	}

	metaBuf := make([]byte, slotLen)
	if _, err := io.ReadFull(f, metaBuf); err != nil {
		return err
	}

	metaBuf = bytes.TrimRight(metaBuf, "\x00")

	var meta SnapshotMetaV5
	if err := cbor.Unmarshal(metaBuf, &meta); err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(meta.NetworkID[:], CurrentNetworkID[:]) != 1 {
		return fmt.Errorf("network ID mismatch")
	}

	streamHash, _ := blake2b.New256(nil)
	blockChainAcc, _ := blake2b.New256(nil)

	dec := cbor.NewDecoder(io.TeeReader(f, streamHash))

	for i := uint64(0); i < meta.BlockCount; i++ {

		var payload []byte
		if err := dec.Decode(&payload); err != nil {
			return err
		}

		raw, err := compressor.DecompressZSTD(payload)
		if err != nil {
			return err
		}

		if len(raw) > maxBlockSize {
			return fmt.Errorf("block too large")
		}

		perHash := blake2b.Sum256(raw)
		blockChainAcc.Write(perHash[:])

		var blk Block
		if err := cbor.Unmarshal(raw, &blk); err != nil {
			return err
		}

		if blk.Header.Height != i {
			return fmt.Errorf("height mismatch")
		}

		// ------------------------------------------------------------
		// 🔥 MERKLE ROOT VERIFICATION (V1 FIX APPLIED HERE)
		// ------------------------------------------------------------
		expectedMerkle, err := ComputeMerkleRoot(blk.Transactions, blk.Header.Version)
                if err != nil {
                        return fmt.Errorf("merkle compute failed at block %d: %w", i, err)
                }

                if blk.Header.MerkleRoot != expectedMerkle {
                       return fmt.Errorf("merkle root mismatch at block %d", i)
                }

		// ------------------------------------------------------------
		// BLOCK HASH CHECK
		// ------------------------------------------------------------
		if blk.ComputeFinalHash() != blk.BlockHash {
			return fmt.Errorf("block hash mismatch")
		}

		if err := l.PutBlock(i, &blk); err != nil {
			return err
		}
	}

	if subtle.ConstantTimeCompare(streamHash.Sum(nil), meta.StreamChecksum) != 1 {
		return fmt.Errorf("stream checksum mismatch")
	}

	if subtle.ConstantTimeCompare(blockChainAcc.Sum(nil), meta.BlockHashChain) != 1 {
		return fmt.Errorf("block chain checksum mismatch")
	}

	l.PutBytes(MetaChainTip, u64ToBytes(meta.ChainTip))
	l.PutBytes(MetaTotalIssued, u64ToBytes(meta.TotalIssued))

	log.Printf("Snapshot V5 restored successfully. tip=%d blocks=%d",
		meta.ChainTip, meta.BlockCount)

	return nil
}

// ------------------------------------------------------------
// WIPE (SAFE)
// ------------------------------------------------------------

func (l *Ledger) WipeLedgerForRestore() error {
	const maxKeys = 10_000_000
	deleted := 0

	return l.db.Update(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().KeyCopy(nil)

			if bytes.HasPrefix(key, []byte("config_")) ||
				bytes.HasPrefix(key, []byte("meta:")) ||
				bytes.HasPrefix(key, []byte("genesis:")) ||
				bytes.HasPrefix(key, []byte("network:")) ||
				bytes.HasPrefix(key, []byte("pow:")) {
				continue
			}

			if err := txn.Delete(key); err != nil {
				return err
			}

			deleted++
			if deleted > maxKeys {
				return fmt.Errorf("wipe limit exceeded")
			}
		}
		return nil
	})
}

// ------------------------------------------------------------
// UTILITIES
// ------------------------------------------------------------

func u64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

func (l *Ledger) Sync() error {
	return nil
}

func (l *Ledger) TryRestoreSnapshotSafe(path string) error {
	return l.RestoreSnapshot(path)
}

