// internal/ledger/snapshot.go
package ledger

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"explosive/internal/compressor"
)

// ---------------- Snapshot Structures ----------------

// SnapshotMeta stores essential ledger metadata for restoration
type SnapshotMeta struct {
	ChainTip    uint64 `cbor:"chain_tip"`
	TotalIssued uint64 `cbor:"total_issued"`
	Timestamp   int64  `cbor:"timestamp"` // Unix ms
}

// Snapshot represents a snapshot object for testing or inspection
type Snapshot struct {
	ChainTip    uint64
	TotalIssued uint64
	Path        string // Path to the snapshot file
}

// ---------------- High-Level Snapshot Helpers ----------------

// CreateSnapshot creates a ledger snapshot on disk and returns a Snapshot object.
// This is a wrapper for CreateSnapshotStream for test compatibility.
func (l *Ledger) CreateSnapshot(path string) (*Snapshot, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}

	// Create a streaming snapshot on disk
	if err := l.CreateSnapshotStream(path); err != nil {
		return nil, err
	}

	// Read ledger metadata into Snapshot struct for testing or inspection
	chainTip, err := l.GetChainTipHeight()
	if err != nil {
		return nil, err
	}
	total, err := l.GetTotalIssued()
	if err != nil {
		return nil, err
	}

	return &Snapshot{
		ChainTip:    chainTip,
		TotalIssued: total,
		Path:        path,
	}, nil
}

// RestoreSnapshot restores the ledger from a snapshot file.
// This is a wrapper for RestoreSnapshotStream.
func (l *Ledger) RestoreSnapshot(path string) error {
	return l.RestoreSnapshotStream(path)
}

// ---------------- Streaming Snapshot (Zero-Copy) ----------------

// CreateSnapshotStream writes a snapshot to disk in streaming mode.
// Each block is compressed and encoded individually to minimize memory usage.
func (l *Ledger) CreateSnapshotStream(path string) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := cbor.NewEncoder(file)

	// Write ledger metadata first
	meta := SnapshotMeta{
		Timestamp: NowMillis(),
	}
	meta.ChainTip, err = l.GetChainTipHeight()
	if err != nil {
		return err
	}
	meta.TotalIssued, err = l.GetTotalIssued()
	if err != nil {
		return err
	}
	if err := enc.Encode(meta); err != nil {
		return err
	}

	// Stream blocks one by one
	return l.IterateBlocks(func(b *Block) error {
		rawData, err := cbor.Marshal(b)
		if err != nil {
			return err
		}

		compData, err := compressor.CompressZSTD(rawData)
		if err != nil {
			compData = rawData // fallback if compression fails
		}

		return enc.Encode(compData)
	})
}

// RestoreSnapshotStream restores blocks from a streaming snapshot file.
// Decompression is performed for each block individually.
func (l *Ledger) RestoreSnapshotStream(path string) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	dec := cbor.NewDecoder(file)

	// Decode metadata first
	var meta SnapshotMeta
	if err := dec.Decode(&meta); err != nil {
		return err
	}

	// Restore blocks one by one
	for {
		var compData []byte
		if err := dec.Decode(&compData); err != nil {
			break // EOF reached
		}

		decomp, err := compressor.DecompressZSTD(compData)
		if err != nil {
			decomp = compData // fallback
		}

		var blk Block
		if err := cbor.Unmarshal(decomp, &blk); err != nil {
			return err
		}

		// Store block asynchronously
		if err := l.PutBlock(blk.Header.Height, &blk); err != nil {
			return err
		}
	}

	// Restore ledger metadata
	if err := l.PutBytes(MetaChainTip, u64ToBytes(meta.ChainTip)); err != nil {
		return err
	}
	return l.PutBytes(MetaTotalIssued, u64ToBytes(meta.TotalIssued))
}

// ---------------- Helper Functions ----------------

// u64ToBytes encodes a uint64 as an 8-byte big-endian slice
func u64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}
