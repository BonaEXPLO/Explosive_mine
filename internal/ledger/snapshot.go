// internal/ledger/snapshot.go
package ledger

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
	"explosive/internal/compressor"
)

// ---------------- Constants & Types ----------------

const (
	// 4-byte magic "SLEX"
	snapshotMagic   = uint32(0x58454C53)
	snapshotVersion = uint32(3)
	tmpSuffix       = ".tmp"

	// Reserved metadata slot size (future-proof)
	metaSlotSize = 16 * 1024
)

var debugRestore = false // set to true to enable debug prints during restore

type NetworkID [32]byte
var CurrentNetworkID NetworkID

type SnapshotMetaV3 struct {
	ChainTip       uint64 `cbor:"chain_tip"`
	TotalIssued    uint64 `cbor:"total_issued"`
	Timestamp      int64  `cbor:"timestamp"`
	BlockCount     uint64 `cbor:"block_count"`
	NetworkID      [32]byte `cbor:"network_id"`
	StreamChecksum []byte   `cbor:"stream_checksum"`
	BlockHashChain []byte   `cbor:"block_hash_chain"`
}

type SnapshotMetaV1 struct {
	ChainTip    uint64 `cbor:"chain_tip"`
	TotalIssued uint64 `cbor:"total_issued"`
	Timestamp   int64  `cbor:"timestamp"`
}

type Snapshot struct {
	ChainTip    uint64
	TotalIssued uint64
	BlockCount  uint64
	Path        string
	Version     uint32
}

// ---------------- Public API ----------------

func (l *Ledger) CreateSnapshot(path string) (*Snapshot, error) {
	if l == nil || l.db == nil {
		return nil, fmt.Errorf("ledger not initialized")
	}
	if err := l.Sync(); err != nil {
		return nil, fmt.Errorf("failed to sync ledger DB before snapshot: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}

	tmpPath := path + tmpSuffix
	if err := l.createSnapshotV3(tmpPath); err != nil {
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

func (l *Ledger) RestoreSnapshot(path string) error {
	if l == nil || l.db == nil {
		return fmt.Errorf("ledger not initialized")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var magic, version uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		log.Printf("No magic header -> fallback to legacy v1")
		return l.restoreSnapshotV1(path)
	}
	if magic != snapshotMagic {
		log.Printf("Invalid magic 0x%x (expected 0x%x) -> fallback to legacy v1", magic, snapshotMagic)
		return l.restoreSnapshotV1(path)
	}
	if err := binary.Read(f, binary.LittleEndian, &version); err != nil {
		log.Printf("Failed to read snapshot version -> fallback to legacy v1")
		return l.restoreSnapshotV1(path)
	}

	log.Printf("Detected snapshot v%d -> using v3 restore", version)
	if version == 3 {
		return l.restoreSnapshotV3(path)
	}
	return l.restoreSnapshotV1(path)
}

// ---------------- Internal: Create v3 ----------------

func (l *Ledger) createSnapshotV3(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := binary.Write(f, binary.LittleEndian, snapshotMagic); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, snapshotVersion); err != nil {
		return err
	}

	if err := binary.Write(f, binary.LittleEndian, uint32(metaSlotSize)); err != nil {
		return err
	}

	metaSlotZero := make([]byte, metaSlotSize)
	if _, err := f.Write(metaSlotZero); err != nil {
		return err
	}

	streamHash, _ := blake2b.New256(nil)
	enc := cbor.NewEncoder(io.MultiWriter(f, streamHash))

	tip, err := l.GetChainTipHeight()
	if err != nil {
		return err
	}
	total, err := l.GetTotalIssued()
	if err != nil {
		return err
	}

	metaHeader := SnapshotMetaV3{
		ChainTip:   tip,
		TotalIssued: total,
		Timestamp:  NowMillis(),
		BlockCount: tip + 1,
		NetworkID:  CurrentNetworkID,
	}

	blockChainAcc, _ := blake2b.New256(nil)
	expected := uint64(0)
	err = l.IterateBlocks(func(b *Block) error {
		if b.Header.Height != expected {
			return fmt.Errorf("block height inconsistency: expected %d got %d", expected, b.Header.Height)
		}

		raw, merr := cbor.Marshal(b)
		if merr != nil {
			return merr
		}

		perBlockHash := blake2b.Sum256(raw)
		if _, err := blockChainAcc.Write(perBlockHash[:]); err != nil {
			return err
		}

		comp, cerr := compressor.CompressZSTD(raw)
		if cerr != nil || len(comp) == 0 {
			comp = raw
		}

		if err := enc.Encode(comp); err != nil {
			return err
		}

		expected++
		return nil
	})
	if err != nil {
		_ = f.Sync()
		return err
	}

	metaHeader.StreamChecksum = streamHash.Sum(nil)
	metaHeader.BlockHashChain = blockChainAcc.Sum(nil)

	// CBOR déterministe
	encOpts := cbor.CanonicalEncOptions()
	encMode, _ := encOpts.EncMode()
	metaBytes, err := encMode.Marshal(metaHeader)
	if err != nil {
		return fmt.Errorf("failed to marshal final metadata: %w", err)
	}

	if len(metaBytes) > metaSlotSize {
		return fmt.Errorf("metadata too large (%d bytes) to fit reserved slot (%d)", len(metaBytes), metaSlotSize)
	}

	if _, err := f.Seek(8+4, io.SeekStart); err != nil {
		return err
	}
	if _, err := f.Write(metaBytes); err != nil {
		return err
	}
	if pad := metaSlotSize - len(metaBytes); pad > 0 {
		if _, err := f.Write(bytes.Repeat([]byte{0}, pad)); err != nil {
			return err
		}
	}

	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}

// ---------------- Internal: Restore v3 ----------------

func (l *Ledger) restoreSnapshotV3(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	var magic, version uint32
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
		return fmt.Errorf("unexpected snapshot version: %d", version)
	}

	var slotLen uint32
	if err := binary.Read(f, binary.LittleEndian, &slotLen); err != nil {
		return err
	}
	if slotLen == 0 || int(slotLen) > metaSlotSize {
		return fmt.Errorf("invalid meta slot length: %d", slotLen)
	}

	metaSlot := make([]byte, slotLen)
	if _, err := io.ReadFull(f, metaSlot); err != nil {
		return err
	}
	metaTrimmed := bytes.TrimRight(metaSlot, "\x00")

	var meta SnapshotMetaV3
	if err := cbor.Unmarshal(metaTrimmed, &meta); err != nil {
		return fmt.Errorf("failed to decode snapshot metadata: %w", err)
	}

	if subtle.ConstantTimeCompare(meta.NetworkID[:], CurrentNetworkID[:]) != 1 {
		return fmt.Errorf("snapshot network-id mismatch (snapshot vs node)")
	}

	streamHash, _ := blake2b.New256(nil)
	tee := io.TeeReader(f, streamHash)
	dec := cbor.NewDecoder(tee)
	blockChainAcc, _ := blake2b.New256(nil)

	if debugRestore {
		log.Printf("[debug] Starting restore of %d blocks from snapshot v3", meta.BlockCount)
	}

	for i := uint64(0); i < meta.BlockCount; i++ {
		var rawItem interface{}
		if err := dec.Decode(&rawItem); err != nil {
			return fmt.Errorf("failed to decode raw item for block %d: %w", i, err)
		}

		var blk Block
		var payloadForHash []byte

		switch v := rawItem.(type) {
		case []byte:
			decomp, derr := compressor.DecompressZSTD(v)
			if derr != nil || len(decomp) == 0 {
				decomp = v
			}
			if err := cbor.Unmarshal(decomp, &blk); err != nil {
				if debugRestore {
					debugLen := 64
					if len(decomp) < debugLen {
						debugLen = len(decomp)
					}
					fmt.Printf("[debug] block %d first %d bytes: % x\n", i, debugLen, decomp[:debugLen])
				}
				return fmt.Errorf("failed to unmarshal block %d: %w", i, err)
			}
			payloadForHash, _ = cbor.Marshal(blk)

		case string:
			if raw, hexErr := hex.DecodeString(v); hexErr == nil {
				decomp, _ := compressor.DecompressZSTD(raw)
				if len(decomp) == 0 {
					decomp = raw
				}
				if err := cbor.Unmarshal(decomp, &blk); err != nil {
					return fmt.Errorf("failed to unmarshal legacy hex block %d: %w", i, err)
				}
				payloadForHash, _ = cbor.Marshal(blk)
			} else {
				decomp := []byte(v)
				if err := cbor.Unmarshal(decomp, &blk); err != nil {
					return fmt.Errorf("failed to unmarshal legacy string block %d: %w", i, err)
				}
				payloadForHash, _ = cbor.Marshal(blk)
			}

		default:
			data, _ := cbor.Marshal(rawItem)
			decomp, _ := compressor.DecompressZSTD(data)
			if len(decomp) == 0 {
				decomp = data
			}
			if err := cbor.Unmarshal(decomp, &blk); err != nil {
				return fmt.Errorf("failed to unmarshal unknown block type %d: %w", i, err)
			}
			payloadForHash, _ = cbor.Marshal(blk)
		}

		if blk.Header.Height != i {
			return fmt.Errorf("block height mismatch: expected %d, got %d", i, blk.Header.Height)
		}

		perHash := blake2b.Sum256(payloadForHash)
		if _, err := blockChainAcc.Write(perHash[:]); err != nil {
			return err
		}

		if err := l.PutBlock(i, &blk); err != nil {
			return err
		}
	}

	if subtle.ConstantTimeCompare(streamHash.Sum(nil), meta.StreamChecksum) != 1 {
		return fmt.Errorf("stream checksum mismatch — snapshot corrupted or tampered")
	}
	if subtle.ConstantTimeCompare(blockChainAcc.Sum(nil), meta.BlockHashChain) != 1 {
		return fmt.Errorf("block hash chain mismatch — blocks reordered or tampered")
	}

	if err := l.PutBytes(MetaChainTip, u64ToBytes(meta.ChainTip)); err != nil {
		return err
	}
	if err := l.PutBytes(MetaTotalIssued, u64ToBytes(meta.TotalIssued)); err != nil {
		return err
	}

	if debugRestore {
		log.Printf("[debug] Snapshot v3 restored successfully — height=%d, total_issued=%d", meta.ChainTip, meta.TotalIssued)
	}

	return nil
}

// ---------------- Legacy v1 restore ----------------

func (l *Ledger) restoreSnapshotV1(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := cbor.NewDecoder(f)
	var meta SnapshotMetaV1
	if err := dec.Decode(&meta); err != nil {
		return fmt.Errorf("failed to decode legacy snapshot metadata: %w", err)
	}

	for {
		var payload []byte
		if err := dec.Decode(&payload); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed while decoding legacy block stream: %w", err)
		}

		decomp, _ := compressor.DecompressZSTD(payload)
		if len(decomp) == 0 {
			decomp = payload
		}

		var blk Block
		if err := cbor.Unmarshal(decomp, &blk); err != nil {
			blk = Block{Header: BlockHeader{Height: l.getNextBlockHeight()}}
			if err := cbor.Unmarshal(decomp, &blk); err != nil {
				return fmt.Errorf("failed to unmarshal legacy block after fallback: %w", err)
			}
		}
		if err := l.PutBlock(blk.Header.Height, &blk); err != nil {
			return err
		}
	}

	if err := l.PutBytes(MetaChainTip, u64ToBytes(meta.ChainTip)); err != nil {
		return err
	}
	if err := l.PutBytes(MetaTotalIssued, u64ToBytes(meta.TotalIssued)); err != nil {
		return err
	}
	return nil
}

// ---------------- Utilities ----------------

func u64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// Sync should be implemented per DB backend (Bolt, Badger, etc.)
func (l *Ledger) Sync() error {
	// TODO: implement actual DB sync
	return nil
}

func (l *Ledger) getNextBlockHeight() uint64 {
	tip, err := l.GetChainTipHeight()
	if err != nil {
		return 0
	}
	return tip + 1
}
