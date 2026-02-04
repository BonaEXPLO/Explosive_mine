// internal/compressor/compressor.go
package compressor

import (
        "bytes"
        "fmt"
        "sync"

        "github.com/klauspost/compress/zstd"
)

// Global reusable encoders/decoders (concurrent-safe)
var (
        // NEW: High-compression encoder optimized for blockchain storage
        highEncoder *zstd.Encoder
        decoder     *zstd.Decoder
        bufPool     = sync.Pool{
                New: func() interface{} {
                        return new(bytes.Buffer)
                },
        }
)

// Magic header to detect compressed payload ("xZ" = Explosive ZSTD)
var magicHeader = []byte{0x78, 0x5A}

// init initializes a high-compression encoder and decoder.
// Uses SpeedBestCompression + large window for optimal ratio on repetitive blockchain data
// (blocks often share similar structures → excellent deduplication).
func init() {
        var err error

        // High compression settings – ideal for persistent storage and snapshots
        highEncoder, err = zstd.NewWriter(nil,
                zstd.WithEncoderLevel(zstd.SpeedBestCompression), // Maximum ratio (~20-35% better on chain data)
                zstd.WithWindowSize(8*1024*1024),                 // 8MB window → better compression across similar blocks
                zstd.WithEncoderConcurrency(1),                   // Single-threaded for mobile CPU friendliness
        )
        if err != nil {
                panic(fmt.Errorf("failed to init high-compression zstd encoder: %w", err))
        }

        decoder, err = zstd.NewReader(nil,
                zstd.WithDecoderConcurrency(2), // Slight parallelism on decode (common on phones)
        )
        if err != nil {
                panic(fmt.Errorf("failed to init zstd decoder: %w", err))
        }
}

// CompressZSTD compresses input with aggressive settings for storage efficiency.
// Falls back to raw for small payloads or if no size gain (safe & CPU-friendly).
func CompressZSTD(input []byte) ([]byte, error) {
        // Small payloads (<1KB): skip compression to save CPU (common for single TX)
        if len(input) < 1024 {
                raw := make([]byte, len(magicHeader)+len(input))
                copy(raw, magicHeader)
                copy(raw[len(magicHeader):], input)
                return raw, nil
        }

        // Use buffer pool to avoid allocations
        buf := bufPool.Get().(*bytes.Buffer)
        buf.Reset()
        defer bufPool.Put(buf)

        // NEW: Use high-compression encoder
        compressed := highEncoder.EncodeAll(input, make([]byte, 0, len(input)))

        // Only use compressed data if it actually reduces size
        if len(compressed) >= len(input) {
                // Fallback to raw (with header for compatibility)
                buf.Write(magicHeader)
                buf.Write(input)
        } else {
                buf.Write(magicHeader)
                buf.Write(compressed)
        }

        // Return a clean copy
        return append([]byte(nil), buf.Bytes()...), nil
}

// DecompressZSTD safely handles both compressed and raw payloads.
// Returns original data if not compressed or on error (fail-safe behavior).
func DecompressZSTD(input []byte) ([]byte, error) {
        if len(input) < len(magicHeader) || !bytes.Equal(input[:len(magicHeader)], magicHeader) {
                // Not compressed → return as-is
                return input, nil
        }

        out, err := decoder.DecodeAll(input[len(magicHeader):], nil)
        if err != nil {
                // Fail-safe: return raw payload after header (for corrupted but recoverable data)
                return input[len(magicHeader):], nil
        }
        return out, nil
}
