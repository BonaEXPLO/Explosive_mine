// internal/compressor/compressor.go
package compressor

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Global encoders/decoders (safe for concurrent use)
var (
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	bufPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

// Magic header to detect compressed payload
var magicHeader = []byte{0x78, 0x5A} // "xZ" (Explosive ZSTD)

// init initializes global encoder and decoder for reuse.
func init() {
	var err error
	encoder, err = zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedFastest), // fastest for small-medium payloads
	)
	if err != nil {
		panic(fmt.Errorf("failed to init zstd encoder: %w", err))
	}

	decoder, err = zstd.NewReader(nil)
	if err != nil {
		panic(fmt.Errorf("failed to init zstd decoder: %w", err))
	}
}

// CompressZSTD compresses input with adaptive logic (saves CPU on small payloads).
func CompressZSTD(input []byte) ([]byte, error) {
	if len(input) < 1024 {
		// Small payload → return raw (faster)
		raw := make([]byte, len(magicHeader)+len(input))
		copy(raw, magicHeader)
		copy(raw[len(magicHeader):], input)
		return raw, nil
	}

	// Use buffer pool to reduce allocations
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	compressed := encoder.EncodeAll(input, nil)

	// Prepend header
	buf.Write(magicHeader)
	buf.Write(compressed)

	return append([]byte(nil), buf.Bytes()...), nil
}

// DecompressZSTD safely decompresses or returns raw if not compressed.
func DecompressZSTD(input []byte) ([]byte, error) {
	if len(input) < len(magicHeader) {
		return input, nil
	}
	if !bytes.Equal(input[:len(magicHeader)], magicHeader) {
		// Not compressed → return raw
		return input, nil
	}

	out, err := decoder.DecodeAll(input[len(magicHeader):], nil)
	if err != nil {
		// Fail-safe: return original payload
		return input[len(magicHeader):], nil
	}
	return out, nil
}
