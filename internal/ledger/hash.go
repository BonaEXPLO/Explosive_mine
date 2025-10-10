// internal/ledger/hash.go
package ledger

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// Sha3Hex returns the sha3-256 hex string of the input bytes.
func Sha3Hex(data []byte) string {
	h := sha3.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Sha3Bytes returns the sha3-256 bytes.
func Sha3Bytes(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}
