// internal/crypto/argon2.go
package crypto

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// This file provides an adaptive Argon2id wrapper tailored for mobile devices.
// It selects a memory cost between 8MiB and 64MiB depending on the device RAM,
// uses a conservative time (iterations) parameter for responsiveness on phones,
// and sets parallelism based on CPU cores. Comments are in English as requested.

const (
	minMemoryMiB = 8    // minimum memory cost (MiB)
	midMemoryMiB = 32   // medium memory cost (MiB)
	maxMemoryMiB = 64   // maximum memory cost (MiB)

	defaultTime      = 3 // iterations / time cost
	defaultKeyLen    = 32
	saltLen          = 16
	encodedSeparator = ";"
)

// Params holds chosen Argon2id parameters for hashing/verifying.
type Params struct {
	Memory      uint32 // in KiB
	Time        uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams returns adaptive parameters based on the host device.
func DefaultParams() Params {
	memMiB := detectMemoryMiB()
	var selectedMiB uint32
	if memMiB < 1024 { // <1GB RAM -> conserve
		selectedMiB = minMemoryMiB
	} else if memMiB < 2048 { // 1-2GB -> medium
		selectedMiB = midMemoryMiB
	} else {
		selectedMiB = maxMemoryMiB
	}

	// convert MiB to KiB for Argon2 API (which takes KiB)
	memoryKiB := selectedMiB * 1024

	p := Params{
		Memory:      memoryKiB,
		Time:        defaultTime,
		Parallelism: uint8(minInt(runtime.NumCPU(), 4)),
		SaltLen:     saltLen,
		KeyLen:      defaultKeyLen,
	}
	return p
}

// HashPassword hashes the given plaintext password with Argon2id and returns
// an encoded string containing parameters, salt and hash (safe for storage).
func HashPassword(password string, p Params) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}

	salt, err := generateRandomBytes(int(p.SaltLen))
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// encoded format (simple, parseable):
	// argon2id;memory=...;time=...;par=...;salt=<b64>;hash=<b64>
	encoded := strings.Join([]string{
		"argon2id",
		fmt.Sprintf("memory=%d", p.Memory),
		fmt.Sprintf("time=%d", p.Time),
		fmt.Sprintf("par=%d", p.Parallelism),
		"salt=" + b64Salt,
		"hash=" + b64Hash,
	}, encodedSeparator)

	return encoded, nil
}

// VerifyPassword checks a plaintext password against the encoded stored value.
func VerifyPassword(password, encoded string) (bool, error) {
	if password == "" {
		return false, errors.New("empty password")
	}

	parts := strings.Split(encoded, encodedSeparator)
	if len(parts) < 6 || parts[0] != "argon2id" {
		return false, errors.New("invalid encoded format")
	}

	var p Params
	// defaults
	p.SaltLen = saltLen
	p.KeyLen = defaultKeyLen

	var b64Salt, b64Hash string
	for _, part := range parts[1:] {
		if strings.HasPrefix(part, "memory=") {
			v := strings.TrimPrefix(part, "memory=")
			mem, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return false, fmt.Errorf("invalid memory param: %w", err)
			}
			p.Memory = uint32(mem)
			continue
		}
		if strings.HasPrefix(part, "time=") {
			v := strings.TrimPrefix(part, "time=")
			t, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return false, fmt.Errorf("invalid time param: %w", err)
			}
			p.Time = uint32(t)
			continue
		}
		if strings.HasPrefix(part, "par=") {
			v := strings.TrimPrefix(part, "par=")
			par, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return false, fmt.Errorf("invalid par param: %w", err)
			}
			p.Parallelism = uint8(par)
			continue
		}
		if strings.HasPrefix(part, "salt=") {
			b64Salt = strings.TrimPrefix(part, "salt=")
			continue
		}
		if strings.HasPrefix(part, "hash=") {
			b64Hash = strings.TrimPrefix(part, "hash=")
			continue
		}
	}

	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 || b64Salt == "" || b64Hash == "" {
		return false, errors.New("incomplete encoded params")
	}

	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(b64Hash)
	if err != nil {
		return false, fmt.Errorf("invalid hash encoding: %w", err)
	}

	computed := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Parallelism, uint32(len(expectedHash)))

	if subtleConstantTimeCompare(expectedHash, computed) {
		return true, nil
	}
	return false, nil
}

// generateRandomBytes returns n random bytes using crypto/rand
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// detectMemoryMiB attempts to detect total system memory in MiB by reading /proc/meminfo.
// On failure it returns 1024 (1GiB) as a conservative default.
func detectMemoryMiB() uint32 {
	// Try Linux /proc/meminfo (works on Android/Termux too)
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 1024
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			// MemTotal is in kB
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				break
			}
			miB := kb / 1024
			return uint32(miB)
		}
	}
	return 1024
}

// subtleConstantTimeCompare uses a constant-time comparison to avoid timing leaks.
func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Optional: convenience wrapper that hashes using DefaultParams and returns encoded string
func HashPasswordAdaptive(password string) (string, error) {
	p := DefaultParams()
	// small sleep to reduce fingerprinting speed? keep minimal
	// time.Sleep(10 * time.Millisecond)
	return HashPassword(password, p)
}

// Optional: bench function to estimate runtime (not used in production by default)
func EstimateHashDuration(password string, runs int) (time.Duration, error) {
	p := DefaultParams()
	start := time.Now()
	for i := 0; i < runs; i++ {
		_, err := HashPassword(password, p)
		if err != nil {
			return 0, err
		}
	}
	return time.Since(start), nil
}
