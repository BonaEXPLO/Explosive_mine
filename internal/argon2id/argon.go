package argon2id

import (
        "crypto/rand"
        "errors"
        "golang.org/x/crypto/argon2"
)

// Parameters holds Argon2id configuration values.
type Parameters struct {
        Time    uint32 // Number of iterations
        Memory  uint32 // Memory cost in KiB (8 MiB → 64 MiB)
        Threads uint8  // Parallelism
        KeyLen  uint32 // Length of derived key in bytes
}

// DefaultParameters returns adaptive Argon2id parameters
// based on the target environment (low, medium, high).
// Memory is between 8MiB and 64MiB.
func DefaultParameters(level string) Parameters {
        switch level {
        case "low": // phones, IoT
                return Parameters{Time: 1, Memory: 8 * 1024, Threads: 2, KeyLen: 32}
        case "medium": // mid-range devices
                return Parameters{Time: 1, Memory: 32 * 1024, Threads: 4, KeyLen: 32}
        case "high": // servers, high-end devices
                return Parameters{Time: 2, Memory: 64 * 1024, Threads: 4, KeyLen: 32}
        default: // fallback
                return Parameters{Time: 1, Memory: 32 * 1024, Threads: 2, KeyLen: 32}
        }
}

// GenerateSalt creates a random salt of given length.
func GenerateSalt(length int) ([]byte, error) {
        salt := make([]byte, length)
        _, err := rand.Read(salt)
        if err != nil {
                return nil, err
        }
        return salt, nil
}

// DeriveKey derives a key using Argon2id with given params.
func DeriveKey(password, salt []byte, params Parameters) ([]byte, error) {
        if len(password) == 0 || len(salt) == 0 {
                return nil, errors.New("password and salt must not be empty")
        }
        key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
        return key, nil
}

// DeriveKeyDefault derives a key with adaptive parameters for mobile/desktop.
// It hides Parameters selection for simplicity.
func DeriveKeyDefault(password, salt []byte) []byte {
        params := DefaultParameters("medium") // change "medium" → "low"/"high" si besoin
        key, _ := DeriveKey(password, salt, params)
        return key
}
