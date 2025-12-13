// internal/guardian/device_lock.go
package guardian

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// 🔒 Persistent directory (~/.explosive)
// This folder stores the local device lock information.
func getLockDir() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".explosive")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// 🔒 Lock file path
// The file that records the link between the device and a single miner account.
func getLockFilePath() string {
	return filepath.Join(getLockDir(), "device_lock.json")
}

// deviceLock defines the structure saved locally
// It binds a device fingerprint (hash) to a single MinerID.
type deviceLock struct {
	DeviceHash string `json:"device_hash"`
	MinerID    string `json:"miner_id"`
}

// GetDeviceHash generates a stable and unique hash for the current device.
// It does NOT collect or expose sensitive data — only OS, architecture, and home directory.
func GetDeviceHash() string {
	base := runtime.GOOS + "_" + runtime.GOARCH
	home, _ := os.UserHomeDir()
	base += "_" + home

	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

// IsDeviceLocked checks if this device is already linked to a miner account.
// Returns (true, minerID) if locked, or (false, "") otherwise.
func IsDeviceLocked() (bool, string) {
	path := getLockFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "" // no lock file found
	}

	var info deviceLock
	if err := json.Unmarshal(data, &info); err != nil {
		return false, ""
	}

	current := GetDeviceHash()
	if info.DeviceHash == current {
		return true, info.MinerID
	}
	return false, ""
}

// RegisterDeviceLock creates a new local lock after a successful account creation.
// Prevents multiple miner accounts from being created on the same device.
func RegisterDeviceLock(minerID string) error {
	path := getLockFilePath()
	locked, existingID := IsDeviceLocked()

	if locked {
		if existingID == minerID {
			// Same account — nothing to do
			return nil
		}
		return fmt.Errorf("this device is already linked to account %s", existingID)
	}

	lock := deviceLock{
		DeviceHash: GetDeviceHash(),
		MinerID:    minerID,
	}

	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// UnlockDevice manually removes the local lock file.
// This is reserved for developers or in case of local reset.
func UnlockDevice() error {
	path := getLockFilePath()
	return os.Remove(path)
}

// CanCreateNewAccount determines if a new miner account can be created on this device.
// It blocks new account creation if the device is already linked to another MinerID.
func CanCreateNewAccount() error {
	locked, minerID := IsDeviceLocked()
	if locked {
		return errors.New(fmt.Sprintf(
			"🚫 Creation denied: this device is already linked to account %s.\n"+
				"Use 'RestoreMinerAccount' to recover this account on another device.",
			minerID,
		))
	}
	return nil
}
