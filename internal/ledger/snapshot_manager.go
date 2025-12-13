// internal/ledger/snapshot_manager.go
// Package ledger provides a production-grade, automatic snapshot management system
// for the Explosive blockchain.
//
// SnapshotManager runs in the background and periodically creates verified,
// cryptographically secure snapshots of the entire ledger state.
// It ensures fast node bootstrapping, crash resilience, and storage efficiency.
//
// Features:
//   • Automatic snapshot creation at fixed intervals and on startup
//   • Intelligent deduplication (avoids creating snapshots too frequently)
//   • Retention policy with automatic rotation (keeps only the N most recent)
//   • Atomic, durable writes via Ledger.CreateSnapshot
//   • Zero external dependencies
//   • Graceful shutdown support

package ledger

import (
	"fmt"
	"log"
        "encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SnapshotManager is responsible for automatically creating and managing
// ledger snapshots in the background.
type SnapshotManager struct {
	ledger   *Ledger               // Reference to the active ledger instance
	dir      string                // Directory where snapshots are stored
	interval time.Duration         // How often to create periodic snapshots
	maxKeep  int                   // Maximum number of snapshots to retain
	stop     chan struct{}         // Signal channel for graceful shutdown
        stopOnce sync.Once
        wg       sync.WaitGroup        // Tracks the background goroutine
}

// snapshotMgr holds the background SnapshotManager instance responsible for
// periodic, automatic, cryptographically verified snapshot creation.
// It is started once at node boot and gracefully stopped on shutdown.
var snapshotMgr *SnapshotManager

// NewSnapshotManager creates a new SnapshotManager instance.
//
// Parameters:
//   l   - The active Ledger instance to snapshot
//   dir - Directory path where snapshots will be written (created if missing)
//
// The default configuration creates a snapshot:
//   • Immediately on startup
//   • Every 45 minutes thereafter
//   • Retains the 5 most recent snapshots
func NewSnapshotManager(l *Ledger, dir string) *SnapshotManager {
	// Ensure the snapshot directory exists
	_ = os.MkdirAll(dir, 0755)

	return &SnapshotManager{
		ledger:   l,
		dir:      dir,
		interval: 45 * time.Minute,
		maxKeep:  5,
		stop:     make(chan struct{}),
	}
}

// Start begins the background snapshot creation process.
//
// It creates an immediate snapshot on startup (unless a recent one exists),
// then continues creating periodic snapshots according to the configured interval.
//
// This method is non-blocking and returns immediately.
func (sm *SnapshotManager) Start() {
	sm.wg.Add(1)
	go func() {
		defer sm.wg.Done()

		// Create a snapshot immediately on node startup
		sm.createIfShould("startup")

		ticker := time.NewTicker(sm.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.createIfShould("periodic")
			case <-sm.stop:
				return
			}
		}
	}()
}

// createIfShould determines whether a new snapshot should be created
// and performs the creation if conditions are met.
//
// It prevents excessive snapshot creation by checking if a recent
// snapshot (less than 15 minutes old) already exists.
//
// Parameters:
//   reason - Human-readable context ("startup" or "periodic")
func (sm *SnapshotManager) createIfShould(reason string) {
	// Avoid creating multiple snapshots in quick succession
	if path, modTime := sm.latestSnapshot(); path != "" && time.Since(modTime) < 15*time.Minute {
		return
	}

	// Determine current chain tip for naming
	tip, _ := sm.ledger.GetChainTipHeight()

	// Use nanosecond timestamp to avoid collisions under high load
	filename := fmt.Sprintf("snapshot-%d-%d.slex", tip, time.Now().UnixNano())
	path := filepath.Join(sm.dir, filename)

	log.Printf("[snapshot] creating %s snapshot at height %d → %s", reason, tip, filepath.Base(path))

	start := time.Now()
	snap, err := sm.ledger.CreateSnapshot(path)
	if err != nil {
		log.Printf("[snapshot] creation failed: %v", err)
		return
	}

	elapsed := time.Since(start)
	sizeGB := float64(fileSize(snap.Path)) / (1024 * 1024 * 1024)

	log.Printf("[snapshot] created successfully in %v → %s (%.3f GB)",
		elapsed.Round(10*time.Millisecond),
		filepath.Base(snap.Path),
		sizeGB,
	)

	// Clean up old snapshots according to retention policy
	sm.rotate()
}

// latestSnapshot returns the path and modification time of the most recent snapshot.
// Returns empty string and zero time if no snapshots exist.
func (sm *SnapshotManager) latestSnapshot() (string, time.Time) {
	matches, err := filepath.Glob(filepath.Join(sm.dir, "*.slex"))
	if err != nil || len(matches) == 0 {
		return "", time.Time{}
	}

	// Sort by modification time (newest first)
	sort.Slice(matches, func(i, j int) bool {
		si, _ := os.Stat(matches[i])
		sj, _ := os.Stat(matches[j])
		return si.ModTime().After(sj.ModTime())
	})

	stat, _ := os.Stat(matches[0])
	return matches[0], stat.ModTime()
}

// rotate enforces the retention policy by deleting the oldest snapshots
// once the maximum number (maxKeep) is exceeded.
func (sm *SnapshotManager) rotate() {
	matches, err := filepath.Glob(filepath.Join(sm.dir, "*.slex"))
	if err != nil || len(matches) <= sm.maxKeep {
		return
	}

	// Sort by modification time (newest first)
	sort.Slice(matches, func(i, j int) bool {
		si, _ := os.Stat(matches[i])
		sj, _ := os.Stat(matches[j])
		return si.ModTime().After(sj.ModTime())
	})

	// Remove excess snapshots (oldest ones)
	for i := sm.maxKeep; i < len(matches); i++ {
		log.Printf("[snapshot] removing old snapshot: %s", filepath.Base(matches[i]))
		_ = os.Remove(matches[i])
	}
}

// Stop gracefully terminates the background snapshot goroutine.
func (sm *SnapshotManager) Stop() {
    sm.stopOnce.Do(func() {
        close(sm.stop)
    })
    sm.wg.Wait()
}

// fileSize returns the size of a file in bytes.
// Returns 0 on error (e.g. file not found).
func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// ====================================================================
// SNAPSHOT: NetworkID Initialization, Auto-Restore, and Background Manager
// ====================================================================

// initNetworkID derives and sets the global CurrentNetworkID from the genesis block hash.
//
// This 256-bit identifier is cryptographically bound to the chain's origin and is
// mandatory for all v3+ snapshot operations. It prevents accidental or malicious
// restoration of a snapshot from a different network (mainnet/testnet/devnet).
// Must be called after the genesis block is guaranteed to exist.
// initNetworkID derives and sets the global CurrentNetworkID from the genesis block hash.
//
// Uses GetBlockByHeight(0) instead of nonexistent GetBlock()
func InitNetworkID(db *Ledger) error {
    genesis, err := db.GetBlockByHeight(0)
    if err != nil {
        return fmt.Errorf("genesis block not found: %w", err)
    }
    if genesis == nil {
        return fmt.Errorf("genesis block is nil")
    }

    hash := genesis.BlockHash
    if len(hash) != 64 { // Expecting a 256-bit hash in hex
        return fmt.Errorf("invalid genesis hash length: %s", hash)
    }

    decoded, err := hex.DecodeString(hash)
    if err != nil {
        return fmt.Errorf("failed to decode genesis hash: %v", err)
    }

    copy(CurrentNetworkID[:], decoded[:32])
    log.Printf("NetworkID initialized from genesis: %x", CurrentNetworkID)
    return nil
}

// autoRestoreLatestSnapshot automatically restores the most recent valid snapshot
// on node startup, if one exists in the configured snapshot directory.
//
// This enables sub-minute bootstrapping even on mobile devices with multi-gigabyte
// ledgers. Snapshots are selected by modification time (newest first).
// On failure, the node terminates — a corrupted snapshot must never be partially applied.
func AutoRestoreLatestSnapshot(db *Ledger, snapshotDir string) bool {
	matches, err := filepath.Glob(filepath.Join(snapshotDir, "*.slex"))
	if err != nil || len(matches) == 0 {
		log.Println("No snapshot found → starting from genesis")
		return false
	}

	sort.Slice(matches, func(i, j int) bool {
		si, _ := os.Stat(matches[i])
		sj, _ := os.Stat(matches[j])
		return si.ModTime().After(sj.ModTime())
	})

	latest := matches[0]
	log.Printf("Found latest snapshot: %s → restoring...", filepath.Base(latest))

	start := time.Now()
	if err := db.RestoreSnapshot(latest); err != nil {
		log.Fatalf("FATAL: Failed to restore snapshot: %v", err)
	}

	height, _ := db.GetChainTipHeight()
	log.Printf("Snapshot restored successfully in %v → height = %d",
		time.Since(start).Round(10*time.Millisecond), height)
	return true
}

