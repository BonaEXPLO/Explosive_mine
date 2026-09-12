package ledger

import (
    "encoding/hex"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "sort"
    "sync"
    "time"
)

// SnapshotManager handles periodic V5 ledger snapshots safely
type SnapshotManager struct {
    ledger   *Ledger
    dir      string
    interval time.Duration
    maxKeep  int
    stop     chan struct{}
    stopOnce sync.Once
    wg       sync.WaitGroup
    mu       sync.Mutex // protects snapshot creation
}

var snapshotMgr *SnapshotManager

// NewSnapshotManager creates a new V5 snapshot manager
func NewSnapshotManager(l *Ledger, dir string) *SnapshotManager {
    if err := os.MkdirAll(dir, 0o750); err != nil {
        log.Fatalf("Failed to create snapshot directory: %v", err)
    }
    return &SnapshotManager{
        ledger:   l,
        dir:      dir,
        interval: 45 * time.Minute,
        maxKeep:  5,
        stop:     make(chan struct{}),
    }
}

// Start begins the background snapshot routine (non-blocking)
func (sm *SnapshotManager) Start() {
    sm.wg.Add(1)
    go func() {
        defer sm.wg.Done()
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

// createIfShould creates a snapshot if none exists in the last 15 minutes
func (sm *SnapshotManager) createIfShould(reason string) {
    sm.mu.Lock()
    defer sm.mu.Unlock()

    if path, modTime := sm.latestSnapshot(); path != "" && time.Since(modTime) < 15*time.Minute {
        return
    }

    tip, _ := sm.ledger.GetChainTipHeight()
    filename := fmt.Sprintf("snapshot-%d-%d.slex", tip, time.Now().UnixNano())
    path := filepath.Join(sm.dir, filename)

    log.Printf("[snapshot] creating %s snapshot at height %d → %s", reason, tip, filepath.Base(path))

    const maxRetries = 3
    var snap *Snapshot
    var err error
    for attempt := 1; attempt <= maxRetries; attempt++ {
        snap, err = sm.ledger.CreateSnapshot(path)
        if err == nil {
            break
        }
        log.Printf("[snapshot] attempt %d failed: %v", attempt, err)
        time.Sleep(time.Duration(attempt) * 2 * time.Second)
    }
    if err != nil {
        log.Printf("[snapshot] creation failed after %d attempts: %v", maxRetries, err)
        return
    }

    elapsed := time.Since(time.Now().Add(-sm.interval))
    sizeGB := float64(fileSize(snap.Path)) / (1024 * 1024 * 1024)
    log.Printf("[snapshot] created successfully in %v → %s (%.3f GB)",
        elapsed.Round(10*time.Millisecond),
        filepath.Base(snap.Path),
        sizeGB,
    )

    sm.rotate()
}

// latestSnapshot returns the newest snapshot path and modTime
func (sm *SnapshotManager) latestSnapshot() (string, time.Time) {
    matches, err := filepath.Glob(filepath.Join(sm.dir, "*.slex"))
    if err != nil || len(matches) == 0 {
        return "", time.Time{}
    }

    sort.Slice(matches, func(i, j int) bool {
        si, _ := os.Stat(matches[i])
        sj, _ := os.Stat(matches[j])
        return si.ModTime().After(sj.ModTime())
    })

    stat, _ := os.Stat(matches[0])
    return matches[0], stat.ModTime()
}

// rotate enforces retention policy by deleting old snapshots
func (sm *SnapshotManager) rotate() {
    matches, err := filepath.Glob(filepath.Join(sm.dir, "*.slex"))
    if err != nil || len(matches) <= sm.maxKeep {
        return
    }

    sort.Slice(matches, func(i, j int) bool {
        si, _ := os.Stat(matches[i])
        sj, _ := os.Stat(matches[j])
        return si.ModTime().After(sj.ModTime())
    })

    for i := sm.maxKeep; i < len(matches); i++ {
        log.Printf("[snapshot] removing old snapshot: %s", filepath.Base(matches[i]))
        _ = os.Remove(matches[i])
    }
}

// Stop gracefully terminates the background snapshot goroutine
func (sm *SnapshotManager) Stop() {
    sm.stopOnce.Do(func() { close(sm.stop) })
    sm.wg.Wait()
}

// fileSize returns the size of a file in bytes
func fileSize(path string) int64 {
    info, err := os.Stat(path)
    if err != nil {
        return 0
    }
    return info.Size()
}

// InitNetworkID sets CurrentNetworkID from genesis block
func InitNetworkID(db *Ledger) error {
    genesis, err := db.GetBlockByHeight(0)
    if err != nil || genesis == nil {
        return fmt.Errorf("genesis block not found or nil")
    }
    hash := genesis.BlockHash
    if len(hash) != 64 {
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

// AutoRestoreLatestSnapshot restores the newest snapshot if available
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
