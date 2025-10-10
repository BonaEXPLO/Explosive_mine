// ~/explosive/internal/sync/sync.go
//
// Package sync provides independent functions to synchronize a wallet's local ledger
// with the network via a P2P node or other sources. This package is designed to
// remain independent to avoid import cycles between ledger and p2p.

package sync

import (
    "fmt"
    "log"

    "explosive/internal/ledger" // Import only the Ledger type, no Node from p2p
)

// SyncWalletLedger fetches all new blocks from an external source (e.g., a P2P node)
// and updates the local wallet ledger. Only blocks with a height higher than the
// current local ledger are added.
//
// Parameters:
//   - fetchBlocks: function that returns the latest blocks from the network
//   - localLedger: pointer to the wallet's local ledger to be updated
//
// Returns an error if fetching blocks fails.
func SyncWalletLedger(fetchBlocks func() ([]*ledger.Block, error), localLedger *ledger.Ledger) error {
    // Fetch new blocks from the network
    newBlocks, err := fetchBlocks()
    if err != nil {
        return fmt.Errorf("failed to fetch blocks: %w", err)
    }

    addedCount := 0
    for _, blk := range newBlocks {
        err := localLedger.AddBlock(blk)
        if err != nil {
            log.Printf("⚠️ Block rejected: %v", err)
            continue
        }
        addedCount++
    }

    log.Printf("✅ Wallet ledger synchronized with network, %d blocks added", addedCount)
    return nil
}
