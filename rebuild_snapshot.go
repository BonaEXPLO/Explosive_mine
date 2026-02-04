// rebuild_snapshot.go
package main

import (
    "fmt"
    "log"
    "os"
    "time"

    "explosive/internal/ledger"

    "github.com/dgraph-io/badger/v4"
    "github.com/fxamacker/cbor/v2"
)

func main() {
    dbPath := "./ledger" // chemin vers votre DB Badger
    snapshotFile := fmt.Sprintf("snapshot-rebuilt-%d.slex", time.Now().UnixNano())

    opts := badger.DefaultOptions(dbPath).WithLogger(nil)
    db, err := badger.Open(opts)
    if err != nil {
        log.Fatalf("❌ Failed to open ledger DB: %v", err)
    }
    defer db.Close()

    fmt.Println("📦 Reading blocks from ledger...")

    var blocks []*ledger.Block

    err = db.View(func(txn *badger.Txn) error {
        it := txn.NewIterator(badger.DefaultIteratorOptions)
        defer it.Close()

        prefix := []byte("block:")
        for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
            item := it.Item()
            val, err := item.ValueCopy(nil)
            if err != nil {
                return err
            }

            var blk ledger.Block
            if err := cbor.Unmarshal(val, &blk); err != nil {
                return fmt.Errorf("failed to decode block %s: %w", item.Key(), err)
            }

            blocks = append(blocks, &blk)
        }
        return nil
    })

    if err != nil {
        log.Fatalf("❌ Error reading blocks: %v", err)
    }

    fmt.Printf("✅ Found %d blocks\n", len(blocks))

    // Écriture du snapshot
    f, err := os.Create(snapshotFile)
    if err != nil {
        log.Fatalf("❌ Failed to create snapshot file: %v", err)
    }
    defer f.Close()

    // Utiliser votre helper snapshot du ledger
    if err := ledger.WriteSnapshot(f, blocks); err != nil {
        log.Fatalf("❌ Failed to write snapshot: %v", err)
    }

    fmt.Printf("✅ Snapshot rebuilt successfully: %s\n", snapshotFile)
}
