// cmd/explosiveapi/main.go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "explosive/internal/api"
    "explosive/internal/ledger"
)

func main() {
    // Path to ledger DB
    dbPath := filepath.Join(".", "ledgerdb")

    // Open Ledger (BadgerDB backend)
    l, err := ledger.OpenLedger(dbPath)
    if err != nil {
        log.Fatalf("❌ Failed to open ledger: %v", err)
    }
    defer l.Close()

    // Create LedgerServiceImpl
    ledgerService := api.NewLedgerServiceImpl(l, nil)

    // Create API
    explosiveAPI := api.NewExplosiveAPI(ledgerService)

    // Port
    port := os.Getenv("EXPLOSIVE_API_PORT")
    if port == "" {
        port = "8080"
    }
    fmt.Printf("🚀 EXPLOSIVE Mainnet API listening on port %s\n", port)

    // Start server
    if err := explosiveAPI.Router.Run(":" + port); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
