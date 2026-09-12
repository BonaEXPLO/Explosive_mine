// cmd/exploscan/main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"explosive/internal/ledger"
	"explosive/internal/scan"
)

func main() {
	// -------------------------------------------------------------------------
	// 1. Detect the home directory to locate the ledger DB
	// -------------------------------------------------------------------------
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("❌ Cannot detect home directory:", err)
		return
	}

	dbPath := filepath.Join(homeDir, ".explosive", "ledger")

	// -------------------------------------------------------------------------
	// 2. Open the ledger database
	// -------------------------------------------------------------------------
	l, err := ledger.OpenLedger(dbPath)
	if err != nil {
		fmt.Println("❌ Failed to open ledger DB:", err)
		return
	}
	defer l.Close()

	fmt.Println("🚀 Ledger opened successfully. Starting Exploscan...")

	// -------------------------------------------------------------------------
	// 3. Create a channel to stop the scanner gracefully
	// -------------------------------------------------------------------------
	stopCh := make(chan struct{})

	// -------------------------------------------------------------------------
	// 4. Start Exploscan
	//
	// StartExploscan now expects:
	//   - the ledger
	//   - a Broadcaster
	//   - a stop channel
	//
	// This standalone Exploscan process has no network broadcaster,
	// so nil is intentionally passed here.
	// -------------------------------------------------------------------------
	scan.StartExploscan(l, nil, stopCh)

	// -------------------------------------------------------------------------
	// 5. Capture Ctrl+C / termination signal
	// -------------------------------------------------------------------------
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	<-sigs

	fmt.Println("\n🛑 Ctrl+C received, stopping Exploscan...")

	// Signal the scanner goroutine to stop.
	close(stopCh)

	// Give the scanner a short moment to exit cleanly.
	time.Sleep(500 * time.Millisecond)

	fmt.Println("✅ Exploscan stopped. Goodbye!")
}
