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
	// 1️⃣ Detect the home directory to locate the ledger DB
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("❌ Cannot detect home directory:", err)
		return
	}
	dbPath := filepath.Join(homeDir, ".explosive", "ledger")

	// 2️⃣ Open the ledger database
	l, err := ledger.OpenLedger(dbPath)
	if err != nil {
		fmt.Println("❌ Failed to open ledger DB:", err)
		return
	}
	defer l.Close()

	fmt.Println("🚀 Ledger opened successfully. Starting Exploscan...")

	// 3️⃣ Create a channel to stop the scanner gracefully
	stopCh := make(chan struct{})

	// 4️⃣ Start Exploscan in a separate goroutine
	scan.StartExploscan(l, stopCh)

	// 5️⃣ Capture Ctrl+C or termination signal to stop the scanner properly
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs // wait for signal
	fmt.Println("\n🛑 Ctrl+C received, stopping Exploscan...")

	close(stopCh)                      // signal the scanner to stop
	time.Sleep(500 * time.Millisecond) // small delay to let goroutine finish
	fmt.Println("✅ Exploscan stopped. Goodbye!")
}
