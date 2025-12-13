// cmd/ledgerapp/main.go
package main

import (
	"bufio"
	"fmt"
        "flag"
        "os/signal"
        "syscall"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
        "explosive/internal/imanifund"
        "github.com/fxamacker/cbor/v2"

	"explosive/internal/guardian"
	"explosive/internal/halving"
	"explosive/internal/ledger"
	"explosive/internal/p2p"
	"explosive/internal/scan"
	"explosive/internal/wallet"
)

// Toggle password masking (false = clear text, true = hidden)
var hidePassword = false

// start node, attach ledger, set up handlers, start Exploscan and request initial sync
func startP2PNodeForMiner(listenAddr string, db *ledger.Ledger, minerID string) (*p2p.Node, chan struct{}, error) {
    node := p2p.NewNode(listenAddr, "explosive-mainnet", "ledger-client")
    node.Ledger = db

    // Register custom message handler (replaces old OnMessage)
p2p.RegisterCustomHandler(func(peer *p2p.Peer, payload []byte) {
    var msg struct {
        Type string `cbor:"type"`
    }
    if err := cbor.Unmarshal(payload, &msg); err != nil {
        return
    }

    switch msg.Type {
    case "BALANCE_UPDATE":
        var bal struct {
            Addr   string  `cbor:"addr"`
            Exp    float64 `cbor:"exp"`
            Imani  float64 `cbor:"imani"`
        }
        if err := cbor.Unmarshal(payload, &bal); err == nil {
            fmt.Printf("Balance update for %s: %.4f EXPLO / %.4f IMANI\n", bal.Addr, bal.Exp, bal.Imani)
        }
    case "LEDGER_SYNC":
        var sync struct {
            Data []wallet.Transaction `cbor:"data"`
        }
        if err := cbor.Unmarshal(payload, &sync); err == nil {
            fmt.Printf("LEDGER_SYNC received: %d transactions\n", len(sync.Data))
            for _, tx := range sync.Data {
                _ = wallet.SaveTransaction(nil, tx)
            }
        }
    }
})

    // Start node
    if err := node.Start(); err != nil {
        return nil, nil, fmt.Errorf("failed to start P2P node: %w", err)
    }

    // 🔹 Bootstrap peers (connect + LightSync + AutoRegisterLocalMiners)
    go node.Bootstrap()

    // Attach node to wallet package so wallet functions can broadcast if needed
    wallet.SetActiveNode(node)
    // Start Exploscan (gathers and broadcasts metrics periodically)
    stopScan := make(chan struct{})
    go scan.StartExploscan(db, node, stopScan)

    // Small initial request for blocks / sync
go func() {
    time.Sleep(800 * time.Millisecond)
    fmt.Println("📡 Requesting initial ledger sync from peers...")

    blocks, err := node.FetchBlocks()
    if err != nil {
        fmt.Printf("⚠️ Initial FetchBlocks failed: %v\n", err)
        return
    }

    for _, blk := range blocks {
        if err := db.ApplyBlock(blk); err != nil {
            fmt.Printf("⚠️ Failed to apply block %d: %v\n", blk.Header.Height, err)
        } else {
            fmt.Printf("✅ Applied block %d\n", blk.Header.Height)
        }
    }

    fmt.Println("📡 Initial ledger sync completed.")
}()

    return node, stopScan, nil
}

func main() {
    // ----- Flags -----
    // Define command-line flags for configuring node behavior
    flagPort := flag.Int("port", 8443, "Port to listen on for P2P")
    flagP2P := flag.Bool("p2p", false, "Enable P2P networking")
    flagSeed := flag.Bool("seed", false, "Run seed initialization (create genesis etc.)")
    flagHeadless := flag.Bool("headless", false, "Run node without CLI interface (no interactive menu)")
    flagNode := flag.Bool("node", false, "Alias for --headless")
    flag.Parse()

    // ----- Setup paths -----
    // Determine user home directory and set paths for ledger DB and snapshot storage
    homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatal("❌ Cannot detect home directory:", err)
    }
    dbPath := filepath.Join(homeDir, ".explosive", "ledger")
    snapshotDir := filepath.Join(homeDir, ".explosive", "snapshots")

    // ----- Open Ledger DB -----
    // Initialize or open the local ledger database
    db, err := ledger.OpenLedger(dbPath)
if err != nil {
    log.Fatal("❌ Failed to open ledger DB:", err)
}
defer db.Close()

// ===== 2. Initialize IMANI Fund =====
if err := imanifund.Init(func(minerID string, amount float64) error {
    return ledger.CreditSoul(db, minerID, amount)
}); err != nil {
    log.Fatal("❌ Failed to initialize IMANI Fund:", err)
}

// ===== 3. Initialize NetworkID, snapshots, etc. =====

    // ===== 1. Genesis =====
    // Create the genesis block if running with the --seed flag, otherwise ensure it exists
    if *flagSeed {
        genesis, err := ledger.CreateGenesisBlock(db)
        if err != nil {
            log.Fatal("❌ Failed to initialize Genesis block:", err)
        }
        if genesis != nil {
            fmt.Printf("⚡ Genesis block created: %d EXPLO locked forever\n", ledger.GenesisEXPLO)
        } else {
            fmt.Println("⚡ Genesis block already exists.")
        }
    } else {
        if _, err := ledger.CreateGenesisBlock(db); err != nil {
            log.Fatal("❌ Failed to ensure Genesis block:", err)
        }
    }

    // ===== 2. Initialize NetworkID =====
    // Ensure a unique NetworkID derived from the genesis block for snapshot consistency
    if err := ledger.InitNetworkID(db); err != nil {
        log.Fatal("❌ Failed to initialize NetworkID:", err)
    }

    // ===== 3. Auto-restore the latest snapshot =====
    // Attempt to restore the most recent snapshot for faster startup
    if !ledger.AutoRestoreLatestSnapshot(db, snapshotDir) {
        log.Println("⚠️ No snapshot restored → starting from genesis")
    }

    // ===== 4. Start SnapshotManager =====
    // Start background snapshot manager to periodically create verified snapshots
    snapshotMgr := ledger.NewSnapshotManager(db, snapshotDir)
    snapshotMgr.Start()
    defer snapshotMgr.Stop()

    // ----- Optional dump for monitoring -----
    // Output ledger state for debugging or inspection purposes
    if err := db.DumpLedger(); err != nil {
        fmt.Printf("⚠️ DumpLedger failed (continuing): %v\n", err)
    }

    // ----- Node & CLI setup -----
    var currentMiner *ledger.Miner
    var node *p2p.Node
    var scanStop chan struct{}

    // ----- Headless / node mode -----
    // If running in headless mode, start P2P node if requested and wait for shutdown signals
    if *flagHeadless || *flagNode {
        if *flagP2P {
            listen := fmt.Sprintf(":%d", *flagPort)
            fmt.Printf("🚀 Starting EXPLOSIVE P2P Node (HEADLESS) on %s ...\n", listen)
            n, stop, err := startP2PNodeForMiner(listen, db, "")
            if err != nil {
                log.Fatalf("❌ Failed to start P2P node: %v", err)
            }
            node = n
            scanStop = stop
            fmt.Printf("📡 P2P node started on %s\n", listen)
        } else {
            fmt.Println("⚠️ Running in headless mode without --p2P: no network started.")
        }

        // Wait for termination signals (SIGINT / SIGTERM) to gracefully shutdown
        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
        <-sig
        fmt.Println("\n🛑 Shutdown signal received, stopping node...")

        if scanStop != nil {
            close(scanStop)
        }
        if node != nil {
            node.Stop()
        }
        fmt.Println("✅ Node stopped, exiting.")
        return
    }

    // ----- Interactive CLI -----
    // Start the command-line interface for miner operations
    fmt.Println("💎 Welcome to EXPLOSIVE Ledger App (merged P2P)!")
    scanner := bufio.NewScanner(os.Stdin)

mainLoop:
    for {
        // Display menu options for miner actions
        fmt.Println("\nSelect an option:")
        fmt.Println("1️⃣  Create miner account")
        fmt.Println("2️⃣  Restore miner account")
        fmt.Println("3️⃣  Mine EXPLO / IMANI")
        fmt.Println("4️⃣  Change password")
        fmt.Println("5️⃣  Delete account")
        fmt.Println("6️⃣  Exit")
        fmt.Println("7️⃣  Sync with network")
        fmt.Println("8️⃣  View synchronized network metrics")
        fmt.Println("9️⃣  Export Miner Backup")
        fmt.Println("🔟 Restore Miner Backup")
        fmt.Print("> ")

        if !scanner.Scan() {
            break
        }
        choice := strings.TrimSpace(scanner.Text())

        switch choice {
    case "1":
        // Create a new miner account and optionally start P2P node
        miner := handleCreateMiner(db, scanner, node)
        if miner != nil {
            currentMiner = miner
            if node == nil {
                listenAddr, err := p2p.DeriveListenAddr(currentMiner.ID, currentMiner.ConsciousnessFingerprint, "")
                if err != nil {
                    log.Fatal("❌ Cannot derive listen address:", err)
                }
                n, stop, err := startP2PNodeForMiner(listenAddr, db, currentMiner.ID)
                if err != nil {
                    log.Fatalf("❌ Failed to start P2P node: %v", err)
                }
                node = n
                scanStop = stop
                fmt.Printf("📡 P2P node started on %s\n", listenAddr)

                if md, err := scan.GatherMetrics(db); err == nil && md != nil {
metrics := p2p.MetricsData{
    Timestamp:       md.Timestamp,
    MaxSupply:       md.MaxSupply,
    Circulating:     md.Circulating,
    TotalHolders:    md.TotalHolders,
    MinersCount:     md.MinersCount,
    MinersRemaining: md.MinersRemaining,
}
node.UpdateGlobalMetrics(metrics)
fmt.Println("📊 Global metrics initialized from ledger.")
                }
            }
            // Start background network synchronization
            go SyncWithNetwork(node, db)
        }
    case "2":
        // Restore existing miner account and optionally start P2P node
        miner := handleRestoreMiner(db, scanner)
        if miner != nil {
            currentMiner = miner
            if node == nil {
                listenAddr, err := p2p.DeriveListenAddr(currentMiner.ID, currentMiner.ConsciousnessFingerprint, "")
                if err != nil {
                    log.Fatal("❌ Cannot derive listen address:", err)
                }
                n, stop, err := startP2PNodeForMiner(listenAddr, db, currentMiner.ID)
                if err != nil {
                    log.Fatalf("❌ Failed to start P2P node: %v", err)
                }
                node = n
                scanStop = stop
                fmt.Printf("📡 P2P node started on %s\n", listenAddr)

                if md, err := scan.GatherMetrics(db); err == nil && md != nil {
metrics := p2p.MetricsData{
    Timestamp:       md.Timestamp,
    MaxSupply:       md.MaxSupply,
    Circulating:     md.Circulating,
    TotalHolders:    md.TotalHolders,
    MinersCount:     md.MinersCount,
    MinersRemaining: md.MinersRemaining,
}
node.UpdateGlobalMetrics(metrics)
fmt.Println("📊 Global metrics initialized from ledger.")
                }
            }
            go SyncWithNetwork(node, db)
        }
    case "3":
        // Perform mining operation for the current miner
        if currentMiner == nil {
            fmt.Println("❌ You must create or restore a miner account first.")
            continue
        }
        if node == nil {
            listenAddr, err := p2p.DeriveListenAddr(currentMiner.ID, currentMiner.ConsciousnessFingerprint, "")
            if err != nil {
                log.Fatal("❌ Cannot derive listen address:", err)
            }
            n, stop, err := startP2PNodeForMiner(listenAddr, db, currentMiner.ID)
            if err != nil {
                log.Fatalf("❌ Failed to start P2P node: %v", err)
            }
            node = n
            scanStop = stop
            fmt.Printf("📡 P2P node started on %s\n", listenAddr)
        }
        handleMine(db, scanner, currentMiner, node)
    case "4":
        // Change password for the current miner
        if currentMiner == nil {
            fmt.Println("❌ You must create or restore a miner account first.")
        } else {
            handleChangePassword(db, scanner, currentMiner)
        }
    case "5":
        // Delete the current miner account and stop P2P node if running
        if currentMiner == nil {
            fmt.Println("❌ You must create or restore a miner account first.")
        } else {
            if handleDeleteMiner(db, scanner, currentMiner) {
                currentMiner = nil
                if node != nil {
                    if scanStop != nil {
                        close(scanStop)
                        scanStop = nil
                    }
                    node.Stop()
                    node = nil
                }
            }
        }
    case "6":
        // Exit the CLI and shutdown all services
        fmt.Println("👋 Goodbye!")
        if scanStop != nil {
            close(scanStop)
        }
        if node != nil {
            node.Stop()
        }
        break mainLoop
    case "7":
        // Manually synchronize local ledger with the network
        fmt.Println("📡 Synchronizing ledger with network...")
        if node == nil {
            fmt.Println("❌ No P2P node running. Create or restore a miner first.")
            continue
        }
        SyncWithNetwork(node, db)
    case "8":
        // Display live network metrics for monitoring
        if node == nil {
            fmt.Println("❌ You must create or restore a miner account first.")
            continue
        }
        fmt.Println("📊 Live Exploscan metrics (type 'Stop' to exit)\n")
        p2p.ShowLiveMetrics(node)
    case "9": {
    if currentMiner == nil {
        fmt.Println("❌ You must create or restore a miner account first.")
        continue
    }

    fmt.Print("Enter optional password to encrypt backup (leave empty for passwordless): ")
    pw := readPassword(scanner, "")

    path := fmt.Sprintf("%s_backup.dat", currentMiner.ID)

    if err := ledger.ExportMinerBackup(currentMiner, pw, path); err != nil {
        fmt.Println("❌ Failed to export backup:", err)
    } else {
        fmt.Println("✅ Backup exported to:", path)
    }
}
    case "10": {
    fmt.Print("Enter path to backup file: ")
    scanner.Scan()
    path := strings.TrimSpace(scanner.Text())

    fmt.Print("Enter password used for backup (leave empty if none): ")
    pw := readPassword(scanner, "")

    restoredMiner, err := ledger.RestoreMinerBackup(pw, path)
    if err != nil {
        fmt.Println("❌ Failed to restore backup:", err)
    } else {
        fmt.Println("✅ Miner restored successfully:", restoredMiner.ID)

        if db != nil {
            key := []byte("miner:" + restoredMiner.ID)
            _ = db.PutObject(key, restoredMiner)
        }

        currentMiner = restoredMiner
    }
}
    default:
        fmt.Println("❌ Invalid option, try again.")
    }
}

fmt.Println("🛑 Exiting ledger app.")

// ----- Graceful shutdown of snapshot manager -----
if snapshotMgr != nil {
    snapshotMgr.Stop()
}

// ----- Close remaining resources -----
if scanStop != nil {
    close(scanStop)
}
if node != nil {
    node.Stop()
}
}

func handleCreateMiner(db *ledger.Ledger, scanner *bufio.Scanner, node *p2p.Node) *ledger.Miner {
    fmt.Println("\n🆕 Create Miner Account")

    // --- 1️⃣ Formulaire d'identité ---
    rawID := readInput(scanner, "Enter miner ID (ex: explo + 40 hex + 8 checksum, total 53 chars): ")
    id := strings.ToLower(strings.TrimSpace(rawID))
    id = strings.ReplaceAll(id, "\n", "")
    id = strings.ReplaceAll(id, "\r", "")

    if !ledger.IsValidMinerID(id) {
        fmt.Println("❌ Invalid miner ID.")
        return nil
    }

    var existing ledger.Miner
    if err := db.GetObject([]byte("miner:"+id), &existing); err == nil {
        fmt.Println("❌ Miner ID already exists.")
        return nil
    }

    // --- 2️⃣ Mot de passe ---
    password := readPassword(scanner, "Create a strong password: ")
    confirm := readPassword(scanner, "Confirm password: ")
    if password != confirm {
        fmt.Println("❌ Passwords do not match.")
        return nil
    }

    // --- 3️⃣ Empreinte spirituelle (4 mots) ---
    fmt.Println("💡 Enter your 4 sacred words:")
    words := make([]string, 4)
    for i := 0; i < 4; i++ {
        for {
            word := strings.TrimSpace(readInput(scanner, fmt.Sprintf("Word #%d: ", i+1)))
            if !ledger.IsValidSacredWordFormat(word) {
                fmt.Println("⚠️ Invalid format.")
                continue
            }
            words[i] = word
            break
        }
    }

    dup, err := guardian.IsDuplicateFingerprint(words)
    if err != nil {
        fmt.Println("❌ Failed to check fingerprint:", err)
        return nil
    }
    if dup {
        fmt.Println("❌ Sacred words already used.")
        return nil
    }

    // --- 4️⃣ Création du compte mineur ---
    miner, msg, err := ledger.CreateMiner(id, password, words, "", db) // pas d’IP
    if err != nil {
        fmt.Println("❌ Error creating miner:", err)
        return nil
    }

    // --- 5️⃣ Sauvegarde ---
    if err := db.PutObject([]byte("miner:"+id), miner); err != nil {
        fmt.Println("❌ Failed to save miner:", err)
        return nil
    }

    // --- 6️⃣ Message final ---
    fmt.Println("✅ Miner account created successfully!")
    fmt.Println("💬 Guardian says:", msg)

    return miner
}

func handleRestoreMiner(db *ledger.Ledger, scanner *bufio.Scanner) *ledger.Miner {
    fmt.Println("\n♻️ Restore Miner Account")
    id := readInput(scanner, "Enter miner ID (ex: explo + 40 hex + 8 checksum, total 53 chars): ")

    var stored ledger.Miner
    err := db.GetObject([]byte("miner:"+id), &stored)
    if err != nil {
        fmt.Println("❌ Miner not found:", err)
        return nil
    }

    fmt.Println("Enter your 4 sacred words in order:")
    words := make([]string, 4)
    for i := 0; i < 4; i++ {
        for {
            word := strings.TrimSpace(readInput(scanner, fmt.Sprintf("Word #%d: ", i+1)))
            if !ledger.IsValidSacredWordFormat(word) {
                fmt.Println("⚠️ Invalid format. Must start with uppercase, ≥4 chars, letters and '-' allowed.")
                continue
            }
            words[i] = word
            break
        }
    }

    newPass := readPassword(scanner, "Enter a new password for restoration: ")

    miner, msg, err := ledger.RestoreMiner(id, words, newPass, db)
    if err != nil {
        fmt.Println("❌ Failed to restore miner:", err)
        return nil
    }

    err = db.PutObject([]byte("miner:"+id), miner)
    if err != nil {
        fmt.Println("❌ Failed to save restored miner:", err)
        return nil
    }

    fmt.Println("✅ Miner restored successfully:", miner.ID)
    fmt.Println("💬 Guardian says:", msg)
    return miner
}

func handleMine(db *ledger.Ledger, scanner *bufio.Scanner, miner *ledger.Miner, node *p2p.Node) {
    fmt.Println("\n⛏️ Mine EXPLO / IMANI")

    stateKey := []byte("state:" + miner.ID)
    state := &ledger.MinerState{}
    if err := db.GetObject(stateKey, state); err != nil || state == nil {
        state = &ledger.MinerState{}
    }
    prevIMANI := state.IMANI

    balanceKey := []byte("balance:" + miner.ID)
    balance := &ledger.Balance{}
    if err := db.GetObject(balanceKey, balance); err != nil || balance == nil {
        balance = &ledger.Balance{}
    }

    var donation float64
    for {
        input := readInput(scanner, "Donation percent (0.0 - 0.1)? Enter 0 for none: ")
        d, err := strconv.ParseFloat(strings.TrimSpace(input), 64)
        if err != nil {
            fmt.Println("⚠️ Invalid number format.")
            continue
        }
        if d < 0.0 || d > 0.1 {
            fmt.Println("⚠️ Must be between 0.0 and 0.1")
            continue
        }
        donation = d
        break
    }

    if err := ledger.Mine(db, miner, state, donation); err != nil {
        fmt.Println("❌ Mining failed:", err)
        return
    }

    exploReward, err := halving.GetCurrentReward(db.GetDB())
    if err != nil {
        fmt.Println("❌ Failed to get reward:", err)
        return
    }

    donationAmount := exploReward * donation
    netReward := exploReward - donationAmount

    balance.EXPLO += netReward
    deltaIMANI := state.IMANI - prevIMANI
    if deltaIMANI > 0 {
        balance.IMANI += deltaIMANI
    }

    if err := db.PutObject(balanceKey, balance); err != nil {
        fmt.Println("⚠️ Failed to save wallet balance:", err)
    }
    if err := db.PutObject(stateKey, state); err != nil {
        fmt.Println("⚠️ Failed to save miner state:", err)
    }

    if donationAmount > 0 {
        if err := ledger.CreditDonpool(db, donationAmount); err != nil {
            fmt.Println("⚠️ Failed to credit donpool:", err)
        }
    }

    fmt.Println("✅ Mining session complete!")
    fmt.Printf("💰 Wallet balance: %.3f EXPLO, %.2f IMANI\n", balance.EXPLO, balance.IMANI)
    fmt.Printf("🌟 LUMEN: %.2f / %.2f\n", state.LUMEN, ledger.MaxLumen)
    fmt.Printf("💸 Donation: %.3f EXPLO contributed\n", donationAmount)

    // 🔄 Broadcast last block
    lastBlock, err := db.GetLatestBlock()
    if err != nil {
        fmt.Println("⚠️ Failed to fetch last block:", err)
    } else if lastBlock != nil && node != nil {
        env, err := p2p.NewEnvelopeFromPayload(node.ProtocolVersion(), p2p.MsgTypeBlock, lastBlock)
        if err == nil {
            node.Broadcast(env)
            fmt.Println("📡 New block broadcasted to network peers!")
        } else {
            fmt.Println("⚠️ Failed to create block envelope:", err)
        }
    }

    // ⚡ Update global metrics after mining
    if node != nil {
        md, err := scan.GatherMetrics(db)
        if err != nil {
            fmt.Println("⚠️ Failed to gather metrics after mining:", err)
        } else {
            // Conversion scan.MetricsData -> p2p.MetricsData
            pm := p2p.MetricsData{
                Timestamp:       md.Timestamp,
                MaxSupply:       md.MaxSupply,
                Circulating:     md.Circulating,
                TotalHolders:    md.TotalHolders,
                MinersCount:     md.MinersCount,
                MinersRemaining: md.MinersRemaining,
            }
            node.UpdateGlobalMetrics(pm)
            fmt.Println("📊 Global metrics updated after mining.")
        }
    }
}

func handleChangePassword(db *ledger.Ledger, scanner *bufio.Scanner, miner *ledger.Miner) {
    fmt.Println("\n🔑 Change Password")
    newPass := readPassword(scanner, "Enter new password: ")
    confirm := readPassword(scanner, "Confirm new password: ")
    if newPass != confirm {
        fmt.Println("❌ Passwords do not match.")
        return
    }

    err := miner.ChangePasswordAfterRestore(newPass)
    if err != nil {
        fmt.Println("❌ Failed to change password:", err)
        return
    }

    err = db.PutObject([]byte("miner:"+miner.ID), miner)
    if err != nil {
        fmt.Println("❌ Failed to save updated miner:", err)
        return
    }

    fmt.Println("✅ Password changed successfully.")
}

func handleDeleteMiner(db *ledger.Ledger, scanner *bufio.Scanner, miner *ledger.Miner) bool {
    fmt.Println("\n🗑️ Delete Miner Account")
    fmt.Println("Enter your 4 sacred words in order:")
    words := make([]string, 4)
    for i := 0; i < 4; i++ {
        for {
            word := strings.TrimSpace(readInput(scanner, fmt.Sprintf("Word #%d: ", i+1)))
            if !ledger.IsValidSacredWordFormat(word) {
                fmt.Println("⚠️ Invalid format. Must start with uppercase, ≥4 chars, letters and '-' allowed.")
                continue
            }
            words[i] = word
            break
        }
    }

    err := ledger.DeleteMiner(words, miner)
    if err != nil {
        fmt.Println("❌ Failed to authorize deletion:", err)
        return false
    }

    err = db.PutBytes([]byte("miner:"+miner.ID), nil)
    if err != nil {
        fmt.Println("❌ Failed to delete from DB:", err)
        return false
    }

    fmt.Println("✅ Miner account deleted successfully.")
    return true
}

func SyncWithNetwork(node *p2p.Node, db *ledger.Ledger) {
    blocks, err := node.FetchBlocks()
    if err != nil {
        fmt.Println("⚠️ Failed to fetch blocks from network:", err)
        return
    }

    for _, blk := range blocks {
        if err := db.ApplyBlock(blk); err != nil {
            fmt.Printf("⚠️ Failed to apply block %d: %v\n", blk.Header.Height, err)
        } else {
            fmt.Printf("✅ Block %d applied successfully.\n", blk.Header.Height)
        }
    }

    fmt.Println("📡 Ledger fully synchronized with network.")
}

// -----------------------------
// Helpers
// -----------------------------
func readInput(scanner *bufio.Scanner, prompt string) string {
        fmt.Print(prompt)
        if !scanner.Scan() {
                return ""
        }
        return strings.TrimSpace(scanner.Text())
}

func readPassword(scanner *bufio.Scanner, prompt string) string {
        // Currently no masking implemented
        return readInput(scanner, prompt)
}
