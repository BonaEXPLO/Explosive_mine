// cmd/ledgerapp/main.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"explosive/internal/address"
	"explosive/internal/encryption"
	"explosive/internal/guardian"
	"explosive/internal/ledger"
	"explosive/internal/p2p"
	"explosive/internal/scan"
	"explosive/internal/wallet"
	"flag"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var hidePassword = false

// Local wallet database and currently selected wallet for mining.
var (
	walletDB            *wallet.WalletDB
	currentMiningWallet *wallet.Wallet
)

// Wallet signing session.
//
// The wallet private key exists in memory only while the wallet is unlocked.
// It is never sent through P2P.
var (
	walletSessionMu   sync.RWMutex
	walletSessionPriv ed25519.PrivateKey
)

func clearWalletSigningSession() {
	walletSessionMu.Lock()
	defer walletSessionMu.Unlock()

	if walletSessionPriv != nil {
		for i := range walletSessionPriv {
			walletSessionPriv[i] = 0
		}
		walletSessionPriv = nil
	}
}

func setWalletSigningSession(w *wallet.Wallet, password string) error {
	if w == nil {
		return fmt.Errorf("wallet is nil")
	}

	if password == "" {
		return fmt.Errorf("wallet password is required")
	}

	if w.EncryptedPriv == nil {
		return fmt.Errorf("wallet has no encrypted private key")
	}

	privBytes, _, err := encryption.DecryptWallet(w.EncryptedPriv, password)
	if err != nil {
		return fmt.Errorf("failed to unlock wallet: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		for i := range privBytes {
			privBytes[i] = 0
		}
		return fmt.Errorf("invalid wallet private key length")
	}

	priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(priv, privBytes)

	for i := range privBytes {
		privBytes[i] = 0
	}

	pub := priv.Public().(ed25519.PublicKey)

	expectedPub, err := hex.DecodeString(strings.TrimSpace(w.PublicKeyHex))
	if err != nil {
		for i := range priv {
			priv[i] = 0
		}
		return fmt.Errorf("invalid wallet public key encoding: %w", err)
	}

	if len(expectedPub) != ed25519.PublicKeySize {
		for i := range priv {
			priv[i] = 0
		}
		return fmt.Errorf("invalid wallet public key length")
	}

	if !ed25519.PublicKey(pub).Equal(ed25519.PublicKey(expectedPub)) {
		for i := range priv {
			priv[i] = 0
		}
		return fmt.Errorf("wallet private key does not match wallet public key")
	}

	walletSessionMu.Lock()

	if walletSessionPriv != nil {
		for i := range walletSessionPriv {
			walletSessionPriv[i] = 0
		}
	}

	walletSessionPriv = priv

	walletSessionMu.Unlock()

	return nil
}

func signWithWalletSession(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot sign empty data")
	}

	walletSessionMu.RLock()
	defer walletSessionMu.RUnlock()

	if len(walletSessionPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("wallet signing session is locked")
	}

	signature := ed25519.Sign(walletSessionPriv, data)
	return signature, nil
}

// startP2PNodeForMiner starts the P2P node, attaches the ledger and wallet
// public identity, configures wallet signing, starts Exploscan and requests
// an initial ledger synchronization.
func startP2PNodeForMiner(
	listenAddr string,
	db *ledger.Ledger,
	minerID string,
	sacredWords []string,
) (*p2p.Node, chan struct{}, error) {

	var node *p2p.Node
	var err error

	// Create a deterministic node identity when a miner identity is available.
	// Otherwise create a normal observer node.
	if minerID != "" && len(sacredWords) == 4 {
		node, err = p2p.NewNode(
			listenAddr,
			"explosive-mainnet",
			"ledger-client",
			minerID,
			sacredWords,
		)
	} else {
		node, err = p2p.NewNode(
			listenAddr,
			"explosive-mainnet",
			"ledger-client",
			"",
			nil,
		)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create P2P node: %w", err)
	}

	// Attach ledger.
	node.Ledger = db

	// ------------------------------------------------------------
	// WALLET PUBLIC IDENTITY
	// ------------------------------------------------------------
	//
	// For a miner:
	//
	//     MinerID == WalletAddress
	//
	// The wallet public key is used to prove ownership of the wallet
	// address during the P2P handshake.
	//
	// The private key NEVER enters the P2P package.
	if minerID != "" {
		if currentMiningWallet == nil {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"no wallet selected for miner identity",
			)
		}

		if !address.IsValidEXPLOAddress(currentMiningWallet.Address) {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"selected wallet has invalid EXPLO address",
			)
		}

		if !strings.EqualFold(
			currentMiningWallet.Address,
			minerID,
		) {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"wallet address does not match miner ID",
			)
		}

		publicKey, err := currentMiningWallet.PublicKeyBytes("")
		if err != nil {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to read wallet public key: %w",
				err,
			)
		}

		if len(publicKey) != ed25519.PublicKeySize {
			for i := range publicKey {
				publicKey[i] = 0
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"invalid wallet public key length",
			)
		}

		// Give the node only public wallet identity.
		if err := node.SetWalletIdentity(
			currentMiningWallet.Address,
			publicKey,
		); err != nil {
			for i := range publicKey {
				publicKey[i] = 0
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to configure wallet identity: %w",
				err,
			)
		}

		// The node receives only a signing callback.
		// The P2P package never receives the wallet private key.
		if err := node.SetWalletSigner(signWithWalletSession); err != nil {
			for i := range publicKey {
				publicKey[i] = 0
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to configure wallet signer: %w",
				err,
			)
		}

		for i := range publicKey {
			publicKey[i] = 0
		}

		log.Printf(
			"🔐 Wallet identity attached to miner P2P node: %s",
			currentMiningWallet.Address,
		)
	}

	// ------------------------------------------------------------
	// CUSTOM MESSAGE HANDLER
	// ------------------------------------------------------------

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
				Addr  string  `cbor:"addr"`
				Exp   float64 `cbor:"exp"`
				Imani float64 `cbor:"imani"`
			}

			if err := cbor.Unmarshal(payload, &bal); err == nil {
				fmt.Printf(
					"Balance update for %s: %.4f EXPLO / %.4f IMANI\n",
					bal.Addr,
					bal.Exp,
					bal.Imani,
				)
			}

		case "LEDGER_SYNC":
			var syncData struct {
				Data []wallet.Transaction `cbor:"data"`
			}

			if err := cbor.Unmarshal(payload, &syncData); err == nil {
				fmt.Printf(
					"LEDGER_SYNC received: %d transactions\n",
					len(syncData.Data),
				)

				for _, tx := range syncData.Data {
					_ = wallet.SaveTransaction(nil, tx)
				}
			}
		}
	})

	// ------------------------------------------------------------
	// START P2P
	// ------------------------------------------------------------

	// Bootstrap is called internally by Start.
	if err := node.Start(); err != nil {
		return nil, nil, fmt.Errorf(
			"failed to start P2P node: %w",
			err,
		)
	}

	// Attach node to wallet package.
	wallet.SetActiveNode(node)

	// ------------------------------------------------------------
	// EXPLOSCAN
	// ------------------------------------------------------------

	stopScan := make(chan struct{})

	go scan.StartExploscan(
		db,
		node,
		stopScan,
	)

	// ------------------------------------------------------------
	// INITIAL LEDGER SYNC
	// ------------------------------------------------------------

	go func() {
		time.Sleep(800 * time.Millisecond)

		fmt.Println("📡 Requesting initial ledger sync from peers...")

		if _, err := node.FetchBlocks(); err != nil {
			fmt.Printf(
				"⚠️ Initial FetchBlocks failed: %v\n",
				err,
			)
			return
		}

		fmt.Println(
			"📡 Block sync requested — blocks will arrive asynchronously.",
		)
	}()

	return node, stopScan, nil
}

// prepareWalletForMining selects and unlocks an existing wallet.
//
// Important:
// - The wallet is created/restored using BIP39.
// - The wallet address automatically becomes MinerID.
// - Wallet password and miner password remain separate.
// - Sacred words are used only by the miner identity.
func prepareWalletForMining(scanner *bufio.Scanner) (*wallet.Wallet, error) {
	if walletDB == nil {
		return nil, fmt.Errorf("wallet database is not available")
	}

	fmt.Println()
	fmt.Println("🔐 Connect your existing EXPLO wallet.")
	fmt.Println("Enter the wallet address you want to use for mining.")
	fmt.Println("The wallet must already exist on this device.")
	fmt.Println()

	// Ask directly for the wallet address.
	// Never enumerate or display all wallets stored in the database.
	walletAddress := strings.TrimSpace(
		readInput(scanner, "Enter wallet address: "),
	)

	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	// Normalize the address before validation and database lookup.
	walletAddress = strings.ToLower(walletAddress)

	// Validate the supplied EXPLO address.
	if !address.IsValidEXPLOAddress(walletAddress) {
		return nil, fmt.Errorf("invalid EXPLO wallet address")
	}

	// Load ONLY the wallet identified by the supplied address.
	selected, err := walletDB.LoadWallet(walletAddress)
	if err != nil {
		return nil, fmt.Errorf(
			"wallet not found on this device or could not be loaded: %w",
			err,
		)
	}

	if selected == nil {
		return nil, fmt.Errorf("wallet record is empty")
	}

	// Verify that the loaded wallet corresponds to the requested address.
	if !strings.EqualFold(selected.Address, walletAddress) {
		return nil, fmt.Errorf(
			"wallet identity mismatch",
		)
	}

	// Verify the wallet address again after loading the record.
	if !address.IsValidEXPLOAddress(selected.Address) {
		return nil, fmt.Errorf(
			"wallet contains an invalid EXPLO address",
		)
	}

	// A wallet used for mining must have a public key.
	if strings.TrimSpace(selected.PublicKeyHex) == "" {
		return nil, fmt.Errorf(
			"wallet has no public key",
		)
	}

	fmt.Println()
	fmt.Println("🔑 Unlock wallet for mining authentication.")
	fmt.Println("The wallet password is NOT the miner password.")

	walletPassword := readPassword(
		scanner,
		"Enter wallet password: ",
	)

	// Decrypt and verify the wallet private key.
	// This proves that the user controls the wallet.
	if err := setWalletSigningSession(
		selected,
		walletPassword,
	); err != nil {
		return nil, fmt.Errorf(
			"wallet authentication failed: %w",
			err,
		)
	}

	// Keep the authenticated wallet as the wallet associated
	// with the current mining session.
	currentMiningWallet = selected

	fmt.Println("✅ Wallet authenticated successfully.")
	fmt.Printf(
		"🆔 Miner ID will be: %s\n",
		selected.Address,
	)

	return selected, nil
}

func main() {
	// ----- Flags -----

	flagPort := flag.Int(
		"port",
		8443,
		"Port to listen on for P2P",
	)

	flagP2P := flag.Bool(
		"p2p",
		false,
		"Enable P2P networking",
	)

	flagSeed := flag.Bool(
		"seed",
		false,
		"Run seed initialization (create genesis etc.)",
	)

	flagHeadless := flag.Bool(
		"headless",
		false,
		"Run node without CLI interface (no interactive menu)",
	)

	flagNode := flag.Bool(
		"node",
		false,
		"Alias for --headless",
	)

	flagPeer := flag.String(
		"peer",
		"",
		"Initial P2P peer address (host:port)",
	)

	flag.Parse()

	// ----- Setup paths -----

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(
			"❌ Cannot detect home directory:",
			err,
		)
	}

	dbPath := filepath.Join(
		homeDir,
		".explosive",
		"ledger",
	)

	snapshotDir := filepath.Join(
		homeDir,
		".explosive",
		"snapshots",
	)

	// ----- Open Ledger DB -----

	db, err := ledger.OpenLedger(dbPath)
	if err != nil {
		log.Fatal(
			"❌ Failed to open ledger DB:",
			err,
		)
	}

	defer db.Close()

	// ------------------------------------------------------------
	// OPEN LOCAL WALLET DB
	// ------------------------------------------------------------
	//
	// This allows ledgerapp to find the wallet created/restored
	// by walletapp.
	//
	// The private key remains encrypted in this database.
	// It is decrypted only after the user enters the wallet password.
	walletDBPath := filepath.Join(
		homeDir,
		".explosive_wallet",
		"walletdb",
	)

	walletDB, err = wallet.OpenDB(walletDBPath)
	if err != nil {
		log.Fatal(
			"❌ Failed to open wallet DB:",
			err,
		)
	}

	defer walletDB.Close()

	log.Println("🔐 Local wallet database opened")

	// ===== Genesis =====

	if *flagSeed {
		genesis, err := ledger.CreateGenesisBlock(db)
		if err != nil {
			log.Fatal(
				"❌ Failed to initialize Genesis block:",
				err,
			)
		}

		if genesis != nil {
			fmt.Printf(
				"⚡ Genesis block created: %d EXPLO locked forever\n",
				ledger.GenesisEXPLO,
			)
		} else {
			fmt.Println("⚡ Genesis block already exists.")
		}
	} else {
		if _, err := ledger.CreateGenesisBlock(db); err != nil {
			log.Fatal(
				"❌ Failed to ensure Genesis block:",
				err,
			)
		}
	}

	// ===== NetworkID =====

	if err := ledger.InitNetworkID(db); err != nil {
		log.Fatal(
			"❌ Failed to initialize NetworkID:",
			err,
		)
	}

	// ===== Guardian =====

	ledger.SetupGuardianIdentityHooks(db)

	log.Println(
		"🔐 Guardian identity hooks connected to on-chain ledger",
	)

	// ===== Snapshot restore =====

	snapshots, _ := filepath.Glob("snapshot-*.slex")

	if len(snapshots) == 0 {

		log.Println(
			"ℹ No snapshot found — restoring from blocks only",
		)

		if err := db.RebuildMetaValuesFromBlocks(10000); err != nil {
			log.Fatalf(
				"Ledger rebuild failed: %v",
				err,
			)
		}

		log.Println(
			"✅ Ledger restored purely from block storage",
		)

	} else {

		sort.Slice(
			snapshots,
			func(i, j int) bool {
				return snapshots[i] > snapshots[j]
			},
		)

		latest := snapshots[0]

		log.Printf(
			"📦 Attempting snapshot restore: %s",
			latest,
		)

		if err := db.TryRestoreSnapshotSafe(latest); err != nil {

			log.Println(
				"⚠ Snapshot corrupted or incompatible — skipping",
			)

			if err := db.RebuildMetaValuesFromBlocks(10000); err != nil {
				log.Fatalf(
					"Ledger rebuild failed: %v",
					err,
				)
			}

			log.Println(
				"✅ Ledger restored purely from block storage",
			)

		} else {
			log.Println(
				"✅ Snapshot restored successfully",
			)
		}
	}

	// ===== Snapshot Manager =====

	snapshotMgr := ledger.NewSnapshotManager(
		db,
		snapshotDir,
	)

	snapshotMgr.Start()

	defer snapshotMgr.Stop()

	// ----- Optional dump -----

	if err := db.DumpLedger(); err != nil {
		fmt.Printf(
			"⚠️ DumpLedger failed (continuing): %v\n",
			err,
		)
	}

	// ----- Node & CLI setup -----

	var currentMiner *ledger.Miner
	var node *p2p.Node
	var scanStop chan struct{}

	// ------------------------------------------------------------
	// HEADLESS / NODE MODE
	// ------------------------------------------------------------

	if *flagHeadless || *flagNode {

		if !*flagP2P {
			log.Fatal(
				"❌ Headless mode requires --p2p",
			)
		}

		p2p.ClearBootstrapPeers()

		if *flagPeer != "" {
			p2p.BootstrapPeers = []string{*flagPeer}

			log.Printf(
				"[p2p] Development bootstrap peer configured: %s",
				*flagPeer,
			)
		} else {
			log.Println(
				"[p2p] No bootstrap peer configured — waiting for incoming peers",
			)
		}

		listen := fmt.Sprintf(
			":%d",
			*flagPort,
		)

		fmt.Printf(
			"🚀 Starting EXPLOSIVE P2P Node (HEADLESS) on %s ...\n",
			listen,
		)

		// Headless remains an observer node for now.
		// Miner wallet authentication is configured when an
		// interactive miner account is selected.
		n, stop, err := startP2PNodeForMiner(
			listen,
			db,
			"",
			nil,
		)

		if err != nil {
			log.Fatalf(
				"❌ Failed to start P2P node: %v",
				err,
			)
		}

		node = n
		scanStop = stop

		fmt.Println(
			"📡 P2P node running permanently in headless mode",
		)

		for {
			time.Sleep(24 * time.Hour)
		}
	}

	// ------------------------------------------------------------
	// INTERACTIVE CLI
	// ------------------------------------------------------------

	fmt.Println(
		"💎 Welcome to EXPLOSIVE Ledger App (merged P2P)!",
	)

	scanner := bufio.NewScanner(os.Stdin)

mainLoop:
	for {
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
			miner := handleCreateMiner(
				db,
				scanner,
				node,
			)

			if miner != nil {
				currentMiner = miner

				if node == nil {
					listenAddr, err := p2p.DeriveListenAddr(
						currentMiner.ID,
						currentMiner.ConsciousnessFingerprint,
						"",
					)

					if err != nil {
						log.Fatal(
							"❌ Cannot derive listen address:",
							err,
						)
					}

					n, stop, err := startP2PNodeForMiner(
						listenAddr,
						db,
						currentMiner.ID,
						currentMiner.ConsciousnessFingerprint,
					)

					if err != nil {
						log.Fatalf(
							"❌ Failed to start P2P node: %v",
							err,
						)
					}

					node = n
					scanStop = stop

					fmt.Printf(
						"📡 P2P node started on %s\n",
						listenAddr,
					)

					if md, err := scan.GatherMetrics(db); err == nil && md != nil {
						fmt.Println(
							"📊 Global metrics initialized from ledger.",
						)

						p2p.HookAfterBlock(
							db,
							nil,
							nil,
							"",
						)
					}
				}

				go SyncWithNetwork(
					node,
					db,
				)
			}

		case "2":
			miner := handleRestoreMiner(
				db,
				scanner,
			)

			if miner != nil {
				currentMiner = miner

				if node == nil {
					listenAddr, err := p2p.DeriveListenAddr(
						currentMiner.ID,
						currentMiner.ConsciousnessFingerprint,
						"",
					)

					if err != nil {
						log.Fatal(
							"❌ Cannot derive listen address:",
							err,
						)
					}

					n, stop, err := startP2PNodeForMiner(
						listenAddr,
						db,
						currentMiner.ID,
						currentMiner.ConsciousnessFingerprint,
					)

					if err != nil {
						log.Fatalf(
							"❌ Failed to start P2P node: %v",
							err,
						)
					}

					node = n
					scanStop = stop

					fmt.Printf(
						"📡 P2P node started on %s\n",
						listenAddr,
					)

					if md, err := scan.GatherMetrics(db); err == nil && md != nil {
						fmt.Println(
							"📊 Global metrics initialized from ledger.",
						)

						p2p.HookAfterBlock(
							db,
							nil,
							nil,
							"",
						)
					}
				}

				go SyncWithNetwork(
					node,
					db,
				)
			}

		case "3":
			if currentMiner == nil {
				fmt.Println(
					"❌ You must create or restore a miner account first.",
				)
				continue
			}

			if node == nil {
				listenAddr, err := p2p.DeriveListenAddr(
					currentMiner.ID,
					currentMiner.ConsciousnessFingerprint,
					"",
				)

				if err != nil {
					log.Fatal(
						"❌ Cannot derive listen address:",
						err,
					)
				}

				n, stop, err := startP2PNodeForMiner(
					listenAddr,
					db,
					currentMiner.ID,
					currentMiner.ConsciousnessFingerprint,
				)

				if err != nil {
					log.Fatalf(
						"❌ Failed to start P2P node: %v",
						err,
					)
				}

				node = n
				scanStop = stop

				fmt.Printf(
					"📡 P2P node started on %s\n",
					listenAddr,
				)
			}

			handleMine(
				db,
				scanner,
				currentMiner,
				node,
			)

		case "4":
			if currentMiner == nil {
				fmt.Println(
					"❌ You must create or restore a miner account first.",
				)
			} else {
				handleChangePassword(
					db,
					scanner,
					currentMiner,
				)
			}

		case "5":
			if currentMiner == nil {
				fmt.Println(
					"❌ You must create or restore a miner account first.",
				)
			} else {
				if handleDeleteMiner(
					db,
					scanner,
					currentMiner,
				) {
					currentMiner = nil

					// Clear wallet private key from memory.
					clearWalletSigningSession()
					currentMiningWallet = nil

					if scanStop != nil {
						close(scanStop)
						scanStop = nil
					}

					if node != nil {
						node.Stop()
						node = nil
					}
				}
			}

		case "6":
			fmt.Println("👋 Goodbye!")

			// Clear wallet private key from memory.
			clearWalletSigningSession()
			currentMiningWallet = nil

			if scanStop != nil {
				close(scanStop)
				scanStop = nil
			}

			if node != nil {
				node.Stop()
				node = nil
			}

			break mainLoop

		case "7":
			fmt.Println(
				"📡 Synchronizing ledger with network...",
			)

			if node == nil {
				fmt.Println(
					"❌ No P2P node running. Create or restore a miner first.",
				)
				continue
			}

			SyncWithNetwork(
				node,
				db,
			)

		case "8":
			if currentMiner == nil {
				fmt.Println(
					"❌ You must create or restore a miner account first.",
				)
				continue
			}

			if md, err := scan.GatherMetrics(db); err == nil && md != nil {
				fmt.Printf(
					"📊 Live Exploscan metrics:\n"+
						"  Timestamp: %d\n"+
						"  MaxSupply: %.2f\n"+
						"  Circulating: %.2f\n"+
						"  TotalHolders: %d\n"+
						"  MinersCount: %d\n"+
						"  MinersRemaining: %d\n",
					md.Timestamp,
					md.MaxSupply,
					md.Circulating,
					md.TotalHolders,
					md.MinersCount,
					md.MinersRemaining,
				)
			} else {
				fmt.Println(
					"⚠️ Failed to retrieve live metrics:",
					err,
				)
			}

		case "9":
			if currentMiner == nil {
				fmt.Println(
					" ❌ You must create or restore a miner account first.",
				)
				continue
			}

			fmt.Print(
				"Enter optional password to encrypt backup (leave empty for passwordless): ",
			)

			pw := readPassword(
				scanner,
				"",
			)

			path := fmt.Sprintf(
				"%s_backup.dat",
				currentMiner.ID,
			)

			if err := ledger.ExportMinerBackup(
				currentMiner,
				pw,
				path,
			); err != nil {
				fmt.Println(
					" ❌ Failed to export backup:",
					err,
				)
			} else {
				fmt.Println(
					" ✅ Backup exported to:",
					path,
				)
			}

		case "10":
			fmt.Print("Enter path to backup file: ")

			scanner.Scan()

			path := strings.TrimSpace(
				scanner.Text(),
			)

			fmt.Print(
				"Enter password used for backup (leave empty if none): ",
			)

			pw := readPassword(
				scanner,
				"",
			)

			restoredMiner, err := ledger.RestoreMinerBackup(
				pw,
				path,
			)

			if err != nil {
				fmt.Println(
					" ❌ Failed to restore backup:",
					err,
				)
			} else {
				fmt.Println(
					" ✅ Miner restored successfully:",
					restoredMiner.ID,
				)

				if db != nil {
					key := []byte(
						"miner:" + restoredMiner.ID,
					)

					_ = db.PutObject(
						key,
						restoredMiner,
					)
				}

				currentMiner = restoredMiner
			}

		default:
			fmt.Println(
				"❌ Invalid option, try again.",
			)
		}
	}

	fmt.Println(
		"🛑 Exiting ledger app.",
	)

	// ----- Graceful shutdown -----

	clearWalletSigningSession()
	currentMiningWallet = nil

	if snapshotMgr != nil {
		snapshotMgr.Stop()
	}

	if scanStop != nil {
		close(scanStop)
	}

	if node != nil {
		node.Stop()
	}
}

// handleCreateMiner creates a miner from an existing wallet.
//
// Important architecture:
// WalletAddress -> MinerID
//
// The user no longer manually enters a MinerID.
func handleCreateMiner(
	db *ledger.Ledger,
	scanner *bufio.Scanner,
	node *p2p.Node,
) *ledger.Miner {

	fmt.Println("\n🆕 Create Miner Account")

	// ------------------------------------------------------------
	// 1. Select and unlock existing wallet
	// ------------------------------------------------------------

	selectedWallet, err := prepareWalletForMining(scanner)
	if err != nil {
		fmt.Println(
			"❌ Wallet preparation failed:",
			err,
		)
		return nil
	}

	id := strings.ToLower(
		strings.TrimSpace(
			selectedWallet.Address,
		),
	)

	if !ledger.IsValidMinerID(id) {
		fmt.Println(
			"❌ Wallet address cannot be used as MinerID.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 2. Check duplicate miner
	// ------------------------------------------------------------

	var existing ledger.Miner

	if err := db.GetObject(
		[]byte("miner:"+id),
		&existing,
	); err == nil {
		fmt.Println(
			"❌ A miner already exists for this wallet address.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 3. Miner password
	// ------------------------------------------------------------
	//
	// This password is DIFFERENT from the wallet password.

	fmt.Println()
	fmt.Println("🔐 Now create the miner password.")
	fmt.Println("This password protects the miner identity on this device.")

	password := readPassword(
		scanner,
		"Create miner password: ",
	)

	confirm := readPassword(
		scanner,
		"Confirm miner password: ",
	)

	if password != confirm {
		fmt.Println(
			"❌ Miner passwords do not match.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 4. Sacred words
	// ------------------------------------------------------------

	fmt.Println()
	fmt.Println(
		"💡 Enter your 4 sacred words (Guardian ONLY):",
	)

	words := make([]string, 4)

	used := make(
		map[string]struct{},
	)

	for i := 0; i < 4; i++ {
		for {
			input := strings.TrimSpace(
				readInput(
					scanner,
					fmt.Sprintf("Word #%d: ", i+1),
				),
			)

			if !guardian.IsValidWordFormat(input) {
				fmt.Println(
					"⚠️ Invalid format (6–16 letters, hyphen or apostrophe allowed).",
				)
				continue
			}

			normalized := strings.ToLower(
				strings.TrimSpace(input),
			)

			if _, exists := used[normalized]; exists {
				fmt.Println(
					"⚠️ Duplicate word not allowed.",
				)
				continue
			}

			words[i] = normalized
			used[normalized] = struct{}{}

			fmt.Println(
				"✅ Confirmed:",
				normalized,
			)

			break
		}
	}

	// ------------------------------------------------------------
	// 5. Final Guardian validation
	// ------------------------------------------------------------

	if err := guardian.ValidateWordsFormat(words); err != nil {
		fmt.Println(
			"❌",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	words = guardian.NormalizeWords(words)

	dup, err := guardian.IsDuplicateFingerprint(words)
	if err != nil {
		fmt.Println(
			"❌ Failed to check fingerprint:",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	if dup {
		fmt.Println(
			"❌ Sacred words already used.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 6. Create miner
	// ------------------------------------------------------------

	miner, msg, err := ledger.CreateMiner(
		id,
		password,
		words,
		"",
		db,
	)

	if err != nil {
		fmt.Println(
			"❌ Error creating miner:",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 7. Persist miner
	// ------------------------------------------------------------

	if err := db.PutObject(
		[]byte("miner:"+id),
		miner,
	); err != nil {
		fmt.Println(
			"❌ Failed to save miner:",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	fmt.Println(
		"✅ Miner account created successfully!",
	)

	fmt.Println(
		"🆔 Miner ID:",
		miner.ID,
	)

	fmt.Println(
		"💳 Wallet address:",
		selectedWallet.Address,
	)

	fmt.Println(
		"💬 Guardian says:",
		msg,
	)

	return miner
}

// handleRestoreMiner restores a miner using:
//
// Existing Wallet Address + 4 Sacred Words + new Miner Password
func handleRestoreMiner(
	db *ledger.Ledger,
	scanner *bufio.Scanner,
) *ledger.Miner {

	fmt.Println(
		"\n♻️ Restore Miner Account (Universal Restoration)",
	)

	// ------------------------------------------------------------
	// 1. Select and unlock wallet
	// ------------------------------------------------------------

	selectedWallet, err := prepareWalletForMining(scanner)
	if err != nil {
		fmt.Println(
			"❌ Wallet preparation failed:",
			err,
		)
		return nil
	}

	id := strings.ToLower(
		strings.TrimSpace(
			selectedWallet.Address,
		),
	)

	if !address.IsValidEXPLOAddress(id) {
		fmt.Println(
			"❌ Invalid wallet address.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	fmt.Println()
	fmt.Println(
		"🆔 Miner ID:",
		id,
	)

	// ------------------------------------------------------------
	// 2. Sacred words
	// ------------------------------------------------------------

	fmt.Println(
		"Enter your 4 sacred words in order:",
	)

	words := make([]string, 4)

	used := make(
		map[string]struct{},
	)

	for i := 0; i < 4; i++ {
		for {
			input := strings.TrimSpace(
				readInput(
					scanner,
					fmt.Sprintf("Word #%d: ", i+1),
				),
			)

			if !guardian.IsValidWordFormat(input) {
				fmt.Println(
					"⚠️ Invalid format (6–16 letters, hyphen or apostrophe allowed).",
				)
				continue
			}

			normalized := strings.ToLower(
				strings.TrimSpace(input),
			)

			if _, exists := used[normalized]; exists {
				fmt.Println(
					"⚠️ Duplicate word not allowed.",
				)
				continue
			}

			words[i] = normalized
			used[normalized] = struct{}{}

			fmt.Println(
				"✅ Confirmed:",
				normalized,
			)

			break
		}
	}

	// ------------------------------------------------------------
	// 3. Validate sacred words
	// ------------------------------------------------------------

	if err := guardian.ValidateWordsFormat(words); err != nil {
		fmt.Println(
			"❌",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	words = guardian.NormalizeWords(words)

	// ------------------------------------------------------------
	// 4. New local miner password
	// ------------------------------------------------------------

	fmt.Println()
	fmt.Println(
		"🔐 Create a NEW miner password for this device.",
	)

	newPass := readPassword(
		scanner,
		"Enter new miner password: ",
	)

	confirm := readPassword(
		scanner,
		"Confirm new miner password: ",
	)

	if newPass != confirm {
		fmt.Println(
			"❌ Miner passwords do not match.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	// ------------------------------------------------------------
	// 5. Universal restoration
	// ------------------------------------------------------------

	miner, guardianMsg, err := ledger.RestoreMinerUniversal(
		id,
		words,
		newPass,
		db,
	)

	if err != nil {
		fmt.Println(
			"❌ Failed to restore miner:",
			err,
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	if miner == nil {
		fmt.Println(
			"❌ Miner restoration returned an empty identity.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	if !strings.EqualFold(
		miner.ID,
		selectedWallet.Address,
	) {
		fmt.Println(
			"❌ Restored miner ID does not match wallet address.",
		)

		clearWalletSigningSession()
		currentMiningWallet = nil

		return nil
	}

	fmt.Println(
		"✅ Miner restored successfully:",
		miner.ID,
	)

	fmt.Println(
		"🔐 Identity regenerated deterministically and secured for this device.",
	)

	fmt.Println(
		"💳 Wallet:",
		selectedWallet.Address,
	)

	fmt.Println(
		"💬 Guardian says:",
		guardianMsg,
	)

	return miner
}

func handleMine(
	db *ledger.Ledger,
	scanner *bufio.Scanner,
	miner *ledger.Miner,
	node *p2p.Node,
) {
	fmt.Println("\n⛏️ Mine EXPLO / IMANI")

	stateKey := []byte(
		"state:" + miner.ID,
	)

	state := &ledger.MinerState{}

	if err := db.GetObject(
		stateKey,
		state,
	); err != nil || state == nil {
		state = &ledger.MinerState{}
	}

	balanceKey := []byte(
		"balance:" + miner.ID,
	)

	balance := &ledger.Balance{}

	if err := db.GetObject(
		balanceKey,
		balance,
	); err != nil || balance == nil {
		balance = &ledger.Balance{}
	}

	// ------------------------------------------------------------
	// Donation
	// ------------------------------------------------------------

	var donation float64

	for {
		input := readInput(
			scanner,
			"Donation percent (0.0 - 0.1)? Enter 0 for none: ",
		)

		d, err := strconv.ParseFloat(
			strings.TrimSpace(input),
			64,
		)

		if err != nil {
			fmt.Println(
				"⚠️ Invalid number format.",
			)
			continue
		}

		if d < 0.0 || d > 0.1 {
			fmt.Println(
				"⚠️ Must be between 0.0 and 0.1",
			)
			continue
		}

		donation = d
		break
	}

	// ------------------------------------------------------------
	// Execute mining
	// ------------------------------------------------------------

	if err := ledger.Mine(
		db,
		miner,
		state,
		donation,
		node,
	); err != nil {
		fmt.Println(
			"❌ Mining failed:",
			err,
		)
		return
	}

	// ------------------------------------------------------------
	// Reload authoritative balance
	// ------------------------------------------------------------

	if err := db.GetObject(
		balanceKey,
		balance,
	); err != nil {
		balance = &ledger.Balance{}
	}

	if err := db.PutObject(
		stateKey,
		state,
	); err != nil {
		fmt.Println(
			"⚠️ Failed to save miner state:",
			err,
		)
	}

	fmt.Println(
		"✅ Mining session complete!",
	)

	fmt.Printf(
		"💰 Wallet balance: %.8f EXPLO, %.4f IMANI\n",
		float64(balance.EXPLO)/float64(ledger.PastaboPerEXPLO),
		float64(balance.IMANI)/float64(ledger.PastaboPerEXPLO),
	)

	fmt.Printf(
		"🌟 LUMEN: %.2f / %.2f\n",
		state.LUMEN,
		ledger.MaxLumen,
	)

	// ------------------------------------------------------------
	// Broadcast last block
	// ------------------------------------------------------------

	lastBlock, err := db.GetLatestBlock()

	if err != nil {
		fmt.Println(
			"⚠️ Failed to fetch last block:",
			err,
		)

	} else if lastBlock != nil && node != nil {

		env, err := p2p.NewEnvelopeFromPayload(
			node.ProtocolVersion(),
			p2p.MsgTypeBlock,
			lastBlock,
		)

		if err == nil {
			node.Broadcast(env)

			fmt.Println(
				"📡 New block broadcasted to network peers!",
			)
		} else {
			fmt.Println(
				"⚠️ Failed to create block envelope:",
				err,
			)
		}
	}

	// ------------------------------------------------------------
	// Metrics
	// ------------------------------------------------------------

	if node != nil {
		md, err := scan.GatherMetrics(db)

		if err != nil {
			fmt.Println(
				"⚠️ Failed to gather metrics after mining:",
				err,
			)

		} else if md != nil {
			fmt.Println(
				"📊 Global metrics updated after mining.",
			)

			p2p.HookAfterBlock(
				db,
				nil,
				nil,
				"",
			)
		}
	}
}

func handleChangePassword(
	db *ledger.Ledger,
	scanner *bufio.Scanner,
	miner *ledger.Miner,
) {
	fmt.Println("\n🔑 Change Password")

	newPass := readPassword(
		scanner,
		"Enter new password: ",
	)

	confirm := readPassword(
		scanner,
		"Confirm new password: ",
	)

	if newPass != confirm {
		fmt.Println(
			"❌ Passwords do not match.",
		)
		return
	}

	err := miner.ChangePasswordAfterRestore(
		newPass,
	)

	if err != nil {
		fmt.Println(
			"❌ Failed to change password:",
			err,
		)
		return
	}

	err = db.PutObject(
		[]byte("miner:"+miner.ID),
		miner,
	)

	if err != nil {
		fmt.Println(
			"❌ Failed to save updated miner:",
			err,
		)
		return
	}

	fmt.Println(
		"✅ Password changed successfully.",
	)
}

func handleDeleteMiner(
	db *ledger.Ledger,
	scanner *bufio.Scanner,
	miner *ledger.Miner,
) bool {

	fmt.Println("\n🗑️ Delete Miner Account")

	fmt.Println(
		"Enter your 4 sacred words in order:",
	)

	words := make([]string, 4)

	for i := 0; i < 4; i++ {
		for {
			word := strings.TrimSpace(
				readInput(
					scanner,
					fmt.Sprintf("Word #%d: ", i+1),
				),
			)

			_, err := guardian.FingerprintHash(
				[]string{word},
			)

			if err != nil {
				fmt.Println(
					"⚠️ Invalid format. Must start with uppercase, ≥4 chars, letters and '-' allowed.",
				)
				continue
			}

			words[i] = word
			break
		}
	}

	err := ledger.DeleteMiner(
		words,
		miner,
	)

	if err != nil {
		fmt.Println(
			"❌ Failed to authorize deletion:",
			err,
		)
		return false
	}

	err = db.PutBytes(
		[]byte("miner:"+miner.ID),
		nil,
	)

	if err != nil {
		fmt.Println(
			"❌ Failed to delete from DB:",
			err,
		)
		return false
	}

	fmt.Println(
		"✅ Miner account deleted successfully.",
	)

	return true
}

func SyncWithNetwork(
	node *p2p.Node,
	db *ledger.Ledger,
) {
	if node == nil {
		fmt.Println(
			"⚠️ Cannot synchronize: P2P node is nil.",
		)
		return
	}

	if _, err := node.FetchBlocks(); err != nil {
		fmt.Println(
			"⚠️ Failed to request block sync from network:",
			err,
		)
		return
	}

	fmt.Println(
		"📡 Sync requested — blocks will arrive asynchronously.",
	)
}

// -----------------------------
// Helpers
// -----------------------------

func readInput(
	scanner *bufio.Scanner,
	prompt string,
) string {
	fmt.Print(prompt)

	if !scanner.Scan() {
		return ""
	}

	return strings.TrimSpace(
		scanner.Text(),
	)
}

func readPassword(
	scanner *bufio.Scanner,
	prompt string,
) string {
	// Currently no terminal masking is implemented.
	return readInput(
		scanner,
		prompt,
	)
}
