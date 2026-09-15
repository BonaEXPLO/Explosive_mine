// cmd/ledgerapp/main.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"explosive/internal/address"
	"explosive/internal/encryption"
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

// startP2PNodeForMiner starts the P2P node, attaches the ledger and
// public wallet/miner identities, configures wallet and miner signing,
// starts Exploscan and requests an initial ledger synchronization.
func startP2PNodeForMiner(
	listenAddr string,
	db *ledger.Ledger,
	minerID string,
	sacredWords []string,
) (*p2p.Node, chan struct{}, error) {

	var node *p2p.Node
	var err error

	// Create a deterministic node identity when a miner identity is available.
	// Otherwise create a normal wallet-based node identity.
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
		return nil, nil, fmt.Errorf(
			"failed to create P2P node: %w",
			err,
		)
	}

	// Attach ledger.
	node.Ledger = db

	// ------------------------------------------------------------
	// WALLET P2P IDENTITY
	// ------------------------------------------------------------
	//
	// Every authenticated P2P node uses its EXPLO wallet as its
	// network identity.
	//
	// For miners:
	//
	//     MinerID == WalletAddress
	//
	// The wallet public key and miner public key are separate
	// Ed25519 identities.
	//
	// The P2P package never receives wallet or miner private keys.

	if currentMiningWallet == nil {
		node.Stop()
		return nil, nil, fmt.Errorf(
			"no wallet authenticated for P2P identity",
		)
	}

	if !address.IsValidEXPLOAddress(
		currentMiningWallet.Address,
	) {
		node.Stop()
		return nil, nil, fmt.Errorf(
			"authenticated wallet has invalid EXPLO address",
		)
	}

	// ------------------------------------------------------------
	// 1. WALLET PUBLIC IDENTITY
	// ------------------------------------------------------------

	walletPublicKey, err := currentMiningWallet.PublicKeyBytes("")
	if err != nil {
		node.Stop()
		return nil, nil, fmt.Errorf(
			"failed to read wallet public key: %w",
			err,
		)
	}

	if len(walletPublicKey) != ed25519.PublicKeySize {
		for i := range walletPublicKey {
			walletPublicKey[i] = 0
		}

		node.Stop()
		return nil, nil, fmt.Errorf(
			"invalid wallet public key length",
		)
	}

	// Give the P2P node only the public wallet identity.
	if err := node.SetWalletIdentity(
		currentMiningWallet.Address,
		walletPublicKey,
	); err != nil {
		for i := range walletPublicKey {
			walletPublicKey[i] = 0
		}

		node.Stop()
		return nil, nil, fmt.Errorf(
			"failed to configure wallet identity: %w",
			err,
		)
	}

	// Wallet signing is delegated through a callback.
	// The P2P package never receives the wallet private key.
	if err := node.SetWalletSigner(
		signWithWalletSession,
	); err != nil {
		for i := range walletPublicKey {
			walletPublicKey[i] = 0
		}

		node.Stop()
		return nil, nil, fmt.Errorf(
			"failed to configure wallet signer: %w",
			err,
		)
	}

	log.Printf(
		"🔐 Wallet P2P identity attached: %s",
		currentMiningWallet.Address,
	)

	// Clear the temporary public-key copy.
	for i := range walletPublicKey {
		walletPublicKey[i] = 0
	}

	// ------------------------------------------------------------
	// 2. OPTIONAL MINER PUBLIC IDENTITY
	// ------------------------------------------------------------
	//
	// A normal wallet node has no miner identity.
	//
	// A miner must satisfy:
	//
	//     MinerID == WalletAddress
	//
	// Sacred words remain exclusively local and are never transmitted
	// through the P2P protocol.

	if minerID != "" {

		if !strings.EqualFold(
			currentMiningWallet.Address,
			minerID,
		) {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"wallet address does not match miner ID: wallet=%s miner=%s",
				currentMiningWallet.Address,
				minerID,
			)
		}

		if !address.IsValidEXPLOAddress(minerID) {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"invalid miner ID",
			)
		}

		if len(sacredWords) != 4 {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"miner identity requires exactly 4 sacred words",
			)
		}

		// --------------------------------------------------------
		// MINER PUBLIC IDENTITY
		// --------------------------------------------------------

		// Derive the miner key only long enough to obtain its
		// public identity. The P2P node receives the public key only.
		minerPriv, minerPub, err := ledger.DeriveMinerKey(
			minerID,
			sacredWords,
		)
		if err != nil {
			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to derive miner identity key: %w",
				err,
			)
		}

		if len(minerPub) != ed25519.PublicKeySize {
			for i := range minerPriv {
				minerPriv[i] = 0
			}

			for i := range minerPub {
				minerPub[i] = 0
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"invalid derived miner public key size",
			)
		}

		if err := node.SetMinerIdentity(
			minerID,
			minerPub,
		); err != nil {
			for i := range minerPriv {
				minerPriv[i] = 0
			}

			for i := range minerPub {
				minerPub[i] = 0
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to configure miner identity: %w",
				err,
			)
		}

		// The P2P node never stores the miner private key.
		for i := range minerPriv {
			minerPriv[i] = 0
		}

		// Clear the temporary public-key copy.
		for i := range minerPub {
			minerPub[i] = 0
		}

		// --------------------------------------------------------
		// MINER P2P SIGNER
		// --------------------------------------------------------
		//
		// The P2P package receives only this callback.
		// Sacred words remain outside the P2P package.

		signingWords := append([]string(nil), sacredWords...)

		if err := node.SetMinerSigner(
			func(data []byte) ([]byte, error) {

				priv, _, err := ledger.DeriveMinerKey(
					minerID,
					signingWords,
				)
				if err != nil {
					return nil, err
				}

				signature := ed25519.Sign(
					priv,
					data,
				)

				for i := range priv {
					priv[i] = 0
				}

				return signature, nil
			},
		); err != nil {

			for i := range signingWords {
				signingWords[i] = ""
			}

			node.Stop()
			return nil, nil, fmt.Errorf(
				"failed to configure miner signer: %w",
				err,
			)
		}

		log.Printf(
			"🔐 Miner P2P identity attached: %s",
			minerID,
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

		fmt.Println(
			"📡 Requesting initial ledger sync from peers...",
		)

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

		// ------------------------------------------------------------
		// AUTHENTICATE EXISTING WALLET
		// ------------------------------------------------------------
		//
		// Every authenticated P2P node uses an existing EXPLO wallet
		// as its cryptographic network identity.
		//
		// Headless mode never creates or restores a wallet.
		// It only authenticates an existing local wallet.
		//
		// The wallet password is used locally and is never transmitted.

		scanner := bufio.NewScanner(os.Stdin)

		if _, err := prepareWalletForP2P(scanner); err != nil {
			log.Fatalf(
				"❌ Failed to authenticate wallet for P2P: %v",
				err,
			)
		}

		// ------------------------------------------------------------
		// START WALLET-AUTHENTICATED P2P NODE
		// ------------------------------------------------------------
		//
		// No miner identity is supplied here.
		//
		// Therefore this headless node is a normal wallet node.
		//
		// If the wallet later becomes a miner, MinerID will be equal
		// to the wallet address and the miner identity will be attached
		// through the mining flow.

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

// prepareWalletForP2P authenticates an existing wallet for P2P identity.
// The wallet private key remains encrypted at rest and is unlocked only
// for the in-memory signing session.
func prepareWalletForP2P(scanner *bufio.Scanner) (*wallet.Wallet, error) {
	if walletDB == nil {
		return nil, fmt.Errorf("wallet database is not available")
	}

	fmt.Println()
	fmt.Println("🔐 Connect your existing EXPLO wallet.")
	fmt.Println("This wallet will be used as your P2P network identity.")
	fmt.Println()

	walletAddress := strings.TrimSpace(
		readInput(scanner, "Enter wallet address: "),
	)

	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	walletAddress = strings.ToLower(walletAddress)

	if !address.IsValidEXPLOAddress(walletAddress) {
		return nil, fmt.Errorf("invalid EXPLO wallet address")
	}

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

	if !strings.EqualFold(selected.Address, walletAddress) {
		return nil, fmt.Errorf("wallet identity mismatch")
	}

	if !address.IsValidEXPLOAddress(selected.Address) {
		return nil, fmt.Errorf(
			"wallet contains an invalid EXPLO address",
		)
	}

	if strings.TrimSpace(selected.PublicKeyHex) == "" {
		return nil, fmt.Errorf("wallet has no public key")
	}

	fmt.Println()
	fmt.Println("🔑 Unlock wallet for P2P authentication.")
	fmt.Println("The wallet password is required only locally.")
	fmt.Println("The password is NEVER transmitted over P2P.")

	walletPassword := readPassword(
		scanner,
		"Enter wallet password: ",
	)

	if err := setWalletSigningSession(
		selected,
		walletPassword,
	); err != nil {
		return nil, fmt.Errorf(
			"wallet authentication failed: %w",
			err,
		)
	}

	currentMiningWallet = selected

	fmt.Println()
	fmt.Println("✅ Wallet authenticated successfully.")
	fmt.Printf(
		"🌐 P2P identity: %s\n",
		selected.Address,
	)

	return selected, nil
}
