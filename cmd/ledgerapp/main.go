// cmd/ledgerapp/main.go
package main

import (
	"bufio"
	"explosive/internal/halving"
	"explosive/internal/p2p"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"explosive/internal/guardian"
	"explosive/internal/ledger"
)

// Toggle password masking (false = clear text, true = hidden)
var hidePassword = false

func main() {
	// ✅ Ledger stocké dans ~/.explosive/ledger
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("❌ Cannot detect home directory:", err)
	}
	dbPath := filepath.Join(homeDir, ".explosive", "ledger")

	db, err := ledger.OpenLedger(dbPath)
	if err != nil {
		log.Fatal("Failed to open ledger DB:", err)
	}
	defer db.Close()

	// ⚡ Initialise le Genesis block au démarrage
	genesis, err := ledger.CreateGenesisBlock(db)
	if err != nil {
		log.Fatal("Failed to initialize Genesis block:", err)
	}
	if genesis != nil {
		fmt.Printf("⚡ Genesis block created: %d EXPLO locked forever\n", ledger.GenesisEXPLO)
	} else {
		fmt.Println("⚡ Genesis block already exists.")
	}

	if err := db.DumpLedger(); err != nil {
		log.Fatalf("❌ Dump failed: %v", err)
	}

	fmt.Println("💎 Welcome to EXPLOSIVE Ledger App!")
	scanner := bufio.NewScanner(os.Stdin)
	var currentMiner *ledger.Miner
	var node *p2p.Node

	for {
		fmt.Println("\nSelect an option:")
		fmt.Println("1️⃣  Create miner account")
		fmt.Println("2️⃣  Restore miner account")
		fmt.Println("3️⃣  Mine EXPLO / IMANI")
		fmt.Println("4️⃣  Change password")
		fmt.Println("5️⃣  Delete account")
		fmt.Println("6️⃣  Exit")
		fmt.Println("7️⃣  Sync with network")
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			miner := handleCreateMiner(db, scanner)
			if miner != nil {
				currentMiner = miner
			}

		case "2":
			miner := handleRestoreMiner(db, scanner)
			if miner != nil {
				currentMiner = miner
			}

		case "3":
			if currentMiner == nil {
				fmt.Println("❌ You must create or restore a miner account first.")
				continue
			}

			// ⚡ Crée ou récupère le noeud P2P avec port dérivé
			if node == nil {
				listenAddr, err := p2p.DeriveListenAddrFromIdentity(currentMiner.ID, currentMiner.ConsciousnessFingerprint)
				if err != nil {
					log.Fatal("❌ Cannot derive listen address:", err)
				}
				node = p2p.NewNode(listenAddr, "explosive-mainnet", "ledger-client")
				node.Ledger = db // passe le ledger au noeud P2P
				err = node.Start()
				if err != nil {
					log.Fatal("❌ Failed to start P2P node:", err)
				}
				fmt.Printf("📡 P2P node started on %s\n", listenAddr)
			}

			handleMine(db, scanner, currentMiner, node)

		case "4":
			if currentMiner == nil {
				fmt.Println("❌ You must create or restore a miner account first.")
			} else {
				handleChangePassword(db, scanner, currentMiner)
			}

		case "5":
			if currentMiner == nil {
				fmt.Println("❌ You must create or restore a miner account first.")
			} else {
				if handleDeleteMiner(db, scanner, currentMiner) {
					currentMiner = nil
					if node != nil {
						node.Stop()
						node = nil
					}
				}
			}

		case "6":
			fmt.Println("👋 Goodbye!")
			if node != nil {
				node.Stop()
			}
			return

		case "7":
			fmt.Println("📡 Synchronizing ledger with network...")
			if node == nil {
				fmt.Println("❌ No P2P node running. Restore or create a miner first.")
				continue
			}
			SyncWithNetwork(node, db)

		default:
			fmt.Println("❌ Invalid option, try again.")
		}
	}
}

// -----------------------------
// Handlers
// -----------------------------

func handleCreateMiner(db *ledger.Ledger, scanner *bufio.Scanner) *ledger.Miner {
	fmt.Println("\n🆕 Create Miner Account")

	// 1️⃣ Miner ID
	rawID := readInput(scanner, "Enter miner ID (ex: explo + 40 hex + 8 checksum, total 53 chars): ")
	id := strings.ToLower(strings.TrimSpace(rawID))
	id = strings.ReplaceAll(id, "\n", "")
	id = strings.ReplaceAll(id, "\r", "")

	if !ledger.IsValidMinerID(id) {
		fmt.Println("❌ Invalid miner ID. Must start with 'explo', lowercase, 40 hex chars body + 8 chars checksum (total 53).")
		return nil
	}

	// 2️⃣ Check if ID exists
	var existing ledger.Miner
	err := db.GetObject([]byte("miner:"+id), &existing)
	if err == nil {
		fmt.Println("❌ Miner ID already exists. Choose a different ID.")
		return nil
	}

	// 3️⃣ Password
	password := readPassword(scanner, "Create a strong password (≥8 chars, upper, lower, digit, symbol): ")
	confirm := readPassword(scanner, "Confirm password: ")
	if password != confirm {
		fmt.Println("❌ Passwords do not match.")
		return nil
	}

	// 4️⃣ Sacred words (ConsciousnessFingerprint)
	fmt.Println("💡 Enter your 4 sacred words:")
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

	// 5️⃣ Prevent duplicate fingerprint
	dup, err := guardian.IsDuplicateFingerprint(words)
	if err != nil {
		fmt.Println("❌ Failed to check fingerprint duplication:", err)
		return nil
	}
	if dup {
		fmt.Println("❌ These sacred words are already used by another miner.")
		return nil
	}

	// 6️⃣ Create miner
	miner, msg, err := ledger.CreateMiner(id, password, words)
	if err != nil {
		fmt.Println("❌ Error creating miner:", err)
		return nil
	}

	// 7️⃣ Save to DB
	err = db.PutObject([]byte("miner:"+id), miner)
	if err != nil {
		fmt.Println("❌ Failed to save miner:", err)
		return nil
	}

	fmt.Println("✅ Miner account created successfully!")
	fmt.Println("💬 Guardian says:", msg)
	return miner
}

func handleRestoreMiner(db *ledger.Ledger, scanner *bufio.Scanner) *ledger.Miner {
	fmt.Println("\n♻️ Restore Miner Account")
	id := readInput(scanner, "Enter miner ID (ex: explo + 40 hex + 8 checksum, total 53 chars): ")

	// Check if miner exists
	var stored ledger.Miner
	err := db.GetObject([]byte("miner:"+id), &stored)
	if err != nil {
		fmt.Println("❌ Miner not found:", err)
		return nil
	}

	// Prompt sacred words
	fmt.Println("Enter your 4 sacred words in order (format: start uppercase, ≥4 chars, compound words allowed):")
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

	// Ask for new password
	newPass := readPassword(scanner, "Enter a new password for restoration: ")

	miner, msg, err := ledger.RestoreMiner(id, words, newPass)
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

	// Récupérer l'état du mineur
	stateKey := []byte("state:" + miner.ID)
	state := &ledger.MinerState{}
	if err := db.GetObject(stateKey, state); err != nil || state == nil {
		state = &ledger.MinerState{}
	}
	previousIMANI := state.IMANI

	// Récupérer le solde du mineur
	balanceKey := []byte("balance:" + miner.ID)
	balance := &ledger.Balance{}
	if err := db.GetObject(balanceKey, balance); err != nil || balance == nil {
		balance = &ledger.Balance{}
	}

	// --- Lecture du pourcentage de donation ---
	var donation float64
	for {
		input := readInput(scanner, "Donation percent (0.0 - 0.1)? Enter 0 for none: ")
		d, err := strconv.ParseFloat(strings.TrimSpace(input), 64)
		if err != nil {
			fmt.Println("⚠️ Invalid number format. Use 0.05 for 5%, etc.")
			continue
		}
		if d < 0.0 || d > 0.1 {
			fmt.Println("⚠️ Must be a number between 0.0 and 0.1")
			continue
		}
		donation = d
		break
	}

	// --- Mining ---
	if err := ledger.Mine(db, miner, state, donation); err != nil {
		fmt.Println("❌ Mining failed:", err)
		return
	}

	// Récupérer la récompense actuelle (halving-aware)
	exploReward, err := halving.GetCurrentReward(db.GetDB())
	if err != nil {
		fmt.Println("❌ Failed to get reward:", err)
		return
	}

	// Calcul des montants
	donationAmount := exploReward * donation
	netReward := exploReward - donationAmount

	// --- Mise à jour du solde du mineur ---
	balance.EXPLO += netReward

	deltaIMANI := state.IMANI - previousIMANI
	if deltaIMANI > 0 {
		balance.IMANI += deltaIMANI
	}

	// --- Sauvegarde atomique ---
	if err := db.PutObject(balanceKey, balance); err != nil {
		fmt.Println("⚠️ Warning: failed to save wallet balance:", err)
	}
	if err := db.PutObject(stateKey, state); err != nil {
		fmt.Println("⚠️ Warning: failed to save miner state:", err)
	}

	// --- Crédite le donpool correctement ---
	if donationAmount > 0 {
		if err := ledger.CreditDonpool(db, donationAmount); err != nil {
			fmt.Println("⚠️ Failed to credit donpool:", err)
		}
	}

	// --- Affichage des résultats ---
	fmt.Println("✅ Mining session complete!")
	fmt.Printf("💰 Wallet balance: %.3f EXPLO, %.2f IMANI\n", balance.EXPLO, balance.IMANI)
	fmt.Printf("🌟 LUMEN (spiritual measure): %.2f / %.2f\n", state.LUMEN, ledger.MaxLumen)
	fmt.Printf("💸 Donation: %.3f EXPLO contributed\n", donationAmount)

	// --- Broadcast du nouveau bloc ---
	lastBlock, err := db.GetLatestBlock()
	if err != nil {
		fmt.Println("⚠️ Impossible de récupérer le dernier bloc:", err)
	} else if lastBlock != nil && node != nil {
		env, err := p2p.NewEnvelopeFromPayload(node.ProtocolVersion(), p2p.MsgTypeBlock, lastBlock)
		if err == nil {
			node.Broadcast(env)
			fmt.Println("📡 New block broadcasted to network peers!")
		} else {
			fmt.Println("⚠️ Failed to create block envelope:", err)
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
	if hidePassword {
		return readInput(scanner, prompt)
	}
	return readInput(scanner, prompt)
}

// SyncWithNetwork synchronizes the local ledger with all new blocks from peers.
// Ensures blocks are validated and stored sequentially for Mainnet safety.
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
