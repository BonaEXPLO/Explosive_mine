package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
        "log"
	"path/filepath"
	"strings"
	"sync"
	"time"
        "explosive/internal/p2p"
	"explosive/internal/ledger"

	"explosive/internal/wallet"
)

// ---------- Config / constants ----------
const (
	InactiveTimeout    = 5 * time.Minute
	PasswordChangeDays = 7
	dataDirName        = ".explosive_wallet"
)

var (
	homeDir, _     = os.UserHomeDir()
	dataDir        = filepath.Join(homeDir, dataDirName)
	reader         = bufio.NewReader(os.Stdin)
	langEnglish    = true
	lastActivity   = time.Now()
	lockMutex      sync.Mutex
	locked         = false
	inactivityStop = make(chan struct{})
	currentWallet  *wallet.Wallet
	walletDB       *wallet.WalletDB
)

var walletP2P *p2p.WalletP2P

// ----------Utilities ----------
func printlnL(en, fr string) {
	if langEnglish {
		fmt.Println(en)
	} else {
		fmt.Println(fr)
	}
}

func prompt(promptText string) string {
	fmt.Print(promptText)
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

func updateActivity() {
	lockMutex.Lock()
	lastActivity = time.Now()
	lockMutex.Unlock()
}

// Inactivity watcher
func startInactivityWatcher() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				lockMutex.Lock()
				if !locked && time.Since(lastActivity) > InactiveTimeout {
					locked = true
					printlnL("🔒 Locked due to inactivity. Re-enter password to continue.",
						"🔒 Verrouillé pour inactivité. Entrez le mot de passe pour continuer.")
				}
				lockMutex.Unlock()
			case <-inactivityStop:
				return
			}
		}
	}()
}

func requireUnlock() error {
	lockMutex.Lock()
	if !locked {
		lockMutex.Unlock()
		return nil
	}
	lockMutex.Unlock()

	for {
		printlnL("[1] Enter password 🔑", "[1] Entrer le mot de passe 🔑")
		choice := prompt("Select (number): ")
		if choice == "1" {
			if currentWallet == nil {
				return fmt.Errorf("no wallet loaded")
			}
			pw := prompt("Password: ")
			_, err := currentWallet.RevealMnemonic(pw)
			if err == nil {
				lockMutex.Lock()
				locked = false
				lockMutex.Unlock()
				updateActivity()
				return nil
			}
			printlnL("❌ Incorrect password.", "❌ Mot de passe incorrect.")
		}
	}
}

// ---------- Mnemonic helpers ----------
func pick4Indices(n int) ([]int, error) {
	if n < 4 {
		return nil, fmt.Errorf("mnemonic too short")
	}
	set := map[int]struct{}{}
	for len(set) < 4 {
		var b [2]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return nil, err
		}
		idx := int(b[0])<<8 | int(b[1])
		idx = idx % n
		set[idx] = struct{}{}
	}
	out := make([]int, 0, 4)
	for k := range set {
		out = append(out, k)
	}
	return out, nil
}

// ---------- Wallet Flows ----------
func flowCreateWallet() error {
	printlnL("🧠 You will receive a 24-word mnemonic. Save it safely; Explosive cannot recover it.",
		"🧠 Vous recevrez une phrase mnemonique de 24 mots. Sauvegardez-la; Explosive ne peut pas la récupérer.")

	// Replace typing "continue" by a clickable-like choice (1/2)
	printlnL("1) Continue ▶️", "1) Continuer ▶️")
	printlnL("2) Cancel ❌", "2) Annuler ❌")
	ch := prompt("Select (number): ")
	if strings.TrimSpace(ch) != "1" {
		printlnL("Aborted.", "Annulé.")
		return nil
	}

	var pw string
	for {
		if langEnglish {
			pw = prompt("🔐 Create a strong password (min 8 chars incl upper,lower,digit,symbol): ")
		} else {
			pw = prompt("🔐 Créez un mot de passe fort (min 8 char., maj/min, chiffre, symbole): ")
		}
		pw2 := prompt("🔐 Confirm password: ")
		if pw != pw2 {
			printlnL("❌ Passwords do not match.", "❌ Les mots de passe ne correspondent pas.")
			continue
		}
		if err := wallet.ValidatePassword(pw); err != nil {
			fmt.Println("Password error:", err)
			continue
		}
		break
	}

	w, err := wallet.CreateWallet(pw)
	if err != nil {
		return fmt.Errorf("failed to create wallet: %w", err)
	}

	mn, err := w.RevealMnemonic(pw)
	if err != nil {
		return fmt.Errorf("internal: failed to reveal mnemonic: %w", err)
	}

	fmt.Println("\n--- 🧠 MNEMONIC (save it securely) ---")
	fmt.Println(mn)
	fmt.Println("--------------------------------------\n")

	parts := strings.Fields(mn)
	indices, err := pick4Indices(len(parts))
	if err != nil {
		return err
	}
	for _, idx := range indices {
		var promptText string
		if langEnglish {
			promptText = fmt.Sprintf("Enter word %d: ", idx+1)
		} else {
			promptText = fmt.Sprintf("Entrez le mot %d : ", idx+1)
		}
		ans := prompt(promptText)
		if ans != parts[idx] {
			printlnL("❌ Mnemonic confirmation failed.", "❌ La confirmation mnemonique a échoué.")
			return fmt.Errorf("mnemonic confirmation failed")
		}
	}

	printlnL("✅ Mnemonic confirmed.", "✅ Phrase mnemonique confirmée.")

	// Validate the generated address using wallet package (which uses internal/address)
	if !wallet.IsValidEXPLOAddress(w.Address) {
		return fmt.Errorf("invalid wallet address format")
	}

	if err := walletDB.SaveWallet(w); err != nil {
		return fmt.Errorf("failed to save wallet: %w", err)
	}

	// Initialize balances in DB
	if _, err := walletDB.GetBalance(w.Address); err != nil {
		_ = walletDB.SetBalance(w.Address, wallet.WalletBalance{EXPLO: 0, IMANI: 0})
	}

	currentWallet = w
	lockMutex.Lock()
	locked = false
	lockMutex.Unlock()
	updateActivity()

	printlnL("🎉 Wallet created successfully!", "🎉 Wallet créé avec succès!")
	fmt.Println("📬 Address:", w.Address)
	return nil
}

func flowRestoreWallet() error {
	// Prompt user to restore wallet using their 24-word mnemonic
	printlnL("🔁 Restore your wallet by entering your 24-word mnemonic.",
		"🔁 Restaurez votre wallet en entrant votre phrase mnemonique de 24 mots.")
	mn := prompt("🧠 Enter your 24-word mnemonic: ")

	// Ask user to create a new strong password for the restored wallet
	var pw string
	for {
		if langEnglish {
			pw = prompt("🔐 Create a strong password (min 8 chars incl upper,lower,digit,symbol): ")
		} else {
			pw = prompt("🔐 Créez un mot de passe fort (min 8 char., maj/min, chiffre, symbole): ")
		}
		pw2 := prompt("🔐 Confirm password: ")
		if pw != pw2 {
			printlnL("❌ Passwords do not match.", "❌ Les mots de passe ne correspondent pas.")
			continue
		}
		if err := wallet.ValidatePassword(pw); err != nil {
			fmt.Println("Password error:", err)
			continue
		}
		break
	}

	// Restore wallet object from mnemonic
	w, err := wallet.RestoreWalletByMnemonic(mn, pw)
	if err != nil {
		return fmt.Errorf("failed to restore wallet: %w", err)
	}

	// Validate restored wallet address format
	if !wallet.IsValidEXPLOAddress(w.Address) {
		return fmt.Errorf("invalid wallet address format")
	}

	// Save restored wallet to the local database
	if err := walletDB.SaveWallet(w); err != nil {
		return fmt.Errorf("failed to save restored wallet: %w", err)
	}

	// Initialize balances in the DB if not present
	if _, err := walletDB.GetBalance(w.Address); err != nil {
		_ = walletDB.SetBalance(w.Address, wallet.WalletBalance{EXPLO: 0, IMANI: 0})
	}

	// Set the current wallet and unlock it
	currentWallet = w
	lockMutex.Lock()
	locked = false
	lockMutex.Unlock()
	updateActivity()

	// Sync wallet balances with the blockchain ledger
	if err := SyncWalletBalances(); err != nil {
		fmt.Println("⚠️ Failed to sync balances:", err)
	}

	// Notify user of successful restoration
	printlnL("✅ Wallet restored successfully!", "✅ Wallet restauré avec succès!")
	fmt.Println("📬 Address:", w.Address)
	return nil
}

// ---------- Advanced settings ----------
func flowRevealMnemonic() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}
	pw := prompt("Enter password to reveal mnemonic: ")
	mn, err := currentWallet.RevealMnemonic(pw)
	if err != nil {
		return fmt.Errorf("invalid password or cannot reveal: %w", err)
	}
	fmt.Println("--- MNEMONIC ---")
	fmt.Println(mn)
	fmt.Println("----------------")
	return nil
}

func flowChangePassword() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}
	old := prompt("Enter old password: ")
	_, _, err := wallet.DecryptWallet(currentWallet.EncryptedPriv, old)
	if err != nil {
		return fmt.Errorf("old password incorrect")
	}

	lastChange, _ := walletDB.GetPasswordTimestamp(currentWallet.Address)
	if time.Since(time.Unix(lastChange, 0)) < PasswordChangeDays*24*time.Hour {
		return fmt.Errorf("password can only be changed once per %d days", PasswordChangeDays)
	}

	var newpw string
	for {
		newpw = prompt("Create new strong password: ")
		np2 := prompt("Confirm new password: ")
		if newpw != np2 {
			printlnL("❌ Passwords do not match.", "❌ Les mots de passe ne correspondent pas.")
			continue
		}
		if err := wallet.ValidatePassword(newpw); err != nil {
			fmt.Println("Password error:", err)
			continue
		}
		break
	}

	if err := currentWallet.ChangePassword(old, newpw); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	if err := walletDB.SaveWallet(currentWallet); err != nil {
		return fmt.Errorf("failed to save wallet after pw change: %w", err)
	}

	_ = walletDB.UpdatePasswordTimestamp(currentWallet.Address, time.Now().Unix())
	printlnL("✅ Password changed successfully.", "✅ Mot de passe changé avec succès.")
	return nil
}

func flowDeleteWallet() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}
	mn := prompt("Enter mnemonic to confirm deletion: ")
	pw := prompt("Enter password: ")
	if err := currentWallet.DeleteWallet(mn, pw); err != nil {
		return fmt.Errorf("failed to delete wallet: %w", err)
	}

	if err := walletDB.DeleteWallet(currentWallet.Address); err != nil {
		return fmt.Errorf("failed to remove wallet record: %w", err)
	}

	_ = walletDB.DeleteBalance(currentWallet.Address)
	currentWallet = nil
	printlnL("🗑️ Wallet deleted.", "🗑️ Wallet supprimé.")
	return nil
}

func ensureDataDir() error {
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		return os.MkdirAll(dataDir, 0700)
	}
	return nil
}

// flowShowBalances displays the current wallet's balances from the Ledger DB (source of truth).
func flowShowBalances() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}

	// Determine ledger path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot detect home dir: %w", err)
	}
	ledgerPath := filepath.Join(homeDir, ".explosive", "ledger")

	// Open ledger
	ldb, err := ledger.OpenLedger(ledgerPath)
	if err != nil {
		return fmt.Errorf("failed to open ledger: %w", err)
	}
	defer ldb.Close()

	// Read balance directly from ledger (key: "balance:<addr>")
	var bal ledger.Balance
	if err := ldb.GetObject([]byte("balance:"+currentWallet.Address), &bal); err != nil {
		// If not found or other error, treat as zero but don't crash
		bal = ledger.Balance{EXPLO: 0, IMANI: 0}
	}

	// Display
	printlnL("💰 Your balances:", "💰 Vos soldes :")
	fmt.Printf("🔹 EXPLO: %.4f\n", bal.EXPLO)
	fmt.Printf("✨ IMANI: %.4f\n", bal.IMANI)
	return nil
}

// flowSendEXPLO handles sending EXPLO tokens from the current wallet
// to a recipient address. It validates input, checks balance, updates
// the local ledger, records the transaction in the wallet DB, syncs
// cached balances, and broadcasts the transaction to the P2P network.
func flowSendEXPLO() error {
    if currentWallet == nil {
        return fmt.Errorf("no wallet loaded")
    }

    // Prompt user for recipient address and validate
    to := prompt("Recipient EXPLO address: ")
    if !wallet.IsValidEXPLOAddress(to) {
        return fmt.Errorf("invalid EXPLO address")
    }

    // Prompt user for amount
    amtStr := prompt("Amount EXPLO: ")
    var amt float64
    _, _ = fmt.Sscan(amtStr, &amt)
    if amt <= 0 {
        return fmt.Errorf("invalid amount")
    }

    // Open the local ledger database
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("cannot detect home directory: %w", err)
    }
    ledgerPath := filepath.Join(homeDir, ".explosive", "ledger")
    ldb, err := ledger.OpenLedger(ledgerPath)
    if err != nil {
        return fmt.Errorf("failed to open ledger: %w", err)
    }
    defer ldb.Close()

    // Retrieve current balance
    var fromBal ledger.Balance
    if err := ldb.GetObject([]byte("balance:"+currentWallet.Address), &fromBal); err != nil {
        // If not found, treat as zero balance
        fromBal = ledger.Balance{EXPLO: 0, IMANI: 0}
    }
    if fromBal.EXPLO < amt {
        return fmt.Errorf("insufficient EXPLO balance")
    }

    // Create a new ledger transaction
    tx, err := ledger.NewTransaction(currentWallet.Address, to, amt, 0, false)
    if err != nil {
        return fmt.Errorf("failed to create transaction: %w", err)
    }

    // Apply the transaction to the local ledger
    applyMsg, err := ldb.ApplyAndPersistTransaction(tx)
    if err != nil {
        return fmt.Errorf("failed to apply transaction to ledger: %w", err)
    }

    // Record transaction in the wallet's local history
    txRec := wallet.TxRecord{
        Timestamp: time.Now().Format(time.RFC3339),
        Type:      "SEND",
        From:      currentWallet.Address,
        To:        to,
        AmountEXP: amt,
        Note:      "EXPLO sent via Ledger",
    }
    _ = walletDB.AppendTx(txRec)

    // Sync cached balances from ledger to walletDB
    if err := SyncWalletBalances(); err != nil {
        fmt.Println("⚠️ Sent but failed to sync local cache:", err)
        fmt.Println("Ledger message:", applyMsg)
        printlnL("✅ EXPLO sent successfully.", "✅ EXPLO envoyé avec succès.")
        return nil
    }

    // Broadcast transaction to the P2P network if WalletP2P is initialized
    if walletP2P != nil {
        if err := walletP2P.BroadcastTransaction(tx); err != nil {
            return fmt.Errorf("failed to broadcast transaction: %w", err)
        }
    } else {
        log.Println("⚠️ No WalletP2P instance, transaction not broadcast to network")
    }

    // Display ledger feedback if any
    if applyMsg != "" {
        fmt.Println(applyMsg)
    }

    printlnL("✅ EXPLO sent successfully.", "✅ EXPLO envoyé avec succès.")
    return nil
}

// SyncWalletBalances refreshes the walletDB cache by reading the ledger's balance:<addr>.
func SyncWalletBalances() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot detect home directory: %w", err)
	}
	ledgerPath := filepath.Join(homeDir, ".explosive", "ledger")

	l, err := ledger.OpenLedger(ledgerPath)
	if err != nil {
		return fmt.Errorf("failed to open ledger: %w", err)
	}
	defer l.Close()

	var bal ledger.Balance
	if err := l.GetObject([]byte("balance:"+currentWallet.Address), &bal); err != nil {
		// If balance not found, treat as zero
		bal = ledger.Balance{EXPLO: 0, IMANI: 0}
	}

	// Persist updated totals to the local wallet DB (cache)
	return walletDB.SetBalance(currentWallet.Address, wallet.WalletBalance{
		EXPLO: bal.EXPLO,
		IMANI: bal.IMANI,
	})
}

// flowShowHistory displays the transaction history for the current wallet
// by scanning the canonical Ledger database (BadgerDB).
//
// Enhancements:
// - Classifies transactions into 🎉 Reward, ✅ Sent, 📥 Received.
// - Displays EXPLO, IMANI, and fees (where applicable).
// - Shows SYSTEM rewards distinctly.
// - Ensures full consistency with blockchain state.
//
// Note: IMANI is displayed but never transferable by users.
// LUMEN is intentionally excluded (shown only in mining app).
func flowShowHistory() error {
	if currentWallet == nil {
		return fmt.Errorf("no wallet loaded")
	}

	// Determine ledger path based on the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot detect home directory: %w", err)
	}
	ledgerPath := filepath.Join(homeDir, ".explosive", "ledger")

	// Open Ledger database
	ldb, err := ledger.OpenLedger(ledgerPath)
	if err != nil {
		return fmt.Errorf("failed to open ledger: %w", err)
	}
	defer ldb.Close()

	fmt.Println("=== Transaction History ===")

	found := false

	// Iterate all blocks and extract relevant transactions
	err = ldb.IterateBlocks(func(blk *ledger.Block) error {
		for _, tx := range blk.Transactions {
			if tx.From != currentWallet.Address && tx.To != currentWallet.Address {
				continue
			}
			found = true

			// Classify transaction type
			var label string
			switch {
			case tx.IsReward && tx.From == "SYSTEM":
				label = "🎉 Reward"
			case tx.From == currentWallet.Address:
				label = "✅ Sent"
			case tx.To == currentWallet.Address:
				label = "📥 Received"
			default:
				label = "🔄 Other"
			}

			// Print formatted transaction
			fmt.Printf("[%d] %s | From: %s | To: %s | EXPLO: %.4f | IMANI: %.4f | Fee: %.3f | Note: %s\n",
				tx.Timestamp,
				label,
				tx.From,
				tx.To,
				tx.AmountEXP,
				tx.AmountIM,
				tx.Fee,
				tx.Note,
			)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to scan ledger: %w", err)
	}

	if !found {
		printlnL("No history found.", "Aucun historique trouvé.")
	}

	fmt.Println("===========================")
	return nil
}

// ---------- Main menu ----------
func mainMenu() {
	for {
		updateActivity()
		printlnL("\n--- Main Menu ---", "\n--- Menu Principal ---")
		printlnL("1) Create new wallet 🆕", "1) Créer un nouveau wallet 🆕")
		printlnL("2) Restore wallet ♻️", "2) Restaurer wallet ♻️")
		printlnL("3) Show balances 💰", "3) Afficher soldes 💰")
		printlnL("4) Send EXPLO ✉️", "4) Envoyer EXPLO ✉️")
		printlnL("5) Transaction history 📜", "5) Historique des transactions 📜")
		printlnL("6) Advanced settings ⚙️", "6) Paramètres avancés ⚙️")
		printlnL("7) Exit 👋", "7) Quitter 👋")

		choice := prompt("Select (number): ")
		switch choice {
		case "1":
			if err := flowCreateWallet(); err != nil {
				fmt.Println("Error:", err)
			}
		case "2":
			if err := flowRestoreWallet(); err != nil {
				fmt.Println("Error:", err)
			}
		case "3":
			if err := requireUnlock(); err == nil {
				if err := flowShowBalances(); err != nil {
					fmt.Println("Error:", err)
				}
			}
		case "4":
			if err := requireUnlock(); err == nil {
				if err := flowSendEXPLO(); err != nil {
					fmt.Println("Error:", err)
				}
			}
		case "5":
			if err := requireUnlock(); err == nil {
				if err := flowShowHistory(); err != nil {
					fmt.Println("Error:", err)
				}
			}
		case "6":
			if err := requireUnlock(); err == nil {
				printlnL("1) Reveal Mnemonic 🧾", "1) Révéler la phrase mnemonique 🧾")
				printlnL("2) Change password 🔁", "2) Changer mot de passe 🔁")
				printlnL("3) Delete wallet 🗑️", "3) Supprimer wallet 🗑️")
				sub := prompt("Select (number): ")
				switch sub {
				case "1":
					if err := flowRevealMnemonic(); err != nil {
						fmt.Println("Error:", err)
					}
				case "2":
					if err := flowChangePassword(); err != nil {
						fmt.Println("Error:", err)
					}
				case "3":
					if err := flowDeleteWallet(); err != nil {
						fmt.Println("Error:", err)
					}
				default:
					printlnL("Unknown choice", "Choix inconnu")
				}
			}
		case "7":
			printlnL("Goodbye 👋", "Au revoir 👋")
			close(inactivityStop)
			return
		default:
			printlnL("Unknown choice", "Choix inconnu")
		}
	}
}

// ---------- main ----------
func main() {
	printlnL("🌟 Welcome To Explosive Wallet Powered by Explosive Blockchain 💥",
		"🌟 Bienvenue dans Explosive Wallet propulsé par la blockchain Explosive 💥")
	choice := prompt("1) English  2) Français  — Choose (1/2): ")
	if strings.TrimSpace(choice) == "2" {
		langEnglish = false
	}

	if err := ensureDataDir(); err != nil {
		fmt.Println("Failed to create data dir:", err)
		return
	}

	var err error
	walletDB, err = wallet.OpenDB(filepath.Join(dataDir, "walletdb"))
	if err != nil {
		fmt.Println("Failed to open wallet DB:", err)
		return
	}
	defer walletDB.Close()

	startInactivityWatcher()
	mainMenu()
}
