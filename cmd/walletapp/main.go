// cmd/walletapp/main.go
package main

import (
        "bufio"
        "crypto/rand"
        "fmt"
        "io"
        "os"
        "sort"
        "path/filepath"
        "crypto/ed25519"
        "strings"
        "sync"
        "time"

        "explosive/internal/ledger"
        "explosive/internal/encryption"
        "explosive/internal/p2p"
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
        p2pNode        *p2p.Node
)

// ---------- Utilities ----------
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

// ensureDataDir creates the data dir for wallet DB if missing
func ensureDataDir() error {
        if _, err := os.Stat(dataDir); os.IsNotExist(err) {
                return os.MkdirAll(dataDir, 0700)
        }
        return nil
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
                                        printlnL(
                                                "🔒 Locked due to inactivity. Re-enter password to continue.",
                                                "🔒 Verrouillé pour inactivité. Entrez le mot de passe pour continuer.",
                                        )
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

// ---------- Wallet flows ----------
func flowCreateWallet() error {
        printlnL("🧠 You will receive a 24-word mnemonic. Save it safely; Explosive cannot recover it.",
                "🧠 Vous recevrez une phrase mnemonique de 24 mots. Sauvegardez-la; Explosive ne peut pas la récupérer.")
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
                promptText := fmt.Sprintf("Enter word %d: ", idx+1)
                if !langEnglish {
                        promptText = fmt.Sprintf("Entrez le mot %d : ", idx+1)
                }
                ans := prompt(promptText)
                if ans != parts[idx] {
                        printlnL("❌ Mnemonic confirmation failed.", "❌ La confirmation mnemonique a échoué.")
                        return fmt.Errorf("mnemonic confirmation failed")
                }
        }

        printlnL("✅ Mnemonic confirmed.", "✅ Phrase mnemonique confirmée.")

        if !wallet.IsValidEXPLOAddress(w.Address) {
                return fmt.Errorf("invalid wallet address format")
        }

        if err := walletDB.SaveWallet(w); err != nil {
                return fmt.Errorf("failed to save wallet: %w", err)
        }

        if _, err := walletDB.GetBalance(w.Address); err != nil {
                _ = walletDB.SetBalance(w.Address, wallet.WalletBalance{EXPLO: 0, IMANI: 0})
        }

        currentWallet = w
        lockMutex.Lock()
        locked = false
        lockMutex.Unlock()
        updateActivity()

        printlnL("🎉 Wallet created successfully!", " 🎉 Wallet créé avec succès!")
        fmt.Println("📬 Address:", w.Address)
        return nil
}

func flowRestoreWallet() error {
    // Prompt user to enter their 24-word mnemonic
    printlnL("🔁 Restore your wallet by entering your 24-word mnemonic.",
             "🔁 Restaurez votre wallet en entrant votre phrase mnemonique de 24 mots.")
    mn := prompt("🧠 Enter your 24-word mnemonic: ")

    // Prompt for a strong password — only used locally for encryption of wallet file
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

    // Restore wallet object deterministically from mnemonic
    w, err := wallet.RestoreWalletByMnemonic(mn, pw)
    if err != nil {
        return fmt.Errorf("failed to restore wallet: %w", err)
    }

    // Verify the EXPLO address format
    if !wallet.IsValidEXPLOAddress(w.Address) {
        return fmt.Errorf("invalid wallet address format")
    }

    // Save wallet in local DB
    if err := walletDB.SaveWallet(w); err != nil {
        return fmt.Errorf("failed to save restored wallet: %w", err)
    }

    // Set currentWallet in memory
    currentWallet = w
    lockMutex.Lock()
    locked = false
    lockMutex.Unlock()
    updateActivity()

    // Ensure wallet has a balance record in DB
    if _, err := walletDB.GetBalance(currentWallet.Address); err != nil {
        _ = walletDB.SetBalance(currentWallet.Address, wallet.WalletBalance{EXPLO: 0, IMANI: 0})
    }

    // Sync balances from ledger
    if err := SyncWalletBalances(); err != nil {
        fmt.Println("⚠️ Failed to sync balances from ledger:", err)
    }

    // Notify user of successful restoration
    printlnL("✅ Wallet restored successfully!", "✅ Wallet restauré avec succès!")
    fmt.Println("📬 Address:", currentWallet.Address)

    return nil
}

// ---------- Wallet utilities ----------
func flowRevealMnemonic() error {
    if currentWallet == nil {
        return fmt.Errorf("no wallet loaded")
    }
    pw := prompt("Enter password to reveal mnemonic: ")
    mn, err := currentWallet.RevealMnemonic(pw)
    if err != nil {
        return fmt.Errorf("invalid password or cannot reveal: %w", err)
    }

    fmt.Println("\n--- 🧠 MNEMONIC ---")
    fmt.Println(mn)
    fmt.Println("----------------\n")
    updateActivity()
    return nil
}

func flowChangePassword() error {
    if currentWallet == nil {
        return fmt.Errorf("no wallet loaded")
    }

    old := prompt("Enter old password: ")
    _, _, err := encryption.DecryptWallet(currentWallet.EncryptedPriv, old)
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
        return fmt.Errorf("failed to save wallet after password change: %w", err)
    }

    _ = walletDB.UpdatePasswordTimestamp(currentWallet.Address, time.Now().Unix())
    printlnL("✅ Password changed successfully.", "✅ Mot de passe changé avec succès.")
    updateActivity()
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
    updateActivity()

    currentWallet = nil
    printlnL("🗑️ Wallet deleted.", "🗑️ Wallet supprimé.")
    return nil
}
// SyncWalletBalances updates walletDB cache from ledger safely
func SyncWalletBalances() error {
    if currentWallet == nil || p2pNode == nil || p2pNode.Ledger == nil {
        return fmt.Errorf("no wallet or ledger")
    }

    ldb := p2pNode.Ledger
    var bal ledger.Balance
    if err := ldb.GetObject([]byte("balance:"+currentWallet.Address), &bal); err != nil {
        // On ne fait plus de fmt.Println concurrent
        bal = ledger.Balance{EXPLO: 0, IMANI: 0}
    }

    // Verrouille uniquement pour l'accès à walletDB
    lockMutex.Lock()
    defer lockMutex.Unlock()
    if err := walletDB.SetBalance(currentWallet.Address, wallet.WalletBalance{
        EXPLO: bal.EXPLO,
        IMANI: bal.IMANI,
    }); err != nil {
        return fmt.Errorf("failed to update walletDB cache: %w", err)
    }

    return nil
}

func flowSendEXPLO() error {
    if currentWallet == nil {
        return fmt.Errorf("no wallet loaded")
    }

    // 1️⃣ Prompt recipient address and amount
    to := prompt("Recipient EXPLO address: ")
    if !wallet.IsValidEXPLOAddress(to) {
        return fmt.Errorf("invalid EXPLO address")
    }

    amtStr := prompt("Amount EXPLO: ")
    var amt float64
    _, _ = fmt.Sscan(amtStr, &amt)
    if amt <= 0 {
        return fmt.Errorf("invalid amount")
    }

    // 2️⃣ Check current balance
    lockMutex.Lock()
    ldb := p2pNode.Ledger
    var fromBal ledger.Balance
    _ = ldb.GetObject([]byte("balance:"+currentWallet.Address), &fromBal)
    lockMutex.Unlock()

    if fromBal.EXPLO < amt {
        return fmt.Errorf("insufficient EXPLO balance")
    }

    // 3️⃣ Create transaction
    tx, err := ledger.NewTransaction(currentWallet.Address, to, amt, 0.0, false, time.Now().UnixMilli())
    if err != nil {
        return fmt.Errorf("failed to create transaction: %w", err)
    }

    // 4️⃣ Prompt for wallet password to decrypt private key
    pw := prompt("Enter wallet password to sign: ")

    // 🔍 Debug before signing
    fmt.Println("🔹 Debug: signing transaction...")
    if currentWallet.EncryptedPriv == nil {
        fmt.Println("⚠️ Warning: EncryptedPriv is nil!")
    } else {
        fmt.Printf("🔹 EncryptedPriv salt len=%d, data len=%d\n",
            len(currentWallet.EncryptedPriv.Salt),
            len(currentWallet.EncryptedPriv.Data))
    }

    // 5️⃣ Sign the transaction
    sigBytes, err := wallet.SignTransaction(currentWallet, pw, tx.HashForSignature())
if err != nil {
    return fmt.Errorf("failed to sign transaction: %w", err)
}
if len(sigBytes) != ed25519.SignatureSize {
    return fmt.Errorf("signature length invalid: got %d, want %d", len(sigBytes), ed25519.SignatureSize)
}
tx.Signature = sigBytes

    // 🔑 Assign the public key so the ledger can verify the signature
    pubKeyBytes, err := currentWallet.PublicKeyBytes(pw) // decrypt and extract public key
    if err != nil {
        return fmt.Errorf("failed to get public key: %w", err)
    }
    tx.FromPubKey = pubKeyBytes

    fmt.Println("🖋️ Transaction signed by:", currentWallet.Address)
    fmt.Printf("🔏 Signature (hex): %x...\n", tx.Signature[:8])

    // 6️⃣ Apply transaction atomically
    lockMutex.Lock()
    applyMsg, err := ldb.ApplyAndPersistTransaction(tx)
    lockMutex.Unlock()
    if err != nil {
        return fmt.Errorf("failed to apply transaction: %w", err)
    }

    // 7️⃣ Broadcast transaction to network
    if p2pNode != nil {
        go func(tx *ledger.Transaction) {
            for i := 0; i < 3; i++ {
                if err := p2pNode.BroadcastTransaction(tx); err != nil {
                    time.Sleep(1 * time.Second)
                    continue
                }
                fmt.Println("🌍 Transaction broadcasted to network.")
                break
            }
        }(tx)
    }

    // 8️⃣ Save transaction locally in wallet DB
    txRecord := wallet.TxRecord{
        Timestamp: time.Now().Format(time.RFC3339),
        Type:      "SEND",
        From:      currentWallet.Address,
        To:        to,
        AmountEXP: amt,
        Note:      "EXPLO sent via Ledger + broadcasted",
    }
    lockMutex.Lock()
    _ = walletDB.AppendTx(txRecord)
    lockMutex.Unlock()

    // 9️⃣ Refresh wallet balances
    _ = SyncWalletBalances()

    if applyMsg != "" {
        fmt.Println(applyMsg)
    }

    printlnL("✅ EXPLO sent successfully and broadcast to network.",
        "✅ EXPLO envoyé et diffusé sur le réseau.")
    return nil
}
// ---------- Balances / History ----------
// ---------- Balances / History ----------
func flowShowBalances() error {
    if currentWallet == nil {
        return fmt.Errorf("no wallet loaded")
    }

    // Refresh balances from ledger
    if err := SyncWalletBalances(); err != nil {
        fmt.Println("⚠️ Warning: failed to sync balances:", err)
    }

    bal, err := walletDB.GetBalance(currentWallet.Address)
    if err != nil {
        bal = wallet.WalletBalance{EXPLO: 0, IMANI: 0}
    }

    printlnL("💰 Your balances:", "💰 Vos soldes :")
    fmt.Printf("🔹 EXPLO: %.4f\n", bal.EXPLO)
    fmt.Printf("✨ IMANI: %.4f\n", bal.IMANI)
    return nil
}

// flowShowHistory lit directement les transactions dans le Ledger local.
func flowShowHistory() error {
    if currentWallet == nil {
        return fmt.Errorf("aucun wallet chargé")
    }
    if p2pNode == nil || p2pNode.Ledger == nil {
        return fmt.Errorf("ledger non initialisé")
    }

    addr := currentWallet.Address
    l := p2pNode.Ledger

    fmt.Printf("📜 === Historique des transactions pour %s ===\n\n", addr[:12]+"...")

    txs, err := l.GetTransactionsByAddress(addr, 1, 200)
    if err != nil {
        return fmt.Errorf("erreur lecture ledger : %w", err)
    }

    if len(txs) == 0 {
        fmt.Println("❗ Aucune transaction trouvée (première utilisation ou synchronisation en cours).")
        fmt.Println("=====================================")
        return nil
    }

    // Tri du plus récent au plus ancien
    sort.Slice(txs, func(i, j int) bool {
        return txs[i].Timestamp > txs[j].Timestamp
    })

    for _, tx := range txs {
        var emoji string
        switch {
        case tx.From == "SYSTEM" && tx.IsReward:
            emoji = "⛏️ Récompense minage"
        case tx.From == addr:
            emoji = "📤 Envoyé"
        case tx.To == addr:
            emoji = "📥 Reçu"
        default:
            emoji = "🔄 Autre"
        }

        timeStr := time.UnixMilli(tx.Timestamp).Format("02/01/2006 15:04:05")

        fromShort := tx.From
        if len(fromShort) > 12 {
            fromShort = fromShort[:6] + "..." + fromShort[len(fromShort)-6:]
        }
        toShort := tx.To
        if len(toShort) > 12 {
            toShort = toShort[:6] + "..." + toShort[len(toShort)-6:]
        }

        note := tx.Note
        if note == "" {
            note = "—"
        }

        fmt.Printf("[%s] %s", timeStr, emoji)
        if tx.AmountEXP > 0 {
            fmt.Printf("  💰 %.6f EXPLO", tx.AmountEXP)
        }
        if tx.AmountIM > 0 {
            fmt.Printf("  ✨ +%.6f IMANI", tx.AmountIM)
        }
        if tx.Fee > 0 {
            fmt.Printf("  (📉 frais %.3f)", tx.Fee)
        }
        fmt.Printf("\n    👤 %s → %s\n    📝 Note : %s\n\n", fromShort, toShort, note)
    }

    fmt.Printf("📊 Total : %d transaction(s) affichée(s)\n", len(txs))
    fmt.Println("=====================================")
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

        choice := strings.TrimSpace(prompt("Select (number): "))

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
            if currentWallet == nil || p2pNode == nil || p2pNode.Ledger == nil {
                printlnL("⚠️ Wallet or Ledger not ready yet.", "⚠️ Wallet ou Ledger pas encore prêt.")
                continue
            }
            if err := flowShowBalances(); err != nil {
                fmt.Println("Error:", err)
            }
        case "4":
            if currentWallet == nil || p2pNode == nil || p2pNode.Ledger == nil {
                printlnL("⚠️ Wallet or Ledger not ready yet.", "⚠️ Wallet ou Ledger pas encore prêt.")
                continue
            }
            if err := flowSendEXPLO(); err != nil {
                fmt.Println("Error:", err)
            }
        case "5":
            if currentWallet == nil || p2pNode == nil || p2pNode.Ledger == nil {
                printlnL("⚠️ Wallet or Ledger not ready yet.", "⚠️ Wallet ou Ledger pas encore prêt.")
                continue
            }
            if err := flowShowHistory(); err != nil {
                fmt.Println("Error:", err)
            }
        case "6":
            printlnL("1) Reveal Mnemonic 🧠", "1) Révéler la phrase mnemonique 🧠")
            printlnL("2) Change password 🔁", "2) Changer mot de passe 🔁")
            printlnL("3) Delete wallet 🗑️", "3) Supprimer wallet 🗑️")
            sub := strings.TrimSpace(prompt("Select (number): "))

            switch sub {
            case "1":
                if err := flowRevealMnemonic(); err != nil {
                    fmt.Println("Error:", err)
                }
            case "2":
                if currentWallet == nil {
                    printlnL("⚠️ No wallet loaded.", "⚠️ Aucun wallet chargé.")
                    continue
                }
                if err := flowChangePassword(); err != nil {
                    fmt.Println("Error:", err)
                }
            case "3":
                if currentWallet == nil {
                    printlnL("⚠️ No wallet loaded.", "⚠️ Aucun wallet chargé.")
                    continue
                }
                if err := flowDeleteWallet(); err != nil {
                    fmt.Println("Error:", err)
                }
            default:
                printlnL("❌ Invalid choice", "❌ Choix invalide")
            }
        case "7":
            printlnL("Goodbye 👋", "Au revoir 👋")
            close(inactivityStop)
            return
        default:
            printlnL("❌ Invalid choice", "❌ Choix invalide")
        }
    }
}

// ---------- Main ----------

func main() {
        printlnL(
                "🌟 Welcome To Explosive Wallet Powered by Explosive Blockchain 💥",
                "🌟 Bienvenue dans Explosive Wallet propulsé par la blockchain Explosive 💥",
        )

        // Language selection
        choice := prompt("1) English  2) Français  — Choose (1/2): ")
        if strings.TrimSpace(choice) == "2" {
                langEnglish = false
        }

        // Create data directory
        if err := ensureDataDir(); err != nil {
                fmt.Println("❌ Failed to create data dir:", err)
                return
        }
        fmt.Println("✅ Data directory ready at", dataDir)

        // Open local wallet database
        var err error
        walletDB, err = wallet.OpenDB(filepath.Join(dataDir, "walletdb"))
        if err != nil {
                fmt.Println("❌ Failed to open wallet DB:", err)
                return
        }
        defer func() {
                _ = walletDB.Close()
                fmt.Println("🗄️ Wallet DB closed")
        }()
        fmt.Println("✅ Wallet DB opened successfully")

        // Open local ledger (single open for the whole app)
        ledgerPath := filepath.Join(homeDir, ".explosive", "ledger")
        ldb, err := ledger.OpenLedger(ledgerPath)
        if err != nil {
                fmt.Println("❌ Failed to open ledger:", err)
                return
        }
        defer func() {
                _ = ldb.Close()
                fmt.Println("🗄️ Ledger closed")
        }()
        fmt.Println("✅ Ledger opened successfully at", ledgerPath)

        // Start P2P node
        p2pNode = p2p.NewNode(":9101", "explosive-mainnet", "ExplosiveWallet/1.0")
        if err := p2pNode.Start(); err != nil {
                fmt.Println("❌ Failed to start P2P node:", err)
                return
        }
        defer func() {
                p2pNode.Stop()
                fmt.Println("🛑 P2P Node stopped")
        }()
        fmt.Println("✅ P2P Node started on port :9101")

        // Attach ledger to P2P node
        p2pNode.Ledger = ldb
        fmt.Println("✅ Ledger attached to P2P node")

        // Start inactivity watcher
        startInactivityWatcher()
        fmt.Println("✅ Inactivity watcher running")

        fmt.Printf("ℹ️ Ready. WalletDB=%s Ledger=%s P2PAddr=%s\n", filepath.Join(dataDir, "walletdb"), ledgerPath, ":9101")

        // Launch main menu
        mainMenu()

        fmt.Println("👋 Exiting wallet application. Goodbye.")
}
