// cmd/ledgerapp/main.go
package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"explosive/internal/address"
	"explosive/internal/guardian"
	"explosive/internal/ledger"
	"explosive/internal/p2p"
	"explosive/internal/scan"
)

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
