package imanifund

import (
	"errors"
	"fmt"
	"log"

	"explosive/internal/guardian"
)

const (
	// Eligibility bounds (UX layer only — never consensus critical)
	MinLumenEligible = 15.0
	MaxLumenAllowed  = 50.0

	// Fixed sacred reward per redistribution round (EXPLO — human readable)
	RewardPerMiner = 1.0
)

//
// ─────────────────────────────────────────────────────────────
// LedgerAdapter Interface
// ─────────────────────────────────────────────────────────────
//
// IMPORTANT PRINCIPLE:
// This interface speaks ONLY in EXPLO (float64).
// It is UX-level communication.
// The Ledger implementation is responsible for converting
// EXPLO → Pastabo internally for consensus safety.
//

type LedgerAdapter interface {
	AddTransaction(tx TransactionLite) error

	// All values below are expressed in EXPLO (human readable layer)
	GetIMANIPool() float64
	DeductIMANIPool(amount float64) error

	GetEligibleMinersRange(minLumen, maxLumen float64) []string
	GetTotalReceivedFromIMANI(minerID string) float64
}

//
// ─────────────────────────────────────────────────────────────
// TransactionLite — UX-Level Transaction
// ─────────────────────────────────────────────────────────────
//
// Amount is expressed in EXPLO (float64).
// Conversion to Pastabo happens inside the Ledger.
//

type TransactionLite struct {
	Type    string
	From    string
	To      string
	Amount  float64 // EXPLO (human layer)
	Message string
}

//
// ─────────────────────────────────────────────────────────────
// AddDonation
// ─────────────────────────────────────────────────────────────
// Adds EXPLO donation into IMANI pool (UX layer).
//

func AddDonation(minerID string, amount float64, db LedgerAdapter) error {
	if amount <= 0 {
		return errors.New("invalid donation amount")
	}

	tx := TransactionLite{
		Type:    "IMANI_DONATION",
		From:    minerID,
		To:      "IMANI_POOL",
		Amount:  amount, // EXPLO
		Message: fmt.Sprintf("IMANI donation by %s", shortID(minerID)),
	}

	if err := db.AddTransaction(tx); err != nil {
		return fmt.Errorf("IMANI donation failed: %w", err)
	}

	log.Printf("⛑️ IMANI FUND +%.6f EXPLO from %s", amount, shortID(minerID))
	return nil
}

//
// ─────────────────────────────────────────────────────────────
// RegisterLumen
// ─────────────────────────────────────────────────────────────
// Stores LUMEN value (UX symbolic layer only).
//

func RegisterLumen(minerID string, lumen float64, db LedgerAdapter) error {
	if lumen < 0 {
		return errors.New("invalid lumen value")
	}

	tx := TransactionLite{
		Type:    "LUMEN_REGISTER",
		From:    minerID,
		To:      minerID,
		Amount:  0,
		Message: fmt.Sprintf("LUMEN update %.2f", lumen),
	}

	if err := db.AddTransaction(tx); err != nil {
		return fmt.Errorf("LUMEN register failed: %w", err)
	}

	return nil
}

//
// ─────────────────────────────────────────────────────────────
// DistributeRewards
// ─────────────────────────────────────────────────────────────
//
// Sacred redistribution logic (UX layer).
// All arithmetic is in EXPLO (float64).
// Ledger enforces real supply & Pastabo safety.
//

func DistributeRewards(db LedgerAdapter) error {
	donpool := db.GetIMANIPool() // EXPLO

	if donpool < RewardPerMiner {
		return nil
	}

	miners := db.GetEligibleMinersRange(MinLumenEligible, MaxLumenAllowed)
	count := len(miners)
	if count == 0 {
		return nil
	}

	required := float64(count) * RewardPerMiner
	if donpool < required {
		return nil
	}

	for _, minerID := range miners {
		tx := TransactionLite{
			Type:    "IMANI_REWARD",
			From:    "IMANI_POOL",
			To:      minerID,
			Amount:  RewardPerMiner, // EXPLO
			Message: "IMANI blessing",
		}

		if err := db.AddTransaction(tx); err != nil {
			log.Printf("⚠️ IMANI reward failed for %s: %v", shortID(minerID), err)
			continue
		}

		msg := guardian.EncourageMessageEphemeral([]string{
			"blessing", "gratitude", "unity", "light", "sacred",
		})

		log.Printf("✨ IMANI → %s +1 EXPLO | %s", shortID(minerID), msg)
	}

	// Deduct in EXPLO (ledger converts internally)
	if err := db.DeductIMANIPool(required); err != nil {
		log.Printf("⚠️ Failed to deduct IMANI pool: %v", err)
	}

	return nil
}

//
// ─────────────────────────────────────────────────────────────
// GetSoulGift
// ─────────────────────────────────────────────────────────────
// Returns total EXPLO received via IMANI blessings.
//

func GetSoulGift(minerID string, db LedgerAdapter) float64 {
	return db.GetTotalReceivedFromIMANI(minerID)
}

//
// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
//

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
