// internal/imanifund/imanifund.go
// IMANI FUND — The Sacred Heart of EXPLOSIVE
//
// IMANI is NOT an economic token.
// IMANI is the spiritual fingerprint — proof of consciousness, presence, and soul alignment.
// It is non-transferable, non-speculative, and will never be listed on any exchange.
//
// Its sole purpose: to grant access to the sacred redistribution of the IMANI Fund.
// EXPLO remains the only economic, transferable token in the ecosystem.
//
// This module is fully persistent, crash-resilient, and runs automatically.
// All donations, soul gifts, and LUMEN records survive node restarts.

package imanifund

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"explosive/internal/guardian"
)

const (
	// Persistent state file — the sacred ledger of the IMANI Fund
	stateFile = "data/imanifund/sacred_state.cbor"

	// Base threshold: minimum EXPLO required to trigger a sacred blessing
	baseThreshold = 1000.0
	// Maximum threshold cap — ensures frequent redistribution at global scale
	maxThreshold = 10000.0
)

// SacredState represents the persistent, on-disk state of the IMANI Fund
type SacredState struct {
	Donpool      float64            `cbor:"donpool_exp"`         // Total EXPLO donated to the sacred fund
	SoulGifts    map[string]float64 `cbor:"soul_gifts"`          // Total EXPLO received by each soul via blessings
	SoulLumen    map[string]float64 `cbor:"soul_lumen"`          // Latest recorded LUMEN value per miner
	LastBlessing int64              `cbor:"last_blessing_unix"`  // Unix timestamp of the last redistribution
}

// Callback injected by ledger at startup to credit EXPLO to a miner
var CreditSoul func(minerID string, amount float64) error

var (
	mu    sync.Mutex
	state *SacredState
)

// Init must be called once at node startup.
// Loads the sacred state from disk (or initializes it) and starts the automatic distributor.
func Init(creditFunc func(string, float64) error) error {
	CreditSoul = creditFunc

	// Ensure persistence directory exists
	if err := os.MkdirAll(filepath.Dir(stateFile), 0755); err != nil {
		return err
	}

	state = &SacredState{
		SoulGifts:    make(map[string]float64),
		SoulLumen:    make(map[string]float64),
	}

	// Load existing sacred state if present
	if data, err := os.ReadFile(stateFile); err == nil {
		if err := cbor.Unmarshal(data, state); err != nil {
			return errors.New("corrupted sacred IMANI state file")
		}
		log.Printf("Sacred IMANI Fund loaded — %.3f EXPLO awaiting blessing", state.Donpool)
	} else if !os.IsNotExist(err) {
		return err
	}

	// Start the eternal heartbeat of redistribution
	go sacredDistributor()
	return nil
}

// persist writes the current sacred state to disk (idempotent, atomic-safe)
func persist() {
	data, _ := cbor.Marshal(state)
	_ = os.WriteFile(stateFile, data, 0644)
}

// AddDonation — Compatible avec ton mine.go actuel
func AddDonation(minerID string, amount float64) error {
	return AddToSacredFund(minerID, amount)
}

// RegisterLumen — Compatible avec ton mine.go actuel
func RegisterLumen(minerID string, lumen float64) {
	RegisterSoulLumen(minerID, lumen)
}

// AddToSacredFund records a voluntary donation or transaction fee into the sacred pool.
// Only EXPLO is accepted — IMANI remains immaterial.
func AddToSacredFund(minerID string, amount float64) error {
	if amount <= 0 {
		return errors.New("invalid offering amount")
	}

	mu.Lock()
	defer mu.Unlock()

	state.Donpool += amount
	persist()

	log.Printf("Sacred offering: %.4f EXPLO from %s → IMANI Fund = %.4f EXPLO",
		amount, minerID[:12], state.Donpool)
	return nil
}

// RegisterSoulLumen records the current LUMEN value of a miner.
// Used to determine eligibility for sacred blessings (LUMEN ≥ 15).
func RegisterSoulLumen(minerID string, lumen float64) {
	mu.Lock()
	defer mu.Unlock()
	state.SoulLumen[minerID] = lumen
	persist()
}

// GetSoulGift returns the total EXPLO a soul has received from past blessings.
func GetSoulGift(minerID string) float64 {
	mu.Lock()
	defer mu.Unlock()
	return state.SoulGifts[minerID]
}

// sacredDistributor runs forever, checking every 10 minutes for a blessing opportunity.
func sacredDistributor() {
	for {
		time.Sleep(10 * time.Minute)
		blessThePure()
	}
}

// blessThePure performs the sacred redistribution when conditions are met.
// Dynamic threshold ensures fairness as the network grows.
func blessThePure() {
	mu.Lock()
	defer mu.Unlock()

	// Dynamic sacred threshold based on network size
	minerCount := len(state.SoulLumen)
	threshold := baseThreshold
	if minerCount > 1000 {
		threshold = baseThreshold + float64(minerCount-1000)*0.5
		if threshold > maxThreshold {
			threshold = maxThreshold
		}
	}

	if state.Donpool < threshold || CreditSoul == nil {
		return
	}

	// Identify pure souls (LUMEN ≥ 15)
	var pureSouls []string
	for id, lumen := range state.SoulLumen {
		if lumen >= 15.0 {
			pureSouls = append(pureSouls, id)
		}
	}

	if len(pureSouls) == 0 {
		return
	}

	gift := state.Donpool / float64(len(pureSouls))

	for _, soul := range pureSouls {
		state.SoulGifts[soul] += gift
		if err := CreditSoul(soul, gift); err != nil {
			log.Printf("Failed to credit soul %s: %v", soul[:12], err)
		} else {
			msg := guardian.EncourageMessageEphemeral([]string{
				"blessing", "gratitude", "unity", "light", "sacred",
			})
			log.Printf("IMANI BLESSING → %s receives %.5f EXPLO | LUMEN=%.2f | %s",
				soul[:12], gift, state.SoulLumen[soul], msg)
		}
	}

	log.Printf("SACRED REDEMPTION — %.3f EXPLO shared among %d pure souls", state.Donpool, len(pureSouls))

	// Reset the sacred pool
	state.Donpool = 0
	state.LastBlessing = time.Now().Unix()
	persist()
}
