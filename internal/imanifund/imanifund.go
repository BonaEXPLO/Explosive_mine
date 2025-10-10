// internal/imanifund/imanifund.go
package imanifund

import (
	"errors"
	"fmt"
	"sync"

	"explosive/internal/guardian"
)

var (
	mu sync.Mutex

	// donpool accumulates donated EXPLO tokens and transaction fees
	donpool float64

	// balances stores redistributed EXPLO per miner ID
	balances = map[string]float64{}

	// lumenRecords keeps track of miner LUMEN values for eligibility
	lumenRecords = map[string]float64{}
)

// AddDonation adds a voluntary donation (EXPLO) or transaction fee to the pool.
// minerID: donor miner's ID
func AddDonation(minerID string, amount float64) error {
	if amount <= 0 {
		return errors.New("donation amount must be positive")
	}

	mu.Lock()
	defer mu.Unlock()

	// Add EXPLO donation/fee to pool
	donpool += amount

	fmt.Printf("💰 %.3f EXPLO added to donpool by %s. Current donpool: %.3f EXPLO\n",
		amount, minerID, donpool)

	return nil
}

// RegisterLumen updates the LUMEN record for a miner
func RegisterLumen(minerID string, lumen float64) {
	mu.Lock()
	defer mu.Unlock()
	lumenRecords[minerID] = lumen
}

// DistributeDonations distributes the donpool (EXPLO) to miners with >=15 LUMEN
// Each eligible miner receives an equal share of EXPLO
func DistributeDonations() {
	mu.Lock()
	defer mu.Unlock()

	if donpool < 1000.0 {
		// not enough in donpool yet
		return
	}

	// Collect eligible miners
	var eligible []string
	for id, lumen := range lumenRecords {
		if lumen >= 15.0 {
			eligible = append(eligible, id)
		}
	}

	if len(eligible) == 0 {
		// no eligible miners, keep donpool intact
		return
	}

	// Calculate fair share of EXPLO
	shareEXPLO := donpool / float64(len(eligible))

	for _, id := range eligible {
		balances[id] += shareEXPLO

		msg := guardian.EncourageMessageEphemeral([]string{"solidarity", "sharing", "trust", "reward"})
		fmt.Printf("🏆 Miner %s received %.3f EXPLO from donpool. Guardian: %s\n",
			id, shareEXPLO, msg)
	}

	// Reset donpool after distribution
	donpool = 0
}

// GetBalance returns the redistributed EXPLO balance of a miner
func GetBalance(minerID string) float64 {
	mu.Lock()
	defer mu.Unlock()
	return balances[minerID]
}

// GetDonpool returns current total in donpool (EXPLO)
func GetDonpool() float64 {
	mu.Lock()
	defer mu.Unlock()
	return donpool
}
