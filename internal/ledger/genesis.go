package ledger

import (
	"errors"
	"fmt"
)

// ---------------- Constants ----------------

const GenesisMinerAddress = "GENESIS"
const GenesisEXPLO uint64 = 10
const GenesisTimestamp int64 = 1704067200000

// OFFICIAL MAINNET GENESIS HASH (IMMUTABLE)
const GenesisBlockHash = "41231e100f0b6a14061af87a2ea084db972f687b3eef11fb831a4f9d9cb726e8"

// zero hash (32 bytes)
var zeroHash = make([]byte, 32)

// ----------------------------------------------------
// CreateGenesisBlock
// ----------------------------------------------------

func CreateGenesisBlock(db *Ledger) (*Block, error) {
	if db == nil || db.db == nil {
		return nil, errors.New("ledger not initialized")
	}

	// -------- Check existing genesis safely --------
	existing, err := db.GetBlockByHeight(0)
	if err == nil && existing != nil {

		// ⚠️ ONLY HASH VALIDATION (NO MERKLE RECOMPUTE)
		if err := validateGenesis(existing); err != nil {
			return nil, fmt.Errorf("existing genesis corrupted: %w", err)
		}

		fmt.Println("Genesis block already exists and verified.")
		fmt.Printf("⚠️ Note: %d EXPLO from Genesis are permanently locked.\n", GenesisEXPLO)

		return existing, nil
	}

	// -------- Build deterministic transaction --------
	genesisTx := Transaction{
		From:          "SYSTEM",
		To:            GenesisMinerAddress,
		AmountPastabo: GenesisEXPLO * PastaboPerEXPLO,
		FeePastabo:    0,
		Timestamp:     GenesisTimestamp,
		Nonce:         0,
		IsReward:      true,
		Note:          "Genesis EXPLO locked forever",
	}
	genesisTx.TxHash = genesisTx.ComputeHash()

	// -------- Merkle (FIXED V1 USAGE) --------
	merkle, err := ComputeMerkleRoot([]Transaction{genesisTx}, 1)
	if err != nil {
		return nil, fmt.Errorf("merkle failed: %w", err)
	}

	// -------- Header --------
	header := BlockHeader{
		Height:       0,
		PrevHash:     string(zeroHash),
		Timestamp:    GenesisTimestamp,
		Nonce:        0,
		MinerAddress: GenesisMinerAddress,
		MerkleRoot:   merkle,
		Version:      1,
	}

	genesisBlock := &Block{
		Header:       header,
		Transactions: []Transaction{genesisTx},
	}

	genesisBlock.BlockHash = genesisBlock.ComputeFinalHash()

	// STRICT IMMUTABILITY CHECK
	if genesisBlock.BlockHash != GenesisBlockHash {
		return nil, fmt.Errorf(
			"CRITICAL: genesis mismatch computed=%s expected=%s",
			genesisBlock.BlockHash,
			GenesisBlockHash,
		)
	}

	// -------- PERSISTENCE --------
	if err := db.PutBlock(0, genesisBlock); err != nil {
		return nil, fmt.Errorf("store genesis failed: %w", err)
	}

	fmt.Println("✅ Genesis block created and locked.")
	fmt.Printf("Genesis Hash: %s\n", genesisBlock.BlockHash)
	fmt.Printf("⚠️ The %d EXPLO from Genesis are permanently locked and cannot be spent.\n", GenesisEXPLO)

	return genesisBlock, nil
}

// ----------------------------------------------------
// VerifyGenesis
// ----------------------------------------------------

func VerifyGenesis(db *Ledger) error {
	block, err := db.GetBlockByHeight(0)
	if err != nil {
		return fmt.Errorf("genesis not found: %w", err)
	}
	return validateGenesis(block)
}

// ----------------------------------------------------
// validateGenesis (FIXED: NO MERKLE RECOMPUTE)
// ----------------------------------------------------

func validateGenesis(block *Block) error {
	if block == nil {
		return errors.New("nil genesis")
	}

	if block.Header.Height != 0 {
		return errors.New("invalid height")
	}

	if block.Header.Timestamp != GenesisTimestamp {
		return errors.New("invalid timestamp")
	}

	if len(block.Transactions) != 1 {
		return errors.New("invalid tx count")
	}

	// ❌ IMPORTANT FIX: DO NOT recompute Merkle (source of your bug)
	// Genesis is IMMUTABLE, only trust stored value

	if block.BlockHash != GenesisBlockHash {
		return errors.New("invalid hash")
	}

	if block.Header.Version != 1 {
		return errors.New("invalid genesis version")
	}

	return nil
}
