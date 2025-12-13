package ledger

import (
    "errors"
    "fmt"
)

// ==========================================================
// EXPLOSIVE NETWORK — MAINNET GENESIS BLOCK DEFINITION
// ==========================================================

// GenesisMinerAddress is the fixed address for the genesis block.
const GenesisMinerAddress = "GENESIS"

// GenesisEXPLO is the amount of EXPLO allocated in the genesis block.
const GenesisEXPLO = 10 // Locked forever

// GenesisTimestamp is the fixed UTC timestamp for the genesis block (2024-01-01 00:00:00).
const GenesisTimestamp int64 = 1704067200000

// GenesisHash is the canonical hash of the genesis block used across the network.
const GenesisHash = "45beb1aa8e01fb8dcda83df071abbe4d0431be141a9394b76a82a1830fd20825"

// CreateGenesisBlock initializes the blockchain with the immutable genesis block.
// It will only create the block if it does not exist, and will always force the canonical hash.
func CreateGenesisBlock(db *Ledger) (*Block, error) {
    if db == nil || db.db == nil {
        return nil, fmt.Errorf("ledger not initialized")
    }

    // Check if genesis block already exists
    existing, err := db.GetBlockByHeight(0)
    if err == nil && existing != nil {
        if existing.BlockHash != GenesisHash {
            return nil, errors.New("invalid genesis block hash — possible chain corruption")
        }
        fmt.Println("✅ Genesis block already exists and hash verified.")
        return existing, nil
    }

    // Build the deterministic genesis transaction
    genesisTx := Transaction{
        From:      "SYSTEM",
        To:        GenesisMinerAddress,
        AmountEXP: GenesisEXPLO,
        AmountIM:  0,
        Fee:       0,
        Timestamp: GenesisTimestamp,
        IsReward:  true,
        Note:      "🔒 Genesis EXPLO locked forever",
    }

    // Compute Merkle root deterministically
    merkle := ComputeMerkleRoot([]Transaction{genesisTx})

    // Build the block header
    header := BlockHeader{
        Height:       0,
        PrevHash:     "",
        Timestamp:    GenesisTimestamp,
        Nonce:        0,
        MinerAddress: GenesisMinerAddress,
        MerkleRoot:   merkle,
    }

    // Assemble the genesis block
    genesisBlock := &Block{
        Header:       header,
        Transactions: []Transaction{genesisTx},
        BlockHash:    GenesisHash, // Force canonical hash
    }

    // Store the block in the ledger
    if err := db.StoreBlockBatch(genesisBlock); err != nil {
        return nil, fmt.Errorf("failed to store genesis block: %v", err)
    }
    if err := db.ForceFlushBlocks(); err != nil {
        return nil, fmt.Errorf("failed to flush genesis block: %v", err)
    }

    fmt.Printf("⚡ Genesis block created: %d EXPLO locked forever\n", GenesisEXPLO)
    return genesisBlock, nil
}

// VerifyGenesis ensures that the stored genesis block matches the network specification.
func VerifyGenesis(db *Ledger) error {
    if db == nil || db.db == nil {
        return fmt.Errorf("ledger not initialized")
    }

    block, err := db.GetBlockByHeight(0)
    if err != nil {
        return fmt.Errorf("unable to load genesis block: %v", err)
    }
    if block == nil {
        return fmt.Errorf("genesis block missing")
    }

    // Check canonical hash
    if block.BlockHash != GenesisHash {
        return fmt.Errorf("genesis hash mismatch — expected %s, found %s", GenesisHash, block.BlockHash)
    }

    // Verify block structure
    if block.Header.MinerAddress != GenesisMinerAddress || len(block.Transactions) != 1 {
        return fmt.Errorf("invalid genesis block structure")
    }

    tx := block.Transactions[0]
    if tx.To != GenesisMinerAddress || tx.AmountEXP != GenesisEXPLO || tx.Timestamp != GenesisTimestamp {
        return fmt.Errorf("invalid genesis transaction data")
    }

    fmt.Println("✅ Genesis block integrity verified.")
    return nil
}
