// internal/types/types.go
package types

import (
    "explosive/internal/ledger"
)

type P2PNode interface {
    BroadcastBlockInv(blockHash []byte, kind string)
}

type LedgerInterface interface {
    GetLatestBlock() (*ledger.Block, error)
    ApplyBlock(blk *ledger.Block) error
}
