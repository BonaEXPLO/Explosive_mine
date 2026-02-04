package common


type P2PNode interface {
    BroadcastBlockInv(blockHash []byte, kind string)
}
