// internal/p2p/walletp2p.go
package p2p

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"explosive/internal/address"
	"explosive/internal/ledger"

	"github.com/fxamacker/cbor/v2"
)

// WalletP2P manages wallet-to-P2P synchronization with Ed25519 signing.
type WalletP2P struct {
	Node          *Node
	WalletAddress string
	KnownPeers    []string

	txQueues      [2]chan *ledger.Transaction
	blockQueue    chan *ledger.Block
	appliedTxs    sync.Map
	appliedBlocks sync.Map
	blockBuffer   sync.Map

	stopCh      chan struct{}
	workerCount int
	batchSize   int

	privateKey ed25519.PrivateKey // used only for signing transactions
}

// ---------------- Transaction Helpers ----------------

// LocalTransaction embeds ledger.Transaction to add helper methods
type LocalTransaction struct {
	*ledger.Transaction
}

// HashForSignature generates deterministic bytes to sign for the transaction
func HashForSignature(tx *ledger.Transaction) []byte {
	data := fmt.Sprintf("%s|%s|%f|%f|%f|%d", tx.From, tx.To, tx.AmountEXP, tx.AmountIM, tx.Fee, tx.Timestamp)
	return []byte(data)
}

// ID returns a unique ID for the transaction (using SHA256 of signature hash)
func ID(tx *ledger.Transaction) string {
	h := sha256.Sum256(HashForSignature(tx))
	return hex.EncodeToString(h[:])
}

// ---------------- Constructor ----------------

func NewWalletP2P(walletAddr string, privKey ed25519.PrivateKey, knownPeers []string, workers int, batchSize int) (*WalletP2P, error) {
	node, err := ConnectWalletToP2P(walletAddr, knownPeers)
	if err != nil {
		return nil, err
	}

	w := &WalletP2P{
		Node:          node,
		WalletAddress: walletAddr,
		KnownPeers:    knownPeers,
		txQueues:      [2]chan *ledger.Transaction{make(chan *ledger.Transaction, 250_000), make(chan *ledger.Transaction, 250_000)},
		blockQueue:    make(chan *ledger.Block, 50_000),
		stopCh:        make(chan struct{}),
		workerCount:   workers,
		batchSize:     batchSize,
		privateKey:    privKey,
	}

	node.RegisterHandler(MsgTypeTx, w.handleTxEnvelopeCBOR)
	node.RegisterHandler(MsgTypeBlock, w.handleBlockEnvelopeCBOR)

	for i := 0; i < workers; i++ {
		go w.txWorker()
		go w.blockWorker()
	}

	return w, nil
}

// ---------------- Broadcast Transaction ----------------

func (w *WalletP2P) BroadcastTransaction(tx *ledger.Transaction) error {
	if tx.From != "SYSTEM" {
		tx.Signature = ed25519.Sign(w.privateKey, HashForSignature(tx))
		tx.FromPubKey = w.privateKey.Public().(ed25519.PublicKey)
	}

	payload, err := cbor.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal CBOR transaction: %w", err)
	}

	env, err := NewEnvelopeFromPayload(w.Node.protocolVersion, MsgTypeTx, payload)
	if err != nil {
		return err
	}

	w.Node.Broadcast(env)
	return nil
}

// ---------------- Transaction Handling ----------------

func (w *WalletP2P) handleTxEnvelopeCBOR(_ *Peer, env *Envelope) {
	var tx ledger.Transaction
	if err := cbor.Unmarshal(env.Payload, &tx); err != nil {
		log.Printf("⚠️ Failed to unmarshal CBOR Tx: %v", err)
		return
	}

	if tx.From != "SYSTEM" {
		if !address.IsValidEXPLOAddress(tx.From) || tx.FromPubKey == nil || !ed25519.Verify(tx.FromPubKey, HashForSignature(&tx), tx.Signature) {
			log.Printf("⚠️ Invalid transaction signature from %s", tx.From)
			return
		}
	}

	if !address.IsValidEXPLOAddress(tx.To) {
		return
	}

	idx := 1
	if tx.From == "SYSTEM" {
		idx = 0
	}

	select {
	case w.txQueues[idx] <- &tx:
	default:
		log.Printf("⚠️ Tx queue full, dropping transaction %s -> %s", tx.From, tx.To)
	}
}

// ---------------- Block Handling ----------------

func (w *WalletP2P) handleBlockEnvelopeCBOR(_ *Peer, env *Envelope) {
	var blk ledger.Block
	if err := cbor.Unmarshal(env.Payload, &blk); err != nil {
		log.Printf("⚠️ Failed to unmarshal CBOR block: %v", err)
		return
	}

	select {
	case w.blockQueue <- &blk:
	default:
		w.blockBuffer.Store(blk.Header.Height, &blk)
		log.Printf("⚠️ Block queue full, buffering block height=%d hash=%s", blk.Header.Height, blk.BlockHash)
	}
}

// ---------------- Workers ----------------

func (w *WalletP2P) txWorker() {
	batch := make([]*ledger.Transaction, 0, w.batchSize)
	for {
		select {
		case <-w.stopCh:
			return
		default:
			batch = batch[:0]

			// SYSTEM tx first
		loopSys:
			for i := 0; i < w.batchSize; i++ {
				select {
				case tx := <-w.txQueues[0]:
					batch = append(batch, tx)
				default:
					break loopSys
				}
			}

			// normal tx
			for i := len(batch); i < w.batchSize; i++ {
				select {
				case tx := <-w.txQueues[1]:
					batch = append(batch, tx)
				default:
					break
				}
			}

			for _, tx := range batch {
				w.applyTx(tx)
			}

			if len(batch) == 0 {
				time.Sleep(100 * time.Microsecond)
			}
		}
	}
}

func (w *WalletP2P) applyTx(tx *ledger.Transaction) {
	if _, loaded := w.appliedTxs.LoadOrStore(ID(tx), struct{}{}); loaded {
		return
	}

	if w.Node.Ledger != nil {
		if _, err := w.Node.Ledger.ApplyAndPersistTransaction(tx); err != nil {
			log.Printf("⚠️ Failed to apply transaction: %v", err)
			w.appliedTxs.Delete(ID(tx))
		}
	}
}

func (w *WalletP2P) blockWorker() {
	for {
		select {
		case <-w.stopCh:
			return
		case blk := <-w.blockQueue:
			w.applyBlock(blk)
			w.processBufferedBlocks()
		}
	}
}

func (w *WalletP2P) applyBlock(blk *ledger.Block) {
	if _, loaded := w.appliedBlocks.LoadOrStore(blk.BlockHash, struct{}{}); loaded {
		return
	}

	if err := applyBlockAtomically(w.Node.Ledger, blk); err != nil {
		log.Printf("⚠️ Failed to apply block: %v", err)
		w.appliedBlocks.Delete(blk.BlockHash)
		return
	}

	log.Printf("✅ Applied block height=%d hash=%s txCount=%d", blk.Header.Height, blk.BlockHash, len(blk.Transactions))
}

func (w *WalletP2P) processBufferedBlocks() {
	prevHash := getPrevBlockHash(w.Node.Ledger)
	w.blockBuffer.Range(func(key, value interface{}) bool {
		blk := value.(*ledger.Block)
		if blk.Header.PrevHash == prevHash {
			w.applyBlock(blk)
			w.blockBuffer.Delete(key)
		}
		return true
	})
}

// ---------------- Helpers ----------------

func applyBlockAtomically(l *ledger.Ledger, blk *ledger.Block) error {
	if l == nil {
		return fmt.Errorf("ledger is nil")
	}

	// Optional PrevHash check
	last := getLastBlock(l)
	if last != nil && blk.Header.PrevHash != last.BlockHash {
		return fmt.Errorf("block PrevHash mismatch: expected %s, got %s", last.BlockHash, blk.Header.PrevHash)
	}

	// Apply all transactions
	for _, tx := range blk.Transactions {
		if _, err := l.ApplyAndPersistTransaction(&tx); err != nil {
			return fmt.Errorf("failed to apply tx %s: %w", ID(&tx), err)
		}
	}

	return nil
}

func getPrevBlockHash(l *ledger.Ledger) string {
	last := getLastBlock(l)
	if last != nil {
		return last.BlockHash
	}
	return ""
}

func getLastBlock(l *ledger.Ledger) *ledger.Block {
	height := l.GetLatestBlockHeight()
	if height == 0 {
		return nil
	}
	blk, _ := l.GetBlockByHeight(height)
	return blk
}

// ---------------- Stop ----------------

func (w *WalletP2P) Stop() {
	close(w.stopCh)
	if w.Node != nil {
		w.Node.Stop()
	}
}
