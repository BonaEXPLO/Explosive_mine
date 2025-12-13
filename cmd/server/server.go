// cmd/server/server.go
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"time"

	"explosive/internal/address"
	"explosive/internal/ledger"
	"explosive/internal/p2p"
)

// Simple server that exposes a minimal, safe API over your existing node/ledger.
// It avoids using methods that don't exist in your codebase and uses only
// ledger/p2p functions discovered in your repo.

var p2pNode *p2p.Node

// jsonResponse writes JSON with a content-type header.
func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// allow all origins for local/testing; lock in production
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(data)
}

// -------------------- STATUS --------------------
// Returns whether the node is up and the latest block height available.
// We avoid calling methods that didn't exist in your tree (node.ID()).
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if p2pNode == nil || p2pNode.Ledger == nil {
		jsonResponse(w, map[string]interface{}{"online": false})
		return
	}

	latest := uint64(0)
	// GetLatestBlockHeight exists in internal/ledger/block.go
	latest = p2pNode.Ledger.GetLatestBlockHeight()

	jsonResponse(w, map[string]interface{}{
		"online":       true,
		"latest_block": latest,
		"timestamp":    time.Now().Unix(),
	})
}

// -------------------- BROADCAST SIGNED TRANSACTIONS --------------------

// handleBroadcast expects a fully-signed ledger.Transaction JSON body (client signs locally).
// This endpoint will verify signature and then broadcast the tx to peers.
func handleBroadcast(w http.ResponseWriter, r *http.Request) {
	if p2pNode == nil || p2pNode.Ledger == nil {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "node not initialized"})
		return
	}

	var tx ledger.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "invalid transaction JSON"})
		return
	}

	// Basic address validation using address package
	if !address.IsValidMinerID(tx.From) || !address.IsValidMinerID(tx.To) {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "invalid explo address (from/to)"})
		return
	}

	// Signature verification inline (your ledger.Transaction doesn't have VerifySignature())
	if tx.From != "SYSTEM" {
		if tx.FromPubKey == nil || tx.Signature == nil {
			jsonResponse(w, map[string]interface{}{"success": false, "message": "missing pubkey or signature"})
			return
		}
		// Use the canonical bytes used by ledger.HashForSignature()
		msg := tx.HashForSignature()
		if !ed25519.Verify(tx.FromPubKey, msg, tx.Signature) {
			jsonResponse(w, map[string]interface{}{"success": false, "message": "invalid signature"})
			return
		}
	}

	// Prevent trivial replay at the API level (nonce check simple)
	// Note: the ledger will do deeper validation on ApplyAndPersistTransaction.
	if tx.Nonce == 0 {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "missing nonce"})
		return
	}

	// Broadcast to p2p network (BroadcastTransaction takes *ledger.Transaction)
	p2pNode.BroadcastTransaction(&tx)

	jsonResponse(w, map[string]interface{}{"success": true, "tx_hash": tx.TxHash, "message": "broadcasted"})
}

// -------------------- HISTORY --------------------

// handleHistory returns transactions for a given address by using the ledger function already present.
func handleHistory(w http.ResponseWriter, r *http.Request) {
	if p2pNode == nil || p2pNode.Ledger == nil {
		jsonResponse(w, []string{})
		return
	}
	addr := r.URL.Query().Get("address")
	if addr == "" || !address.IsValidMinerID(addr) {
		jsonResponse(w, []string{})
		return
	}

	txs, err := p2pNode.Ledger.GetTransactionsByAddress(addr, 1, 200)
	if err != nil {
		jsonResponse(w, []string{})
		return
	}
	// sort descending by timestamp
	sort.Slice(txs, func(i, j int) bool { return txs[i].Timestamp > txs[j].Timestamp })

	jsonResponse(w, txs)
}

// -------------------- BALANCE --------------------

// handleBalance uses Ledger.GetGlobalBalances (found in your codebase) and returns the entry for addr.
func handleBalance(w http.ResponseWriter, r *http.Request) {
	if p2pNode == nil || p2pNode.Ledger == nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "node not ready"})
		return
	}
	addr := r.URL.Query().Get("address")
	if addr == "" || !address.IsValidMinerID(addr) {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "invalid address"})
		return
	}

	glob, err := p2pNode.Ledger.GetGlobalBalances()
	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "error": "failed to read balances"})
		return
	}

	if v, ok := glob[addr]; ok {
		jsonResponse(w, map[string]interface{}{"success": true, "address": addr, "balance": v})
		return
	}
	jsonResponse(w, map[string]interface{}{"success": false, "error": "address not found"})
}

// -------------------- CUSTOM PAYLOAD --------------------

func handleBroadcastCustom(w http.ResponseWriter, r *http.Request) {
	if p2pNode == nil {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "node not ready"})
		return
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "message": "invalid json"})
		return
	}
	env, err := p2p.NewEnvelopeFromPayload(p2pNode.ProtocolVersion(), p2p.MsgTypeCustomData, payload)
	if err != nil {
		jsonResponse(w, map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	p2pNode.BroadcastEnvelope(env)
	jsonResponse(w, map[string]interface{}{"success": true, "message": "custom payload broadcasted"})
}

// -------------------- MAIN --------------------

func main() {
	// create node (NewNode signature in your code: NewNode(local, bootstrap, nodeName, ...)
	// adjust parameters below to what your NewNode expects. From your earlier code you called:
	// p2p.NewNode("0.0.0.0:9101", "51.21.180.138:443", "mainnet-server")
	p2pNode = p2p.NewNode("0.0.0.0:9101", "51.21.180.138:443", "mainnet-server")

	// static UI (served from ./cmd/server/ui)
	fs := http.FileServer(http.Dir("./cmd/server/ui"))
	http.Handle("/", fs)

	// API
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/tx/broadcast", handleBroadcast)   // client MUST sign locally
	http.HandleFunc("/api/tx/history", handleHistory)
	http.HandleFunc("/api/balance", handleBalance)
	http.HandleFunc("/api/custom", handleBroadcastCustom)

	log.Println("EXPLOSIVE WALLET server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
