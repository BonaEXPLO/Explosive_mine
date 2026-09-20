package p2p

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// refreshNATCandidates discovers the network paths currently available
// on the local device.
//
// Network candidates are temporary locators. They never replace the
// permanent wallet-linked PeerID.
//
// This first stage discovers local LAN/private IPv4 and IPv6 candidates.
// Reflexive NAT discovery and relay candidates are added later.
func (n *Node) refreshNATCandidates() error {
	if n == nil {
		return errors.New("nil P2P node")
	}

	port := n.listenPort()
	if port == 0 {
		return errors.New("cannot determine P2P listen port")
	}

	candidates, err := DiscoverLocalCandidates(port)
	if err != nil {
		return fmt.Errorf("local network candidate discovery failed: %w", err)
	}

	n.natCandidatesMu.Lock()
	n.natCandidates = append(n.natCandidates[:0], candidates...)
	n.natCandidatesMu.Unlock()
	n.logNATCandidates()

	for _, candidate := range candidates {
		log.Printf(
			"[p2p] 🌐 local network candidate: type=%d addr=%s priority=%d",
			candidate.Type,
			candidate.Addr(),
			candidate.Priority,
		)
	}

	if len(candidates) == 0 {
		log.Printf("[p2p] 🌐 no usable local network candidates discovered")
	}

	return nil
}

// NATCandidates returns a snapshot of the currently known local
// network candidates.
//
// The returned slice is independent from the node's internal state.
func (n *Node) NATCandidates() []NATCandidate {
	if n == nil {
		return nil
	}

	n.natCandidatesMu.RLock()
	defer n.natCandidatesMu.RUnlock()

	if len(n.natCandidates) == 0 {
		return nil
	}

	result := make([]NATCandidate, len(n.natCandidates))
	copy(result, n.natCandidates)

	return result
}

// listenPort extracts the TCP listening port from the node's configured
// listen address.
//
// The listen address is transport information only and is never used
// as the permanent node identity.
func (n *Node) listenPort() uint16 {
	if n == nil {
		return 0
	}

	_, portStringValue, err := net.SplitHostPort(
		strings.TrimSpace(n.listenAddr),
	)
	if err != nil {
		return 0
	}

	port, err := strconv.ParseUint(portStringValue, 10, 16)
	if err != nil || port == 0 {
		return 0
	}

	return uint16(port)
}

// logNATCandidates logs the currently discovered local network candidates.
//
// This is diagnostic information only. It does not alter peer identity,
// connection state, or the existing TLS/handshake behavior.
func (n *Node) logNATCandidates() {
	if n == nil {
		return
	}

	candidates := RankCandidates(n.NATCandidates())

	if len(candidates) == 0 {
		log.Printf("[p2p] 🌐 NAT candidates: none")
		return
	}

	for _, candidate := range candidates {
		log.Printf(
			"[p2p] 🌐 NAT candidate: type=%d addr=%s protocol=%s priority=%d",
			candidate.Type,
			candidate.Addr(),
			candidate.Protocol,
			candidate.Priority,
		)
	}
}
