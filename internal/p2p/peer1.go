package p2p

import (
	"crypto/tls"
	"time"
)

func (p *Peer) getTLSIdentity() (string, bool) {

	conn := p.getConn()

	if conn == nil {
		return "", false
	}

	tlsConn, ok := conn.(*tls.Conn)

	if !ok {
		return "", false
	}

	state := tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return "", false
	}

	cert := state.PeerCertificates[0]
	return cert.Subject.CommonName, true
}

// nextPingNonce generates a unique nonce for the current peer session.
func (p *Peer) nextPingNonce() int64 {
	if p == nil {
		return 0
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	p.pingSequence++

	// Combine the current timestamp with a per-peer sequence.
	// This avoids relying on wall-clock uniqueness alone.
	now := time.Now().UnixNano()

	nonce := now ^ int64(p.pingSequence)
	if nonce == 0 {
		nonce = int64(p.pingSequence)
	}

	return nonce
}

// registerPing records an outbound PING awaiting its PONG.
func (p *Peer) registerPing(nonce int64) {
	if p == nil || nonce == 0 {
		return
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	if p.pendingPings == nil {
		p.pendingPings = make(map[int64]time.Time)
	}

	p.pendingPings[nonce] = time.Now()

	// Keep the pending table bounded.
	// A missing PONG is a session issue, never a reputation violation.
	if len(p.pendingPings) > 64 {
		cutoff := time.Now().Add(-10 * time.Minute)

		for pendingNonce, sentAt := range p.pendingPings {
			if sentAt.Before(cutoff) {
				delete(p.pendingPings, pendingNonce)
			}
		}

		// Hard safety bound in case the clock behaves unexpectedly.
		for len(p.pendingPings) > 64 {
			for pendingNonce := range p.pendingPings {
				delete(p.pendingPings, pendingNonce)
				break
			}
		}
	}
}

// receivePong validates a PONG against an outstanding PING.
//
// The returned duration is the measured round-trip time.
// A false result means that the nonce was not issued by this session.
func (p *Peer) receivePong(nonce int64) (time.Duration, bool) {
	if p == nil || nonce == 0 {
		return 0, false
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	sentAt, ok := p.pendingPings[nonce]
	if !ok {
		return 0, false
	}

	delete(p.pendingPings, nonce)
	rtt := time.Since(sentAt)

	if rtt < 0 {
		rtt = 0
	}

	p.lastPong = time.Now()

	return rtt, true
}

// LastPong returns the last successful PONG time for the current session.
func (p *Peer) LastPong() time.Time {
	if p == nil {
		return time.Time{}
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	return p.lastPong
}

// PendingPingCount returns the number of PINGs currently awaiting PONG.
func (p *Peer) PendingPingCount() int {
	if p == nil {
		return 0
	}

	p.pingMu.Lock()
	defer p.pingMu.Unlock()

	return len(p.pendingPings)
}

// RemoteNATCandidates returns a defensive copy of the authenticated
// peer's advertised network candidates.
//
// Candidates are network locators only. They do not define peer identity.
func (p *Peer) RemoteNATCandidates() []NATCandidate {
	if p == nil {
		return nil
	}

	p.candidateExchangeMu.RLock()
	defer p.candidateExchangeMu.RUnlock()

	if len(p.remoteNATCandidates) == 0 {
		return nil
	}

	out := make([]NATCandidate, len(p.remoteNATCandidates))
	copy(out, p.remoteNATCandidates)

	return out
}

// setRemoteNATCandidates replaces the remote candidate set.
//
// The caller must have already authenticated the peer and validated
// every candidate.
func (p *Peer) setRemoteNATCandidates(candidates []NATCandidate) {
	if p == nil {
		return
	}

	p.candidateExchangeMu.Lock()
	defer p.candidateExchangeMu.Unlock()

	p.remoteNATCandidates = make(
		[]NATCandidate,
		len(candidates),
	)

	copy(p.remoteNATCandidates, candidates)
}

// acceptCandidateExchangeNonce records a candidate-exchange nonce.
//
// A nonce can only be accepted once during its validity window.
// This prevents replay of a previously authenticated candidate set.
func (p *Peer) acceptCandidateExchangeNonce(nonce uint64) bool {
	if p == nil || nonce == 0 {
		return false
	}

	now := time.Now()

	p.candidateExchangeMu.Lock()
	defer p.candidateExchangeMu.Unlock()

	if p.seenCandidateNonces == nil {
		p.seenCandidateNonces = make(map[uint64]time.Time)
	}

	// Remove expired replay entries.
	maxAge := time.Duration(MaxClockSkew) * time.Millisecond

	for seenNonce, seenAt := range p.seenCandidateNonces {
		if now.Sub(seenAt) > maxAge {
			delete(p.seenCandidateNonces, seenNonce)
		}
	}

	if _, exists := p.seenCandidateNonces[nonce]; exists {
		return false
	}

	p.seenCandidateNonces[nonce] = now

	return true
}

// acceptNAT4Nonce records a NAT4 coordination nonce.
//
// A NAT4 nonce can only be accepted once during its validity window.
// This prevents replay of a previously authenticated coordination request.
func (p *Peer) acceptNAT4Nonce(nonce uint64) bool {
	if p == nil || nonce == 0 {
		return false
	}

	now := time.Now()

	p.nat4Mu.Lock()
	defer p.nat4Mu.Unlock()

	if p.seenNAT4Nonces == nil {
		p.seenNAT4Nonces = make(map[uint64]time.Time)
	}

	maxAge := nat4MaxClockSkew

	for seenNonce, seenAt := range p.seenNAT4Nonces {
		if now.Sub(seenAt) > maxAge {
			delete(p.seenNAT4Nonces, seenNonce)
		}
	}

	if _, exists := p.seenNAT4Nonces[nonce]; exists {
		return false
	}

	p.seenNAT4Nonces[nonce] = now

	return true
}
