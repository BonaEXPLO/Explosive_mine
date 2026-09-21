package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	nat2DefaultProbeTimeout = 1500 * time.Millisecond
	nat2DefaultProbeCount   = 8
	nat2MaxCandidates       = 32
	nat2MaxParallelProbes   = 6
)

// NAT2Candidate is the transport-safe representation of a peer candidate.
//
// A candidate is only a locator. It is never an identity.
// The peer identity remains the wallet address / PeerID.
type NAT2Candidate struct {
	Candidate NATCandidate
	PeerID    string
}

// NAT2ProbeResult describes one connectivity attempt.
type NAT2ProbeResult struct {
	Candidate NAT2Candidate
	Address   string
	Latency   time.Duration
	Success   bool
	Error     string
}

// NAT2ConnectivityResult contains the complete result of a candidate check.
type NAT2ConnectivityResult struct {
	PeerID       string
	Selected     *NAT2ProbeResult
	Results      []NAT2ProbeResult
	StartedAt    time.Time
	CompletedAt  time.Time
	ProbeCount   int
	SuccessCount int
}

// NAT2Config controls candidate connectivity checks.
type NAT2Config struct {
	ProbeTimeout  time.Duration
	MaxCandidates int
	MaxParallel   int
}

// DefaultNAT2Config returns conservative mobile-friendly defaults.
func DefaultNAT2Config() NAT2Config {
	return NAT2Config{
		ProbeTimeout:  nat2DefaultProbeTimeout,
		MaxCandidates: nat2MaxCandidates,
		MaxParallel:   nat2MaxParallelProbes,
	}
}

func (c NAT2Config) normalize() NAT2Config {
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = nat2DefaultProbeTimeout
	}

	if c.MaxCandidates <= 0 {
		c.MaxCandidates = nat2MaxCandidates
	}

	if c.MaxCandidates > nat2MaxCandidates {
		c.MaxCandidates = nat2MaxCandidates
	}

	if c.MaxParallel <= 0 {
		c.MaxParallel = nat2MaxParallelProbes
	}

	if c.MaxParallel > c.MaxCandidates {
		c.MaxParallel = c.MaxCandidates
	}

	return c
}

// BuildNAT2CandidateSet creates a bounded, validated candidate list.
func BuildNAT2CandidateSet(peerID string, candidates []NATCandidate, maxCandidates int) []NAT2Candidate {
	if maxCandidates <= 0 || maxCandidates > nat2MaxCandidates {
		maxCandidates = nat2MaxCandidates
	}

	unique := make(map[string]NAT2Candidate)
	result := make([]NAT2Candidate, 0, len(candidates))

	for _, candidate := range candidates {
		if !candidate.IsValid() {
			continue
		}

		addr := candidate.Addr()
		if addr == "" {
			continue
		}

		key := fmt.Sprintf(
			"%d|%s|%d|%s",
			candidate.Type,
			addr,
			candidate.Port,
			candidate.Protocol,
		)

		if _, exists := unique[key]; exists {
			continue
		}

		item := NAT2Candidate{
			Candidate: candidate,
			PeerID:    peerID,
		}

		unique[key] = item
		result = append(result, item)
	}

	sort.SliceStable(result, func(i, j int) bool {
		return nat2CandidateScore(result[i].Candidate) >
			nat2CandidateScore(result[j].Candidate)
	})

	if len(result) > maxCandidates {
		result = result[:maxCandidates]
	}

	return result
}

// nat2CandidateScore gives preference to candidates that are more useful
// for direct Internet connectivity.
//
// This is only a transport preference. It does not determine peer identity.
func nat2CandidateScore(candidate NATCandidate) int {
	score := int(candidate.Priority)

	switch candidate.Type {
	case NATCandidateLAN:
		score += 400
	case NATCandidateIPv6:
		score += 300
	case NATCandidateReflexive:
		score += 250
	case NATCandidatePrivateIPv4:
		score += 150
	case NATCandidateRelay:
		score += 50
	}

	if candidate.IsIPv6() {
		score += 20
	}

	return score
}

// CheckNAT2Candidate performs one bounded TCP connectivity check.
//
// It does not perform the EXPLOSIVE handshake.
// A successful TCP connection only proves that the transport path works.
func CheckNAT2Candidate(
	ctx context.Context,
	candidate NAT2Candidate,
	timeout time.Duration,
) NAT2ProbeResult {

	result := NAT2ProbeResult{
		Candidate: candidate,
		Address:   candidate.Candidate.Addr(),
	}

	if result.Address == "" {
		result.Error = "empty candidate address"
		return result
	}

	if timeout <= 0 {
		timeout = nat2DefaultProbeTimeout
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	var dialer net.Dialer

	conn, err := dialer.DialContext(
		probeCtx,
		"tcp",
		result.Address,
	)

	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	_ = conn.Close()

	result.Success = true
	return result
}

// CheckNAT2Candidates tests candidates in parallel with bounded concurrency.
//
// The first successful candidate is not automatically selected immediately.
// All currently scheduled probes are allowed to finish so that we can choose
// the best successful path based on candidate priority and latency.
func CheckNAT2Candidates(
	ctx context.Context,
	peerID string,
	candidates []NATCandidate,
	config NAT2Config,
) NAT2ConnectivityResult {

	config = config.normalize()

	result := NAT2ConnectivityResult{
		PeerID:    peerID,
		StartedAt: time.Now(),
		Results:   make([]NAT2ProbeResult, 0),
	}

	nat2Candidates := BuildNAT2CandidateSet(
		peerID,
		candidates,
		config.MaxCandidates,
	)

	if len(nat2Candidates) == 0 {
		result.CompletedAt = time.Now()
		return result
	}

	if len(nat2Candidates) > nat2DefaultProbeCount {
		nat2Candidates = nat2Candidates[:nat2DefaultProbeCount]
	}

	type indexedResult struct {
		index  int
		result NAT2ProbeResult
	}

	resultsCh := make(chan indexedResult, len(nat2Candidates))
	sem := make(chan struct{}, config.MaxParallel)

	var wg sync.WaitGroup

	for index, candidate := range nat2Candidates {
		index := index
		candidate := candidate

		wg.Add(1)

		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				resultsCh <- indexedResult{
					index: index,
					result: NAT2ProbeResult{
						Candidate: candidate,
						Address:   candidate.Candidate.Addr(),
						Error:     ctx.Err().Error(),
					},
				}
				return
			}

			defer func() {
				<-sem
			}()

			probeResult := CheckNAT2Candidate(
				ctx,
				candidate,
				config.ProbeTimeout,
			)

			resultsCh <- indexedResult{
				index:  index,
				result: probeResult,
			}
		}()
	}

	wg.Wait()
	close(resultsCh)

	ordered := make([]indexedResult, 0, len(nat2Candidates))

	for item := range resultsCh {
		ordered = append(ordered, item)
	}

	sort.Slice(
		ordered,
		func(i, j int) bool {
			return ordered[i].index < ordered[j].index
		},
	)

	for _, item := range ordered {
		result.Results = append(
			result.Results,
			item.result,
		)

		result.ProbeCount++

		if item.result.Success {
			result.SuccessCount++
		}
	}

	result.Selected = selectNAT2Path(result.Results)
	result.CompletedAt = time.Now()

	return result
}

// selectNAT2Path chooses the best successful transport path.
//
// Candidate priority is considered first. Latency is used as a tie breaker.
func selectNAT2Path(results []NAT2ProbeResult) *NAT2ProbeResult {
	var selected *NAT2ProbeResult

	for index := range results {
		current := results[index]

		if !current.Success {
			continue
		}

		if selected == nil {
			copyResult := current
			selected = &copyResult
			continue
		}

		currentScore := nat2CandidateScore(current.Candidate.Candidate)
		selectedScore := nat2CandidateScore(selected.Candidate.Candidate)

		if currentScore > selectedScore {
			copyResult := current
			selected = &copyResult
			continue
		}

		if currentScore == selectedScore &&
			current.Latency < selected.Latency {
			copyResult := current
			selected = &copyResult
		}
	}

	return selected
}

// NAT2BestCandidate returns the selected reachable candidate.
func NAT2BestCandidate(result NAT2ConnectivityResult) (NATCandidate, error) {
	if result.Selected == nil {
		return NATCandidate{}, errors.New(
			"no reachable NAT candidate",
		)
	}

	return result.Selected.Candidate.Candidate, nil
}

// NAT2CandidateDiagnostics returns a compact human-readable diagnostic.
func NAT2CandidateDiagnostics(result NAT2ConnectivityResult) string {
	if result.ProbeCount == 0 {
		return "NAT2: no candidates tested"
	}

	if result.Selected == nil {
		return fmt.Sprintf(
			"NAT2: %d candidates tested, 0 reachable",
			result.ProbeCount,
		)
	}

	return fmt.Sprintf(
		"NAT2: %d candidates tested, %d reachable, selected=%s latency=%s",
		result.ProbeCount,
		result.SuccessCount,
		result.Selected.Address,
		result.Selected.Latency.Round(time.Millisecond),
	)
}
