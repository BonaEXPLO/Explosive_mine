package p2p

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// NATCandidateType identifies the transport role of a network candidate.
//
// A candidate is only a possible network path.
// It is never a peer identity.
type NATCandidateType uint8

const (
	NATCandidateLAN NATCandidateType = iota + 1
	NATCandidatePrivateIPv4
	NATCandidateIPv6
	NATCandidateReflexive
	NATCandidateRelay
)

// NATCandidate describes one possible network path to a peer.
//
// Peer identity remains completely separate:
//
//	PeerID == WalletAddress
//
// Address and Port are temporary transport locators and may change
// whenever the mobile network changes.
type NATCandidate struct {
	Type     NATCandidateType
	Address  string
	Port     uint16
	Protocol string
	Priority uint16
}

// IsValid verifies the structural validity of a candidate.
func (c NATCandidate) IsValid() bool {
	if strings.TrimSpace(c.Address) == "" {
		return false
	}

	if c.Port == 0 {
		return false
	}

	protocol := strings.ToLower(strings.TrimSpace(c.Protocol))
	switch protocol {
	case "tcp", "tcp4", "tcp6":
	default:
		return false
	}

	switch c.Type {
	case NATCandidateLAN,
		NATCandidatePrivateIPv4,
		NATCandidateIPv6,
		NATCandidateReflexive,
		NATCandidateRelay:
		return true
	default:
		return false
	}
}

// Addr returns the network address represented by the candidate.
func (c NATCandidate) Addr() string {
	if !c.IsValid() {
		return ""
	}

	return net.JoinHostPort(strings.TrimSpace(c.Address), portString(c.Port))
}

// IsIPv4 reports whether the candidate contains an IPv4 address.
func (c NATCandidate) IsIPv4() bool {
	ip := net.ParseIP(strings.TrimSpace(c.Address))
	return ip != nil && ip.To4() != nil
}

// IsIPv6 reports whether the candidate contains an IPv6 address.
func (c NATCandidate) IsIPv6() bool {
	ip := net.ParseIP(strings.TrimSpace(c.Address))
	return ip != nil && ip.To4() == nil
}

// IsPrivate reports whether the candidate address belongs to a private,
// loopback, link-local, or otherwise non-public address range.
func (c NATCandidate) IsPrivate() bool {
	ip := net.ParseIP(strings.TrimSpace(c.Address))
	if ip == nil {
		return false
	}

	return isPrivateOrLocalIP(ip)
}

// CandidateSet stores the currently known network candidates.
//
// The set is transport-only. It contains no wallet keys, passwords,
// BIP39 words, sacred words, or permanent peer identity.
type CandidateSet struct {
	candidates []NATCandidate
}

// NewCandidateSet creates an empty candidate set.
func NewCandidateSet() *CandidateSet {
	return &CandidateSet{
		candidates: make([]NATCandidate, 0, 8),
	}
}

// Add inserts a valid candidate and removes exact duplicates.
//
// Candidates with the same transport type, address, port and protocol
// are considered identical.
func (s *CandidateSet) Add(candidate NATCandidate) bool {
	if s == nil || !candidate.IsValid() {
		return false
	}

	candidate.Address = strings.TrimSpace(candidate.Address)
	candidate.Protocol = strings.ToLower(strings.TrimSpace(candidate.Protocol))

	for _, existing := range s.candidates {
		if existing.Type == candidate.Type &&
			strings.EqualFold(existing.Address, candidate.Address) &&
			existing.Port == candidate.Port &&
			existing.Protocol == candidate.Protocol {
			return false
		}
	}

	s.candidates = append(s.candidates, candidate)
	return true
}

// AddMany inserts multiple candidates and returns the number actually added.
func (s *CandidateSet) AddMany(candidates []NATCandidate) int {
	if s == nil {
		return 0
	}

	added := 0
	for _, candidate := range candidates {
		if s.Add(candidate) {
			added++
		}
	}

	return added
}

// RemoveInvalid removes all structurally invalid candidates.
func (s *CandidateSet) RemoveInvalid() {
	if s == nil {
		return
	}

	valid := s.candidates[:0]
	for _, candidate := range s.candidates {
		if candidate.IsValid() {
			valid = append(valid, candidate)
		}
	}

	s.candidates = valid
}

// Sort orders candidates from the most desirable direct path to
// the least direct fallback path.
func (s *CandidateSet) Sort() {
	if s == nil {
		return
	}

	sort.SliceStable(s.candidates, func(i, j int) bool {
		if s.candidates[i].Priority != s.candidates[j].Priority {
			return s.candidates[i].Priority > s.candidates[j].Priority
		}

		return candidateTypeRank(s.candidates[i].Type) <
			candidateTypeRank(s.candidates[j].Type)
	})
}

// All returns a copy of all currently known candidates.
func (s *CandidateSet) All() []NATCandidate {
	if s == nil || len(s.candidates) == 0 {
		return nil
	}

	result := make([]NATCandidate, len(s.candidates))
	copy(result, s.candidates)
	return result
}

// Direct returns candidates that can be attempted without a relay.
//
// Reflexive candidates are included because they may represent a
// public address discovered through NAT traversal.
func (s *CandidateSet) Direct() []NATCandidate {
	if s == nil {
		return nil
	}

	result := make([]NATCandidate, 0, len(s.candidates))

	for _, candidate := range s.candidates {
		switch candidate.Type {
		case NATCandidateLAN,
			NATCandidatePrivateIPv4,
			NATCandidateIPv6,
			NATCandidateReflexive:
			result = append(result, candidate)
		}
	}

	return result
}

// Relays returns relay candidates only.
func (s *CandidateSet) Relays() []NATCandidate {
	if s == nil {
		return nil
	}

	result := make([]NATCandidate, 0)

	for _, candidate := range s.candidates {
		if candidate.Type == NATCandidateRelay {
			result = append(result, candidate)
		}
	}

	return result
}

// DiscoverLocalCandidates discovers local IPv4 and IPv6 addresses.
//
// The listening port is supplied by the P2P node. This function only
// discovers network paths; it does not create or modify peer identity.
//
// Classification:
//
//   - LAN IPv4: RFC1918 IPv4 addresses used on local networks.
//   - Private IPv4: other non-public IPv4 addresses such as CGNAT/mobile.
//   - IPv6: global or private IPv6 addresses.
//
// Loopback interfaces are deliberately excluded because 127.0.0.1 and
// ::1 are useful for local tests but are never useful as advertised
// mobile network candidates.
func DiscoverLocalCandidates(port uint16) ([]NATCandidate, error) {
	if port == 0 {
		return nil, fmt.Errorf("invalid network port: %d", port)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}

	set := NewCandidateSet()

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, rawAddr := range addrs {
			ip := extractLocalIP(rawAddr)
			if ip == nil {
				continue
			}

			// Ignore unspecified addresses.
			if ip.IsUnspecified() {
				continue
			}

			// Ignore loopback even if it appears through another
			// address representation.
			if ip.IsLoopback() {
				continue
			}

			candidate := candidateFromLocalIP(ip, port)
			if !candidate.IsValid() {
				continue
			}

			set.Add(candidate)
		}
	}

	set.Sort()

	return set.All(), nil
}

// candidateFromLocalIP converts a local IP address into the correct
// transport candidate type.
func candidateFromLocalIP(ip net.IP, port uint16) NATCandidate {
	if ip == nil || port == 0 {
		return NATCandidate{}
	}

	if ip4 := ip.To4(); ip4 != nil {
		if isLANIPv4(ip4) {
			return NATCandidate{
				Type:     NATCandidateLAN,
				Address:  ip4.String(),
				Port:     port,
				Protocol: "tcp4",
				Priority: 100,
			}
		}

		if isPrivateOrLocalIP(ip4) {
			return NATCandidate{
				Type:     NATCandidatePrivateIPv4,
				Address:  ip4.String(),
				Port:     port,
				Protocol: "tcp4",
				Priority: 80,
			}
		}

		return NATCandidate{}
	}

	// IPv6 candidates are kept separate from IPv4.
	//
	// Link-local IPv6 addresses require an interface scope and therefore
	// cannot safely be advertised as a plain host:port locator.
	if ip.IsLinkLocalUnicast() {
		return NATCandidate{}
	}

	return NATCandidate{
		Type:     NATCandidateIPv6,
		Address:  ip.String(),
		Port:     port,
		Protocol: "tcp6",
		Priority: 90,
	}
}

// extractIP extracts an IP address from a net.Addr.
//
// This handles both CIDR addresses returned by network interfaces and
// plain IP address representations.
func extractLocalIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}

	switch value := addr.(type) {
	case *net.IPNet:
		if value == nil {
			return nil
		}
		return value.IP

	case *net.IPAddr:
		if value == nil {
			return nil
		}
		return value.IP
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return net.ParseIP(host)
	}

	return net.ParseIP(strings.TrimSpace(addr.String()))
}

// isLANIPv4 identifies IPv4 addresses commonly used by local
// Wi-Fi and hotspot networks.
//
// The 10.0.0.0/8 range is deliberately excluded because mobile
// operators and CGNAT networks may use it for private cellular
// connectivity.
func isLANIPv4(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	switch {
	case ip4[0] == 192 &&
		ip4[1] == 168:
		return true

	case ip4[0] == 172 &&
		ip4[1] >= 16 &&
		ip4[1] <= 31:
		return true

	default:
		return false
	}
}

// isPrivateOrLocalIP identifies addresses that are not globally
// routable and therefore should never be treated as permanent identity.
func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() {
		return true
	}

	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4 carrier-grade NAT space: 100.64.0.0/10.
		if ip4[0] == 100 &&
			ip4[1] >= 64 &&
			ip4[1] <= 127 {
			return true
		}

		// IPv4 benchmarking/documentation ranges must not be
		// treated as real public network paths.
		if ip4[0] == 192 &&
			ip4[1] == 0 &&
			ip4[2] == 2 {
			return true
		}

		if ip4[0] == 198 &&
			ip4[1] >= 18 &&
			ip4[1] <= 19 {
			return true
		}

		if ip4[0] == 198 &&
			ip4[1] == 51 &&
			ip4[2] == 100 {
			return true
		}

		if ip4[0] == 203 &&
			ip4[1] == 0 &&
			ip4[2] == 113 {
			return true
		}
	}

	return false
}

// candidateTypeRank defines the fallback order when two candidates have
// equal explicit priority.
func candidateTypeRank(candidateType NATCandidateType) int {
	switch candidateType {
	case NATCandidateLAN:
		return 1

	case NATCandidateIPv6:
		return 2

	case NATCandidatePrivateIPv4:
		return 3

	case NATCandidateReflexive:
		return 4

	case NATCandidateRelay:
		return 5

	default:
		return 99
	}
}

// portString converts a numeric port to its network representation.
func portString(port uint16) string {
	return strconv.Itoa(int(port))
}

// RankCandidates returns candidates ordered from the preferred direct
// transport path to the last-resort relay path.
//
// The ranking never changes peer identity.
// It only determines which network path should be attempted first.
func RankCandidates(candidates []NATCandidate) []NATCandidate {
	if len(candidates) == 0 {
		return nil
	}

	result := make([]NATCandidate, 0, len(candidates))

	for _, candidate := range candidates {
		if candidate.IsValid() {
			result = append(result, candidate)
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Priority != result[j].Priority {
			return result[i].Priority > result[j].Priority
		}

		return candidateTypeRank(result[i].Type) <
			candidateTypeRank(result[j].Type)
	})

	return result
}
