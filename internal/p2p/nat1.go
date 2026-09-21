package p2p

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// GLOBAL NAT / INTERNET INTELLIGENCE
// ============================================================================
//
// This file extends nat.go without duplicating its candidate primitives.
//
// nat.go owns:
//   - NATCandidate
//   - CandidateSet
//   - local candidate discovery
//   - basic candidate ranking
//
// nat1.go owns:
//   - NAT classification
//   - global IPv6 validation
//   - CGNAT detection
//   - STUN reflexive address observation
//   - global candidate intelligence
//
// IMPORTANT:
//   A network locator is never a permanent peer identity.
//
// Permanent identity:
//     PeerID == WalletAddress
//
// This layer never handles:
//   - wallet passwords
//   - BIP39 words
//   - sacred words
//   - private keys
//   - decrypted wallet material
//
// ============================================================================

// -----------------------------------------------------------------------------
// NAT reachability classification
// -----------------------------------------------------------------------------

type NATReachability uint8

const (
	NATReachabilityUnknown NATReachability = iota
	NATReachabilityLocal
	NATReachabilityPrivate
	NATReachabilityCGNAT
	NATReachabilityGlobalIPv6
	NATReachabilityReflexive
	NATReachabilityRelay
)

// String returns a stable diagnostic representation.
func (r NATReachability) String() string {
	switch r {
	case NATReachabilityLocal:
		return "local"

	case NATReachabilityPrivate:
		return "private"

	case NATReachabilityCGNAT:
		return "cgnat"

	case NATReachabilityGlobalIPv6:
		return "global_ipv6"

	case NATReachabilityReflexive:
		return "reflexive"

	case NATReachabilityRelay:
		return "relay"

	default:
		return "unknown"
	}
}

// -----------------------------------------------------------------------------
// Candidate classification
// -----------------------------------------------------------------------------

// ClassifyNATCandidate determines the network reachability class of a
// transport candidate.
//
// This function does not establish actual Internet reachability.
// It only classifies what the address represents.
func ClassifyNATCandidate(candidate NATCandidate) NATReachability {
	if !candidate.IsValid() {
		return NATReachabilityUnknown
	}

	switch candidate.Type {
	case NATCandidateLAN:
		return NATReachabilityLocal

	case NATCandidateRelay:
		return NATReachabilityRelay
	}

	ip := net.ParseIP(strings.TrimSpace(candidate.Address))
	if ip == nil {
		return NATReachabilityUnknown
	}

	if ip.To4() == nil {
		if isGlobalIPv6Address(ip) {
			return NATReachabilityGlobalIPv6
		}

		return NATReachabilityPrivate
	}

	if isCGNATIPv4Address(ip) {
		return NATReachabilityCGNAT
	}

	if isPrivateOrLocalIP(ip) {
		return NATReachabilityPrivate
	}

	if candidate.Type == NATCandidateReflexive {
		return NATReachabilityReflexive
	}

	return NATReachabilityUnknown
}

// -----------------------------------------------------------------------------
// Global IPv6
// -----------------------------------------------------------------------------

// IsGlobalIPv6Address reports whether ip is a globally routable IPv6
// candidate.
//
// Link-local, loopback, unspecified, multicast, ULA and documentation
// addresses are deliberately excluded.
func IsGlobalIPv6Address(ip net.IP) bool {
	return isGlobalIPv6Address(ip)
}

func isGlobalIPv6Address(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ip = ip.To16()
	if ip == nil {
		return false
	}

	// An IPv4 address represented as 16 bytes is not IPv6.
	if ip.To4() != nil {
		return false
	}

	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}

	// fc00::/7 - IPv6 Unique Local Addresses.
	if ip[0]&0xfe == 0xfc {
		return false
	}

	// ff00::/8 - IPv6 multicast.
	if ip[0] == 0xff {
		return false
	}

	// 2001:db8::/32 - documentation range.
	if ip[0] == 0x20 &&
		ip[1] == 0x01 &&
		ip[2] == 0x0d &&
		ip[3] == 0xb8 {
		return false
	}

	return true
}

// -----------------------------------------------------------------------------
// IPv4 CGNAT
// -----------------------------------------------------------------------------

// IsCGNATIPv4Address reports whether ip belongs to RFC6598
// carrier-grade NAT space: 100.64.0.0/10.
func IsCGNATIPv4Address(ip net.IP) bool {
	return isCGNATIPv4Address(ip)
}

func isCGNATIPv4Address(ip net.IP) bool {
	if ip == nil {
		return false
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	return ip4[0] == 100 &&
		ip4[1] >= 64 &&
		ip4[1] <= 127
}

// -----------------------------------------------------------------------------
// STUN
// -----------------------------------------------------------------------------

const (
	stunMagicCookie uint32 = 0x2112A442

	stunBindingRequest uint16 = 0x0001
	stunBindingSuccess uint16 = 0x0101

	stunMappedAddress    uint16 = 0x0001
	stunXORMappedAddress uint16 = 0x0020

	stunTransactionIDLength = 12

	stunDefaultTimeout  = 4 * time.Second
	stunMaxResponseSize = 4096
)

// Default STUN servers.
//
// These are used only for reflexive address observation.
// They are not EXPLOSIVE authorities and do not define peer identity.
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

// ReflexiveObservation represents an address observed by an external
// STUN server.
//
// This is intentionally NOT a NATCandidate because STUN is currently
// performed over UDP while EXPLOSIVE P2P transport is TCP/TLS.
//
// Therefore this observation must never be directly fed into Peer.Connect().
type ReflexiveObservation struct {
	Address    string
	Port       uint16
	Server     string
	Protocol   string
	ObservedAt int64
}

// IsValid verifies the observation structure.
func (o ReflexiveObservation) IsValid() bool {
	if strings.TrimSpace(o.Address) == "" {
		return false
	}

	if o.Port == 0 {
		return false
	}

	if net.ParseIP(strings.TrimSpace(o.Address)) == nil {
		return false
	}

	if strings.TrimSpace(o.Server) == "" {
		return false
	}

	if strings.ToLower(strings.TrimSpace(o.Protocol)) != "udp" {
		return false
	}

	return true
}

// Addr returns the observed host:port.
func (o ReflexiveObservation) Addr() string {
	if !o.IsValid() {
		return ""
	}

	return net.JoinHostPort(
		strings.TrimSpace(o.Address),
		portString(o.Port),
	)
}

// -----------------------------------------------------------------------------
// STUN transaction ID
// -----------------------------------------------------------------------------

func newSTUNTransactionID() ([stunTransactionIDLength]byte, error) {
	var id [stunTransactionIDLength]byte

	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf(
			"generate STUN transaction ID: %w",
			err,
		)
	}

	return id, nil
}

// -----------------------------------------------------------------------------
// STUN request
// -----------------------------------------------------------------------------

func buildSTUNBindingRequest(
	transactionID [stunTransactionIDLength]byte,
) []byte {
	packet := make([]byte, 20)

	binary.BigEndian.PutUint16(
		packet[0:2],
		stunBindingRequest,
	)

	binary.BigEndian.PutUint16(
		packet[2:4],
		0,
	)

	binary.BigEndian.PutUint32(
		packet[4:8],
		stunMagicCookie,
	)

	copy(
		packet[8:20],
		transactionID[:],
	)

	return packet
}

// -----------------------------------------------------------------------------
// STUN attribute parsing
// -----------------------------------------------------------------------------

func parseSTUNAddressAttribute(
	attributeType uint16,
	value []byte,
	transactionID [stunTransactionIDLength]byte,
) (net.IP, uint16, bool) {

	if len(value) < 4 {
		return nil, 0, false
	}

	family := value[1]

	port := binary.BigEndian.Uint16(
		value[2:4],
	)

	// -------------------------------------------------------------------------
	// MAPPED-ADDRESS
	// -------------------------------------------------------------------------

	if attributeType == stunMappedAddress {
		switch family {
		case 0x01:
			if len(value) < 8 {
				return nil, 0, false
			}

			return net.IPv4(
				value[4],
				value[5],
				value[6],
				value[7],
			), port, true

		case 0x02:
			if len(value) < 20 {
				return nil, 0, false
			}

			ip := make(net.IP, net.IPv6len)

			copy(
				ip,
				value[4:20],
			)

			return ip, port, true
		}

		return nil, 0, false
	}

	// -------------------------------------------------------------------------
	// XOR-MAPPED-ADDRESS
	// -------------------------------------------------------------------------

	if attributeType != stunXORMappedAddress {
		return nil, 0, false
	}

	xorPort := port ^
		uint16(stunMagicCookie>>16)

	switch family {
	case 0x01:
		if len(value) < 8 {
			return nil, 0, false
		}

		var cookie [4]byte

		binary.BigEndian.PutUint32(
			cookie[:],
			stunMagicCookie,
		)

		rawIP := make([]byte, 4)

		for i := 0; i < 4; i++ {
			rawIP[i] = value[4+i] ^ cookie[i]
		}

		return net.IPv4(
			rawIP[0],
			rawIP[1],
			rawIP[2],
			rawIP[3],
		), xorPort, true

	case 0x02:
		if len(value) < 20 {
			return nil, 0, false
		}

		mask := make([]byte, 16)

		binary.BigEndian.PutUint32(
			mask[0:4],
			stunMagicCookie,
		)

		copy(
			mask[4:],
			transactionID[:],
		)

		rawIP := make([]byte, 16)

		for i := 0; i < 16; i++ {
			rawIP[i] = value[4+i] ^ mask[i]
		}

		return net.IP(rawIP), xorPort, true
	}

	return nil, 0, false
}

// -----------------------------------------------------------------------------
// STUN response parser
// -----------------------------------------------------------------------------

func parseSTUNBindingResponse(
	packet []byte,
	transactionID [stunTransactionIDLength]byte,
) (net.IP, uint16, error) {

	const stunHeaderLength = 20

	if len(packet) < stunHeaderLength {
		return nil, 0, errors.New("STUN response too short")
	}

	messageType := binary.BigEndian.Uint16(packet[0:2])
	if messageType != stunBindingSuccess {
		return nil, 0, fmt.Errorf(
			"unexpected STUN message type: 0x%04x",
			messageType,
		)
	}

	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))

	if messageLength < 0 {
		return nil, 0, errors.New("invalid STUN message length")
	}

	messageEnd := stunHeaderLength + messageLength

	if messageEnd > len(packet) {
		return nil, 0, errors.New("invalid STUN message length")
	}

	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return nil, 0, errors.New("invalid STUN magic cookie")
	}

	if !bytes.Equal(packet[8:20], transactionID[:]) {
		return nil, 0, errors.New("STUN transaction ID mismatch")
	}

	offset := stunHeaderLength

	for offset+4 <= messageEnd {
		attributeType := binary.BigEndian.Uint16(
			packet[offset : offset+2],
		)

		attributeLength := int(
			binary.BigEndian.Uint16(
				packet[offset+2 : offset+4],
			),
		)

		attributeStart := offset + 4
		attributeEnd := attributeStart + attributeLength

		if attributeEnd > messageEnd {
			return nil, 0, errors.New(
				"invalid STUN attribute length",
			)
		}

		value := packet[attributeStart:attributeEnd]

		if attributeType == stunXORMappedAddress ||
			attributeType == stunMappedAddress {

			ip, port, ok := parseSTUNAddressAttribute(
				attributeType,
				value,
				transactionID,
			)

			if ok {
				return ip, port, nil
			}
		}

		// STUN attributes are padded to a four-byte boundary.
		paddedLength := (attributeLength + 3) &^ 3

		nextOffset := attributeStart + paddedLength

		if nextOffset > messageEnd {
			return nil, 0, errors.New(
				"invalid STUN attribute padding",
			)
		}

		offset = nextOffset
	}

	return nil, 0, errors.New(
		"STUN response contains no mapped address",
	)
}

// -----------------------------------------------------------------------------
// STUN server query
// -----------------------------------------------------------------------------

func DiscoverReflexiveObservation(
	server string,
) (ReflexiveObservation, error) {

	server = strings.TrimSpace(server)

	if server == "" {
		return ReflexiveObservation{}, errors.New(
			"STUN server is empty",
		)
	}

	transactionID, err := newSTUNTransactionID()
	if err != nil {
		return ReflexiveObservation{}, err
	}

	conn, err := net.DialTimeout(
		"udp",
		server,
		stunDefaultTimeout,
	)
	if err != nil {
		return ReflexiveObservation{}, fmt.Errorf(
			"STUN dial %s: %w",
			server,
			err,
		)
	}

	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(stunDefaultTimeout),
	); err != nil {
		return ReflexiveObservation{}, fmt.Errorf(
			"set STUN deadline: %w",
			err,
		)
	}

	request := buildSTUNBindingRequest(
		transactionID,
	)

	if _, err := conn.Write(request); err != nil {
		return ReflexiveObservation{}, fmt.Errorf(
			"send STUN request: %w",
			err,
		)
	}

	buffer := make([]byte, stunMaxResponseSize)

	n, err := conn.Read(buffer)
	if err != nil {
		return ReflexiveObservation{}, fmt.Errorf(
			"read STUN response: %w",
			err,
		)
	}

	ip, port, err := parseSTUNBindingResponse(
		buffer[:n],
		transactionID,
	)
	if err != nil {
		return ReflexiveObservation{}, err
	}

	if ip == nil || port == 0 {
		return ReflexiveObservation{}, errors.New(
			"STUN returned invalid reflexive address",
		)
	}

	observation := ReflexiveObservation{
		Address:    ip.String(),
		Port:       port,
		Server:     server,
		Protocol:   "udp",
		ObservedAt: time.Now().Unix(),
	}

	if !observation.IsValid() {
		return ReflexiveObservation{}, errors.New(
			"STUN produced invalid reflexive observation",
		)
	}

	return observation, nil
}

// -----------------------------------------------------------------------------
// Multi-server reflexive discovery
// -----------------------------------------------------------------------------

// DiscoverReflexiveObservations queries the configured STUN servers.
//
// Multiple observations are retained because different NATs may expose
// different mappings depending on the destination server.
func DiscoverReflexiveObservations() []ReflexiveObservation {
	observations := make(
		[]ReflexiveObservation,
		0,
		len(defaultSTUNServers),
	)

	seen := make(map[string]struct{})

	for _, server := range defaultSTUNServers {
		observation, err := DiscoverReflexiveObservation(
			server,
		)

		if err != nil {
			continue
		}

		key := strings.ToLower(
			observation.Addr(),
		)

		if key == "" {
			continue
		}

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}

		observations = append(
			observations,
			observation,
		)
	}

	sort.SliceStable(
		observations,
		func(i, j int) bool {
			if observations[i].Address != observations[j].Address {
				return observations[i].Address <
					observations[j].Address
			}

			if observations[i].Port != observations[j].Port {
				return observations[i].Port <
					observations[j].Port
			}

			return observations[i].Server <
				observations[j].Server
		},
	)

	return observations
}

// -----------------------------------------------------------------------------
// Reflexive TCP candidate construction
// -----------------------------------------------------------------------------

// BuildReflexiveTCPCandidate converts an externally observed address into
// an EXPLOSIVE TCP candidate only when the caller explicitly confirms that
// the observed port corresponds to the local TCP listener.
//
// STUN itself does not prove that UDP and TCP mappings are identical.
//
// Therefore this function is intentionally explicit.
func BuildReflexiveTCPCandidate(
	observation ReflexiveObservation,
	tcpListenPort uint16,
) (NATCandidate, bool) {

	if !observation.IsValid() {
		return NATCandidate{}, false
	}

	if tcpListenPort == 0 {
		return NATCandidate{}, false
	}

	ip := net.ParseIP(
		strings.TrimSpace(observation.Address),
	)

	if ip == nil {
		return NATCandidate{}, false
	}

	// A reflexive candidate must represent a globally observable address.
	//
	// Private/CGNAT addresses are not reflexive Internet endpoints.
	if ip.To4() != nil {
		if isPrivateOrLocalIP(ip) ||
			isCGNATIPv4Address(ip) {
			return NATCandidate{}, false
		}
	} else if !isGlobalIPv6Address(ip) {
		return NATCandidate{}, false
	}

	return NATCandidate{
		Type:     NATCandidateReflexive,
		Address:  ip.String(),
		Port:     tcpListenPort,
		Protocol: "tcp",
		Priority: 60,
	}, true
}

// -----------------------------------------------------------------------------
// Global candidate ranking
// -----------------------------------------------------------------------------

// RankGlobalCandidates applies EXPLOSIVE's global path preference.
//
// Preferred order:
//
//  1. LAN
//  2. Global IPv6
//  3. Private IPv4
//  4. Reflexive
//  5. Relay
//
// A candidate's priority is transport preference only.
// It never changes peer identity.
func RankGlobalCandidates(
	candidates []NATCandidate,
) []NATCandidate {

	if len(candidates) == 0 {
		return nil
	}

	result := make(
		[]NATCandidate,
		0,
		len(candidates),
	)

	for _, candidate := range candidates {
		if !candidate.IsValid() {
			continue
		}

		switch candidate.Type {
		case NATCandidateLAN:
			candidate.Priority = 100

		case NATCandidateIPv6:
			candidate.Priority = 95

		case NATCandidatePrivateIPv4:
			candidate.Priority = 80

		case NATCandidateReflexive:
			candidate.Priority = 60

		case NATCandidateRelay:
			candidate.Priority = 20
		}

		result = append(
			result,
			candidate,
		)
	}

	sort.SliceStable(
		result,
		func(i, j int) bool {
			if result[i].Priority != result[j].Priority {
				return result[i].Priority >
					result[j].Priority
			}

			left := ClassifyNATCandidate(
				result[i],
			)

			right := ClassifyNATCandidate(
				result[j],
			)

			if left != right {
				return globalReachabilityRank(left) <
					globalReachabilityRank(right)
			}

			return result[i].Addr() <
				result[j].Addr()
		},
	)

	return result
}

func globalReachabilityRank(
	reachability NATReachability,
) int {

	switch reachability {
	case NATReachabilityLocal:
		return 1

	case NATReachabilityGlobalIPv6:
		return 2

	case NATReachabilityPrivate:
		return 3

	case NATReachabilityCGNAT:
		return 4

	case NATReachabilityReflexive:
		return 5

	case NATReachabilityRelay:
		return 6

	default:
		return 99
	}
}

// -----------------------------------------------------------------------------
// Candidate merge
// -----------------------------------------------------------------------------

// MergeGlobalCandidates merges local and externally learned candidates
// without changing the existing CandidateSet implementation in nat.go.
func MergeGlobalCandidates(
	local []NATCandidate,
	external []NATCandidate,
) []NATCandidate {

	set := NewCandidateSet()

	set.AddMany(local)
	set.AddMany(external)

	return RankGlobalCandidates(
		set.All(),
	)
}

// -----------------------------------------------------------------------------
// Diagnostics
// -----------------------------------------------------------------------------

// DescribeNATCandidate produces a compact diagnostic representation.
func DescribeNATCandidate(
	candidate NATCandidate,
) string {

	if !candidate.IsValid() {
		return "invalid"
	}

	return fmt.Sprintf(
		"type=%d address=%s protocol=%s priority=%d reachability=%s",
		candidate.Type,
		candidate.Addr(),
		candidate.Protocol,
		candidate.Priority,
		ClassifyNATCandidate(candidate).String(),
	)
}
