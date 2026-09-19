package p2p

import (
	"net"
	"strings"
	"time"
)

// PeerLocator describes a temporary network location for a permanent peer identity.
//
// PeerID is the identity.
// Address is only a network locator and may change at any time.
type PeerLocator struct {
	PeerID    PeerID
	Address   string
	Network   string
	Source    string
	LastSeen  int64
	ExpiresAt int64
}

// IsValid reports whether the locator contains a usable peer identity
// and a valid host:port network address.
func (l PeerLocator) IsValid() bool {
	if l.PeerID == "" {
		return false
	}

	address := strings.TrimSpace(l.Address)
	if address == "" {
		return false
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}

	if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return false
	}

	return true
}

// IsExpired reports whether the locator has passed its expiration time.
//
// ExpiresAt == 0 means the locator does not currently expire.
func (l PeerLocator) IsExpired(now time.Time) bool {
	if l.ExpiresAt == 0 {
		return false
	}

	return now.Unix() >= l.ExpiresAt
}

// Normalize returns a cleaned copy of the locator.
func (l PeerLocator) Normalize() PeerLocator {
	l.PeerID = PeerID(strings.TrimSpace(string(l.PeerID)))
	l.Address = strings.TrimSpace(l.Address)
	l.Network = strings.TrimSpace(l.Network)
	l.Source = strings.TrimSpace(l.Source)

	return l
}
