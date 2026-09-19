package p2p

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// PeerDiscoverySourceHandshake identifies a locator learned during
	// authenticated handshake.
	PeerDiscoverySourceHandshake = "handshake"

	// PeerDiscoverySourcePeer identifies a locator learned from another
	// authenticated peer.
	PeerDiscoverySourcePeer = "peer"

	// PeerDiscoverySourceLocal identifies a locator observed locally.
	PeerDiscoverySourceLocal = "local"

	// PeerDiscoverySourceRelay identifies a locator provided by a relay.
	PeerDiscoverySourceRelay = "relay"

	// PeerLocatorTTL defines how long a discovered locator remains trusted
	// when it is not refreshed.
	PeerLocatorTTL = 24 * time.Hour

	// MaxKnownLocatorsPerPeer prevents unbounded locator growth.
	MaxKnownLocatorsPerPeer = 8
)

// PeerDiscovery manages temporary network locators for permanent peer IDs.
//
// A peer identity must never be deleted merely because its current network
// session disappeared. Locators may expire, but identity survives.
type PeerDiscovery struct {
	mu sync.RWMutex

	locators map[PeerID][]PeerLocator
}

// NewPeerDiscovery creates an empty peer discovery database.
func NewPeerDiscovery() *PeerDiscovery {
	return &PeerDiscovery{
		locators: make(map[PeerID][]PeerLocator),
	}
}

// AddLocator stores or refreshes a locator for a peer.
//
// The locator is normalized and validated before insertion.
// A fresh expiration time is assigned unless the caller already supplied one.
func (d *PeerDiscovery) AddLocator(locator PeerLocator) error {
	if d == nil {
		return errors.New("peer discovery is nil")
	}

	locator = locator.Normalize()

	if !locator.IsValid() {
		return errors.New("invalid peer locator")
	}

	if locator.ExpiresAt == 0 {
		locator.ExpiresAt = time.Now().Add(PeerLocatorTTL).Unix()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.locators == nil {
		d.locators = make(map[PeerID][]PeerLocator)
	}

	list := d.locators[locator.PeerID]

	// Refresh an existing locator instead of creating duplicates.
	for i := range list {
		if list[i].Address == locator.Address {
			list[i] = locator
			d.locators[locator.PeerID] = list
			return nil
		}
	}

	// Keep the newest locator first.
	list = append([]PeerLocator{locator}, list...)

	if len(list) > MaxKnownLocatorsPerPeer {
		list = list[:MaxKnownLocatorsPerPeer]
	}

	d.locators[locator.PeerID] = list

	log.Printf(
		"[p2p] 📍 Discovery locator learned: peer=%s addr=%s source=%s",
		locator.PeerID,
		locator.Address,
		locator.Source,
	)

	return nil
}

// GetLocators returns all currently valid locators for a peer.
func (d *PeerDiscovery) GetLocators(peerID PeerID) []PeerLocator {
	if d == nil || peerID == "" {
		return nil
	}

	d.mu.RLock()
	list := append([]PeerLocator(nil), d.locators[peerID]...)
	d.mu.RUnlock()

	now := time.Now()

	result := make([]PeerLocator, 0, len(list))

	for _, locator := range list {
		if !locator.IsValid() {
			continue
		}

		if locator.IsExpired(now) {
			continue
		}

		result = append(result, locator)
	}

	return result
}

// RemoveLocator removes one specific locator without deleting the peer identity.
func (d *PeerDiscovery) RemoveLocator(peerID PeerID, address string) {
	if d == nil || peerID == "" {
		return
	}

	address = strings.TrimSpace(address)
	if address == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	list := d.locators[peerID]

	filtered := list[:0]

	for _, locator := range list {
		if locator.Address != address {
			filtered = append(filtered, locator)
		}
	}

	if len(filtered) == 0 {
		delete(d.locators, peerID)
		return
	}

	d.locators[peerID] = filtered
}

// RemoveExpired removes expired locators.
//
// It deliberately does not remove peer identities conceptually.
// A future discovery event can add a new locator for the same PeerID.
func (d *PeerDiscovery) RemoveExpired() int {
	if d == nil {
		return 0
	}

	now := time.Now()
	removed := 0

	d.mu.Lock()
	defer d.mu.Unlock()

	for peerID, list := range d.locators {
		filtered := list[:0]

		for _, locator := range list {
			if locator.IsExpired(now) {
				removed++
				continue
			}

			filtered = append(filtered, locator)
		}

		if len(filtered) == 0 {
			delete(d.locators, peerID)
		} else {
			d.locators[peerID] = filtered
		}
	}

	return removed
}

// Snapshot returns a copy of all known locators.
//
// Expired locators are excluded.
func (d *PeerDiscovery) Snapshot() map[PeerID][]PeerLocator {
	if d == nil {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()

	result := make(map[PeerID][]PeerLocator)

	for peerID, list := range d.locators {
		for _, locator := range list {
			if !locator.IsValid() {
				continue
			}

			if locator.IsExpired(now) {
				continue
			}

			result[peerID] = append(
				result[peerID],
				locator,
			)
		}
	}

	return result
}

// IsPrivateAddress reports whether the host portion of an address belongs
// to a private or loopback network.
//
// Private addresses can be useful on the local network but normally cannot
// be used to reach a peer across the public Internet.
func IsPrivateAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}
