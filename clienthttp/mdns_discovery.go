// mdns_discovery.go — Discovery backed by luxfi/mdns.
//
// This is the default Discovery used by NewClient when no
// WithDiscovery override is supplied. Adapts the luxfi/mdns API to
// the local Discovery interface so callers depend on the contract,
// not on luxfi/mdns directly.

package clienthttp

import (
	"time"

	"github.com/luxfi/mdns"
)

// mdnsDiscovery adapts *mdns.Discovery to the local Discovery
// interface. ServiceType is fixed at construction; one instance per
// (serviceType, clientID, interval) triple.
type mdnsDiscovery struct {
	disc *mdns.Discovery
}

// newMDNSDiscovery constructs a Discovery using luxfi/mdns as the
// peer-enumeration backend.
func newMDNSDiscovery(serviceType, clientID string, browseInterval time.Duration) *mdnsDiscovery {
	d := mdns.New(
		serviceType,
		clientID,
		0, // client-side: we don't advertise a port
		mdns.WithBrowseInterval(browseInterval),
	)
	return &mdnsDiscovery{disc: d}
}

// Start begins the mDNS browse loop.
func (m *mdnsDiscovery) Start() error { return m.disc.Start() }

// Stop releases discovery resources. Idempotent.
func (m *mdnsDiscovery) Stop() { m.disc.Stop() }

// PeerCount returns the current peer count without allocating.
func (m *mdnsDiscovery) PeerCount() int { return m.disc.PeerCount() }

// ServiceType reports the discovery's service type.
func (m *mdnsDiscovery) ServiceType() string { return m.disc.ServiceType() }

// Peers returns the current peer snapshot adapted to the local Peer
// shape. The slice is freshly allocated each call — consumers may
// retain it.
func (m *mdnsDiscovery) Peers() []Peer {
	raw := m.disc.Peers()
	out := make([]Peer, 0, len(raw))
	for _, p := range raw {
		if p == nil {
			continue
		}
		out = append(out, Peer{
			NodeID:      p.NodeID,
			ServiceType: m.disc.ServiceType(),
			Address:     p.Address(),
			Metadata:    nil, // luxfi/mdns doesn't surface metadata yet
			LastSeen:    p.LastSeen,
		})
	}
	return out
}
