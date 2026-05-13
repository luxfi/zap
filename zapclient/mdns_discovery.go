// mdns_discovery.go — Discovery backed by luxfi/mdns.
//
// The default Discovery used by Connect when no WithDiscovery override
// is supplied. Adapts luxfi/mdns to the package-level Discovery
// interface so callers depend on the contract, not on luxfi/mdns
// directly. Pure client mode — does not advertise a port.

package zapclient

import (
	"time"

	"github.com/luxfi/mdns"
)

// mdnsDiscovery adapts *mdns.Discovery to the Discovery contract.
type mdnsDiscovery struct {
	disc *mdns.Discovery
}

// newMDNSDiscovery constructs a Discovery using luxfi/mdns. clientID
// is the calling service's mDNS name (used so other peers can see
// who is browsing them, useful for ops dashboards).
func newMDNSDiscovery(serviceType, clientID string, browseInterval time.Duration) *mdnsDiscovery {
	d := mdns.New(
		serviceType,
		clientID,
		0, // client-side: no advertised port
		mdns.WithBrowseInterval(browseInterval),
	)
	return &mdnsDiscovery{disc: d}
}

func (m *mdnsDiscovery) Start() error    { return m.disc.Start() }
func (m *mdnsDiscovery) Stop()           { m.disc.Stop() }
func (m *mdnsDiscovery) PeerCount() int  { return m.disc.PeerCount() }
func (m *mdnsDiscovery) ServiceType() string {
	return m.disc.ServiceType()
}

// Peers returns the current snapshot adapted to the local Peer shape.
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
			Metadata:    nil,
			LastSeen:    p.LastSeen,
		})
	}
	return out
}
