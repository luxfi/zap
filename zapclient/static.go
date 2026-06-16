// static.go — a fixed peer-address Discovery, bypassing mDNS.
//
// This is what WithStaticPeers builds: the cloud/K8s path where peers
// are reached by a known address (a Service DNS name). The NodeID is a
// placeholder for observability — the real peer identity is learned at
// dial time (Node.ConnectDirectID) and authenticated by the mTLS peer
// cert, so the client addresses Calls by the learned id, not this one.

package zapclient

import (
	"strconv"
	"sync"
	"time"
)

type staticDiscovery struct {
	serviceType string
	mu          sync.RWMutex
	peers       []Peer
}

func newStaticDiscovery(serviceType string, addrs []string) *staticDiscovery {
	now := time.Now()
	peers := make([]Peer, 0, len(addrs))
	for i, addr := range addrs {
		if addr == "" {
			continue
		}
		peers = append(peers, Peer{
			NodeID:      serviceType + "-static-" + strconv.Itoa(i),
			ServiceType: serviceType,
			Address:     addr,
			LastSeen:    now,
		})
	}
	return &staticDiscovery{serviceType: serviceType, peers: peers}
}

func (s *staticDiscovery) Peers() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Peer, len(s.peers))
	copy(out, s.peers)
	return out
}

func (s *staticDiscovery) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

func (s *staticDiscovery) ServiceType() string { return s.serviceType }
func (s *staticDiscovery) Start() error        { return nil }
func (s *staticDiscovery) Stop()               {}

var _ Discovery = (*staticDiscovery)(nil)
