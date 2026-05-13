package clienthttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRoundRobinPicker_NoPeers(t *testing.T) {
	var p RoundRobinPicker
	if _, err := p.Pick(nil); !errors.Is(err, ErrNoPeers) {
		t.Errorf("expected ErrNoPeers on empty peer list, got %v", err)
	}
}

func TestRoundRobinPicker_Cycles(t *testing.T) {
	peers := []Peer{
		{NodeID: "a", Address: "1"},
		{NodeID: "b", Address: "2"},
		{NodeID: "c", Address: "3"},
	}
	var p RoundRobinPicker
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		got, err := p.Pick(peers)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		seen[got.NodeID]++
	}
	for _, id := range []string{"a", "b", "c"} {
		if seen[id] != 2 {
			t.Errorf("peer %q hit %d times, want 2 (seen=%v)", id, seen[id], seen)
		}
	}
}

// staticDiscovery is a fake Discovery returning a fixed peer set.
type staticDiscovery struct {
	mu          sync.Mutex
	peers       []Peer
	serviceType string
}

func (s *staticDiscovery) Peers() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Peer, len(s.peers))
	copy(out, s.peers)
	return out
}
func (s *staticDiscovery) PeerCount() int      { s.mu.Lock(); defer s.mu.Unlock(); return len(s.peers) }
func (s *staticDiscovery) ServiceType() string { return s.serviceType }
func (s *staticDiscovery) Start() error        { return nil }
func (s *staticDiscovery) Stop()               {}

// rewriteDialer is a fake Dialer that returns a RoundTripper which
// rewrites the request URL to point at a fixed test target. This lets
// the test exercise the full transport composition against a plain
// httptest.Server while the "peer address" remains an opaque token.
type rewriteDialer struct {
	target *url.URL
}

func (d *rewriteDialer) Dial(_ context.Context, _ Peer) (http.RoundTripper, error) {
	return &rewriteTransport{target: d.target}, nil
}

type rewriteTransport struct {
	target *url.URL
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Scheme = rt.target.Scheme
	r2.URL.Host = rt.target.Host
	r2.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(r2)
}

// TestNewClient_AttachesBearer verifies BearerAttacher actually sets
// Authorization on outgoing requests when configured via WithBearer.
func TestNewClient_AttachesBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)

	disc := &staticDiscovery{
		serviceType: "test",
		peers:       []Peer{{NodeID: "a", Address: target.Host, ServiceType: "test"}},
	}
	dialer := &rewriteDialer{target: target}

	c, stop, err := NewClient("test",
		WithDiscovery(disc),
		WithDialer(dialer),
		WithBearer("hello"),
		WithMinPeers(1),
		WithDiscoverTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer stop()

	resp, err := c.Get("http://test/ping")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer hello" {
		t.Errorf("Authorization = %q, want Bearer hello", gotAuth)
	}
}

// TestNewClient_LocalTrust_NoAuth verifies WithLocalTrust skips the
// Authorization header — trust comes from the ZAP+mDNS scope.
func TestNewClient_LocalTrust_NoAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)

	disc := &staticDiscovery{
		serviceType: "test",
		peers:       []Peer{{NodeID: "a", Address: target.Host, ServiceType: "test"}},
	}
	dialer := &rewriteDialer{target: target}

	c, stop, err := NewClient("test",
		WithDiscovery(disc),
		WithDialer(dialer),
		WithLocalTrust(),
		WithMinPeers(1),
		WithDiscoverTimeout(2*time.Second),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer stop()

	resp, err := c.Get("http://test/ping")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty under WithLocalTrust", gotAuth)
	}
}

// TestNewClient_PerCallAuthOverridesDefault verifies a per-call
// Authorization header beats the configured bearer.
func TestNewClient_PerCallAuthOverridesDefault(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)

	disc := &staticDiscovery{
		serviceType: "test",
		peers:       []Peer{{NodeID: "a", Address: target.Host, ServiceType: "test"}},
	}
	dialer := &rewriteDialer{target: target}

	c, stop, err := NewClient("test",
		WithDiscovery(disc),
		WithDialer(dialer),
		WithBearer("default-bearer"),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer stop()

	req, _ := http.NewRequest("GET", "http://test/ping", nil)
	req.Header.Set("Authorization", "Bearer per-call-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer per-call-token" {
		t.Errorf("Authorization = %q, want Bearer per-call-token", gotAuth)
	}
}

// TestNewClient_NoServiceTypeErrors verifies the boundary check.
func TestNewClient_NoServiceTypeErrors(t *testing.T) {
	_, _, err := NewClient("")
	if err == nil || !strings.Contains(err.Error(), "serviceType is required") {
		t.Errorf("expected serviceType-required error, got %v", err)
	}
}
