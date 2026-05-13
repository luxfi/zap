package zapclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	zap "github.com/luxfi/zap"
)

func TestProcedureOpcode_Stable(t *testing.T) {
	a, err := ProcedureOpcode("ListSecurity")
	if err != nil {
		t.Fatalf("ProcedureOpcode: %v", err)
	}
	b, err := ProcedureOpcode("ListSecurity")
	if err != nil {
		t.Fatalf("ProcedureOpcode: %v", err)
	}
	if a != b {
		t.Errorf("opcode not stable: %#x vs %#x", a, b)
	}
	// Different names → almost-always different opcodes (8-bit space
	// allows collisions but the hashes should differ for these picks).
	c, _ := ProcedureOpcode("DelistSecurity")
	if c == a {
		t.Errorf("expected distinct opcodes for List/Delist, both = %#x", a)
	}
}

func TestProcedureOpcode_EmptyName(t *testing.T) {
	if _, err := ProcedureOpcode(""); err == nil {
		t.Errorf("empty procedure name should error")
	}
}

func TestProcedureOpcode_NeverReserved(t *testing.T) {
	// Bytes 0x00 and 0xff are reserved; ProcedureOpcode maps into
	// [1, 254] in the high byte. Spot-check across a wide name set.
	for _, name := range []string{
		"ListSecurity", "DelistSecurity", "AddIdentity", "AddIdentitiesBulk",
		"GetSnapshot", "PostJournal", "Settle", "Reverse",
		"a", "z", "X", "aaaaaaaaaa", "zzzzzzzz",
	} {
		op, err := ProcedureOpcode(name)
		if err != nil {
			t.Errorf("ProcedureOpcode(%q) err: %v", name, err)
			continue
		}
		hi := byte(op >> 8)
		if hi == 0x00 || hi == 0xff {
			t.Errorf("ProcedureOpcode(%q) = %#x falls in reserved range", name, op)
		}
	}
}

func TestRoundRobinPicker_NoPeers(t *testing.T) {
	var p RoundRobinPicker
	if _, err := p.Pick(nil); !errors.Is(err, ErrNoPeers) {
		t.Errorf("expected ErrNoPeers, got %v", err)
	}
}

func TestRoundRobinPicker_Cycles(t *testing.T) {
	peers := []Peer{{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}}
	var p RoundRobinPicker
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		got, err := p.Pick(peers)
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		seen[got.NodeID]++
	}
	for _, id := range []string{"a", "b", "c"} {
		if seen[id] != 3 {
			t.Errorf("peer %q hit %d times, want 3", id, seen[id])
		}
	}
}

func TestLocalTrustVerifier_AcceptsAuthenticatedPeer(t *testing.T) {
	v := LocalTrustVerifier{}
	err := v.Verify(context.Background(), PeerInfo{NodeID: "n1"}, "ListSecurity")
	if err != nil {
		t.Errorf("LocalTrustVerifier should accept authenticated peer, got %v", err)
	}
}

func TestLocalTrustVerifier_RejectsAnonymous(t *testing.T) {
	v := LocalTrustVerifier{}
	err := v.Verify(context.Background(), PeerInfo{}, "ListSecurity")
	if !errors.Is(err, ErrPeerUnauthorized) {
		t.Errorf("LocalTrustVerifier should reject anonymous peer, got %v", err)
	}
}

func TestAllowListVerifier(t *testing.T) {
	v := AllowListVerifier{
		Allowed: map[string]map[string]struct{}{
			"ListSecurity": {"bd-1": {}, "bd-2": {}},
		},
	}
	cases := []struct {
		peer string
		proc string
		ok   bool
	}{
		{"bd-1", "ListSecurity", true},
		{"bd-2", "ListSecurity", true},
		{"bd-3", "ListSecurity", false},      // not in allow list
		{"bd-1", "DelistSecurity", false},    // procedure not exposed
	}
	for _, tc := range cases {
		err := v.Verify(context.Background(), PeerInfo{NodeID: tc.peer}, tc.proc)
		if (err == nil) != tc.ok {
			t.Errorf("Verify(%q, %q): ok=%v, err=%v", tc.peer, tc.proc, tc.ok, err)
		}
	}
}

func TestServer_Register_OpcodeCollision(t *testing.T) {
	s, err := NewServer("test", WithNoDiscovery())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Stop()
	noop := func(ctx context.Context, _ PeerInfo, _ *zap.Message) (*zap.Message, error) {
		return nil, nil
	}
	// First procedure should register cleanly.
	if err := s.Register("ListSecurity", noop); err != nil {
		t.Fatalf("Register ListSecurity: %v", err)
	}
	// Find another name that hashes to the same opcode.
	target, _ := ProcedureOpcode("ListSecurity")
	collider := findCollider(t, "ListSecurity", target)
	err = s.Register(collider, noop)
	if err == nil {
		t.Errorf("expected collision rejection for %q vs ListSecurity", collider)
	}
}

// findCollider searches for a procedure name distinct from `excluding`
// whose opcode equals `target`. Brute-forces short alphabetic strings;
// in the 8-bit codespace a collision is almost always reachable
// within a few hundred candidates.
func findCollider(t *testing.T, excluding string, target uint16) string {
	t.Helper()
	for i := 0; i < 1<<16; i++ {
		name := generateName(i)
		if name == excluding {
			continue
		}
		op, err := ProcedureOpcode(name)
		if err != nil {
			continue
		}
		if op == target {
			return name
		}
	}
	t.Skipf("no collider found for opcode %#x within search bound", target)
	return ""
}

func generateName(i int) string {
	// Compact deterministic name space: 4-char strings over [a-z].
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	out := []byte{
		alpha[i/(26*26*26)%26],
		alpha[i/(26*26)%26],
		alpha[i/26%26],
		alpha[i%26],
	}
	return string(out)
}

// TestClient_Discover_Timeout exercises the timeout path when no
// peer is discovered.
func TestClient_Discover_Timeout(t *testing.T) {
	// Custom Discovery that never produces peers.
	c, err := Connect(context.Background(), "no-such-service",
		WithMinPeers(1),
		WithDiscoverTimeout(200*time.Millisecond),
		WithDiscovery(emptyDiscovery{}),
	)
	if err == nil {
		c.Close()
		t.Fatalf("expected timeout error")
	}
	if !contains(err.Error(), "timeout") {
		t.Errorf("expected timeout-shaped error, got %v", err)
	}
}

type emptyDiscovery struct{}

func (emptyDiscovery) Peers() []Peer        { return nil }
func (emptyDiscovery) PeerCount() int       { return 0 }
func (emptyDiscovery) ServiceType() string  { return "no-such-service" }
func (emptyDiscovery) Start() error         { return nil }
func (emptyDiscovery) Stop()                {}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestServer_RegisterAndStart_NoDiscovery: smoke test that the
// server can register + start + stop without a real network.
func TestServer_RegisterAndStart_NoDiscovery(t *testing.T) {
	s, err := NewServer("test-rpc", WithNoDiscovery())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hit := false
	var mu sync.Mutex
	if err := s.Register("Ping", func(ctx context.Context, _ PeerInfo, _ *zap.Message) (*zap.Message, error) {
		mu.Lock()
		hit = true
		mu.Unlock()
		return nil, nil
	}); err != nil {
		t.Fatalf("Register Ping: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Stop synchronously; we don't actually call into the handler,
	// just verify the boot/teardown path.
	s.Stop()
	if hit {
		t.Errorf("handler should not fire without an inbound call")
	}
}
