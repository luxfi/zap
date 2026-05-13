package clienthttp

import (
	"errors"
	"testing"

	"github.com/luxfi/mdns"
)

func TestRoundRobinPicker_NoPeers(t *testing.T) {
	var p RoundRobinPicker
	if _, err := p.Pick(nil); !errors.Is(err, ErrNoPeers) {
		t.Errorf("expected ErrNoPeers on empty peer list, got %v", err)
	}
}

func TestRoundRobinPicker_Cycles(t *testing.T) {
	peers := []*mdns.Peer{
		{NodeID: "a"},
		{NodeID: "b"},
		{NodeID: "c"},
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
	// 2 hits each in 6 round-robin selections from a 3-peer pool.
	for _, id := range []string{"a", "b", "c"} {
		if seen[id] != 2 {
			t.Errorf("peer %q hit %d times, want 2 (seen=%v)", id, seen[id], seen)
		}
	}
}
