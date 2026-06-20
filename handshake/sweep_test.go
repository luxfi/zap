// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"testing"
	"time"
)

// TestReplayCacheSweepRemovesExpired: after enough time has passed
// (3×ttl past the original generation's frozenAt), entries from
// the original cycle are gone from both generations.
//
// The two-generation rotation drops the frozen generation when a new
// rotation happens; entries are remembered for between ttl and 2×ttl
// seconds before disappearing. We step 3×ttl to guarantee disappearance.
func TestReplayCacheSweepRemovesExpired(t *testing.T) {
	c := NewReplayCache()
	cur := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return cur }
	c.ttl = time.Second
	c.frozenAt = cur

	// Insert 3 entries at t=0.
	for i := 0; i < 3; i++ {
		var id [IDLen]byte
		id[0] = byte(i)
		var rnd [ClientRandLen]byte
		rnd[0] = byte(i)
		c.SeenOrAdd(id, rnd)
	}
	if c.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", c.Len())
	}

	// Advance past 2×ttl so the old generation rotates out, then
	// advance once more so the freshly-inserted-and-immediately-rotated
	// entries also cycle out.
	cur = cur.Add(3 * time.Second)

	// Trigger generation flip and confirm the originals are gone
	// from active. The rotated-in-frozen generation holds them for
	// another ttl, but we want to verify "Sweep + advance again"
	// fully clears them.
	c.Sweep()
	cur = cur.Add(2 * time.Second)
	c.Sweep()

	if c.Len() != 0 {
		t.Fatalf("after 5×ttl + double-sweep, expected 0 entries, got %d", c.Len())
	}
}

// TestReplayCacheSweepNoOpWhenAllFresh: Sweep on a fully-fresh cache
// removes nothing.
func TestReplayCacheSweepNoOpWhenAllFresh(t *testing.T) {
	c := NewReplayCache()
	for i := 0; i < 8; i++ {
		var id [IDLen]byte
		id[0] = byte(i)
		var rnd [ClientRandLen]byte
		rnd[0] = byte(i)
		c.SeenOrAdd(id, rnd)
	}
	before := c.Len()
	c.Sweep()
	if c.Len() != before {
		t.Fatalf("sweep removed %d fresh entries", before-c.Len())
	}
}

// TestPSKStoreSweepRemovesExpired: same property for PSKStore.
func TestPSKStoreSweepRemovesExpired(t *testing.T) {
	s := NewPSKStore()
	cur := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return cur }
	s.ttl = time.Second

	var ids [][PSKIDLen]byte
	for i := 0; i < 3; i++ {
		var psk [PSKKeyLen]byte
		psk[0] = byte(i)
		var cid [IDLen]byte
		cid[0] = byte(i)
		ids = append(ids, s.Issue(psk, cid))
	}
	if s.Len() != 3 {
		t.Fatalf("expected 3, got %d", s.Len())
	}

	cur = cur.Add(2 * time.Second)
	s.Sweep()
	if s.Len() != 0 {
		t.Fatalf("expired entries not swept: %d remain", s.Len())
	}
	// Each Redeem on a swept ID returns !ok.
	for _, id := range ids {
		if _, _, ok := s.Redeem(id); ok {
			t.Fatalf("Redeem succeeded on swept PSK")
		}
	}
}

// TestPSKStoreSweepKeepsLive: Sweep keeps live entries, removes
// expired ones; Redeem on a live one still works after the sweep.
func TestPSKStoreSweepKeepsLive(t *testing.T) {
	s := NewPSKStore()
	cur := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return cur }
	s.ttl = time.Second

	// Old entry.
	var oldPSK [PSKKeyLen]byte
	oldPSK[0] = 0x01
	s.Issue(oldPSK, [IDLen]byte{0xAA})

	// Advance past TTL.
	cur = cur.Add(2 * time.Second)

	// New entry at t=2s.
	var newPSK [PSKKeyLen]byte
	newPSK[0] = 0x02
	newCID := [IDLen]byte{0xBB}
	newID := s.Issue(newPSK, newCID)

	s.Sweep()
	if s.Len() != 1 {
		t.Fatalf("expected 1 live entry, got %d", s.Len())
	}

	gotPSK, gotCID, ok := s.Redeem(newID)
	if !ok {
		t.Fatal("live entry not redeemable after sweep")
	}
	if gotPSK != newPSK || gotCID != newCID {
		t.Fatal("Redeem returned wrong values")
	}
}

// TestMakeClientPSKTimingFields ensures the helper sets Until at
// now+PSKLifetimeSec and carries the peerID forward — the client
// uses Until to decide whether to resume and PeerID to anchor the
// resumed Session's verified-peer identity (see H-1 regression
// guard in resume_test.go).
func TestMakeClientPSKTimingFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var psk [PSKKeyLen]byte
	psk[0] = 0xAA
	peerID := bytesToArr32(bytesPattern(0x55, IDLen))
	c := MakeClientPSK(psk, peerID, now)
	if c.PSK != psk {
		t.Fatal("PSK mismatch")
	}
	if c.ID != PSKID(psk) {
		t.Fatal("ID mismatch")
	}
	if c.PeerID != peerID {
		t.Fatal("PeerID not carried into ClientPSK")
	}
	want := now.Add(time.Duration(PSKLifetimeSec) * time.Second)
	if !c.Until.Equal(want) {
		t.Fatalf("Until = %v, want %v", c.Until, want)
	}
}
