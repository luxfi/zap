// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"testing"
	"time"
)

// TestReplayCacheTTLExpiry verifies entries past the TTL no longer
// count as seen. The two-generation design retains entries between
// ttl and 2×ttl seconds; we step past 3×ttl to guarantee the entry
// has cycled out of both `active` and `frozen`.
func TestReplayCacheTTLExpiry(t *testing.T) {
	c := NewReplayCache()
	cur := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return cur }
	c.ttl = time.Second
	c.frozenAt = cur

	id := bytesToArr32(bytesPattern(0x01, IDLen))
	rnd := bytesToArr16(bytesPattern(0x02, ClientRandLen))

	if c.SeenOrAdd(id, rnd) {
		t.Fatal("fresh entry flagged as seen")
	}
	if !c.SeenOrAdd(id, rnd) {
		t.Fatal("immediate replay not detected")
	}

	// Step past ttl to trigger the first rotation (key moves from
	// active to frozen but is still remembered).
	cur = cur.Add(2 * time.Second)
	if !c.SeenOrAdd(id, rnd) {
		t.Fatal("entry within 2×ttl should still be remembered")
	}
	// Step past ttl AGAIN to trigger the second rotation (key drops
	// out of frozen). Now the cache has fully forgotten the entry.
	cur = cur.Add(2 * time.Second)
	if c.SeenOrAdd(id, rnd) {
		t.Fatal("expired entry still flagged after two rotations")
	}
}

// TestReplayCacheTimestampWindow verifies the §11 ±30s window.
func TestReplayCacheTimestampWindow(t *testing.T) {
	c := NewReplayCache()
	cur := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return cur }

	if err := c.CheckTimestamp(uint64(cur.UnixNano())); err != nil {
		t.Fatalf("current ts refused: %v", err)
	}
	if err := c.CheckTimestamp(uint64(cur.Add(20 * time.Second).UnixNano())); err != nil {
		t.Fatalf("+20s ts refused: %v", err)
	}
	if err := c.CheckTimestamp(uint64(cur.Add(31 * time.Second).UnixNano())); err == nil {
		t.Fatal("+31s ts admitted")
	}
	if err := c.CheckTimestamp(uint64(cur.Add(-31 * time.Second).UnixNano())); err == nil {
		t.Fatal("-31s ts admitted")
	}
}
