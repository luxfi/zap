// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"testing"
	"time"
)

// TestPSKStoreIssueAndRedeem confirms Issue → Redeem returns the
// same psk and client_id, and that a second redemption fails
// (single-use, §12.2).
func TestPSKStoreIssueAndRedeem(t *testing.T) {
	store := NewPSKStore()
	psk := bytesToArr32(bytesPattern(0x40, PSKKeyLen))
	cid := bytesToArr32(bytesPattern(0x50, IDLen))

	id := store.Issue(psk, cid)
	if store.Len() != 1 {
		t.Fatalf("Len after issue: %d", store.Len())
	}

	gotPSK, gotCID, ok := store.Redeem(id)
	if !ok {
		t.Fatal("Redeem returned !ok for fresh PSK")
	}
	if gotPSK != psk {
		t.Fatal("Redeem returned wrong psk")
	}
	if gotCID != cid {
		t.Fatal("Redeem returned wrong client_id")
	}
	if store.Len() != 0 {
		t.Fatalf("PSK not deleted after redeem: Len=%d", store.Len())
	}

	if _, _, ok := store.Redeem(id); ok {
		t.Fatal("Redeem after single-use returned ok")
	}
}

// TestPSKStoreExpiry covers §12.1's 3600s TTL — an expired entry
// must Redeem as !ok and be evicted.
func TestPSKStoreExpiry(t *testing.T) {
	store := NewPSKStore()
	cur := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return cur }

	psk := bytesToArr32(bytesPattern(0x40, PSKKeyLen))
	cid := bytesToArr32(bytesPattern(0x50, IDLen))
	id := store.Issue(psk, cid)

	cur = cur.Add(time.Duration(PSKLifetimeSec+1) * time.Second)
	if _, _, ok := store.Redeem(id); ok {
		t.Fatal("expired PSK redeemed")
	}
	if store.Len() != 0 {
		t.Fatalf("expired PSK retained: Len=%d", store.Len())
	}
}
