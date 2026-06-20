// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestReplayCacheConcurrentSeenOrAdd hammers SeenOrAdd from many
// goroutines using distinct (id, rand) tuples — the operation MUST
// be linearisable: total accepted = total inserted, no spurious
// "seen" return values for fresh keys.
//
// Run with -race to assert no data race on the underlying map.
func TestReplayCacheConcurrentSeenOrAdd(t *testing.T) {
	c := NewReplayCache()
	const G = 16
	const N = 64

	var collisions int64
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		g := g
		go func() {
			defer wg.Done()
			var id [IDLen]byte
			id[0] = byte(g)
			for i := 0; i < N; i++ {
				var rnd [ClientRandLen]byte
				rnd[0] = byte(i)
				rnd[1] = byte(g)
				if c.SeenOrAdd(id, rnd) {
					atomic.AddInt64(&collisions, 1)
				}
			}
		}()
	}
	wg.Wait()

	if collisions != 0 {
		t.Fatalf("unexpected collisions on distinct keys: %d", collisions)
	}
	if got, want := c.Len(), G*N; got != want {
		t.Fatalf("cache len %d, want %d", got, want)
	}
}

// TestReplayCacheConcurrentDuplicateKey: many goroutines racing on
// the SAME tuple. Exactly one MUST get "not seen", every other MUST
// see the replay flag.
func TestReplayCacheConcurrentDuplicateKey(t *testing.T) {
	c := NewReplayCache()
	const G = 32
	var id [IDLen]byte
	id[0] = 0xAB
	var rnd [ClientRandLen]byte
	rnd[0] = 0xCD

	var firstAccepts int64
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		go func() {
			defer wg.Done()
			if !c.SeenOrAdd(id, rnd) {
				atomic.AddInt64(&firstAccepts, 1)
			}
		}()
	}
	wg.Wait()
	if firstAccepts != 1 {
		t.Fatalf("expected exactly 1 acceptance, got %d", firstAccepts)
	}
}

// TestPSKStoreConcurrentIssueRedeem fires Issue / Redeem from many
// goroutines on independent PSKs and confirms the count of
// successful redemptions matches the count of issued PSKs.
func TestPSKStoreConcurrentIssueRedeem(t *testing.T) {
	store := NewPSKStore()
	const G = 16
	const N = 32

	var issued, redeemed int64
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		g := g
		go func() {
			defer wg.Done()
			ids := make([][PSKIDLen]byte, 0, N)
			for i := 0; i < N; i++ {
				var psk [PSKKeyLen]byte
				psk[0] = byte(g)
				psk[1] = byte(i)
				var cid [IDLen]byte
				cid[0] = byte(g)
				ids = append(ids, store.Issue(psk, cid))
				atomic.AddInt64(&issued, 1)
			}
			for _, id := range ids {
				if _, _, ok := store.Redeem(id); ok {
					atomic.AddInt64(&redeemed, 1)
				}
			}
		}()
	}
	wg.Wait()
	if issued != redeemed {
		t.Fatalf("issued=%d redeemed=%d", issued, redeemed)
	}
	if store.Len() != 0 {
		t.Fatalf("store not empty: %d", store.Len())
	}
}

// TestPSKStoreConcurrentSingleUse: many goroutines race to redeem
// the same psk_id. Exactly one MUST succeed.
func TestPSKStoreConcurrentSingleUse(t *testing.T) {
	store := NewPSKStore()
	var psk [PSKKeyLen]byte
	psk[0] = 0xFF
	var cid [IDLen]byte
	id := store.Issue(psk, cid)

	const G = 64
	var successes int64
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		go func() {
			defer wg.Done()
			if _, _, ok := store.Redeem(id); ok {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful Redeem, got %d", successes)
	}
}

// TestReplayCacheCapacityFailClosed: at the maxLen bound, a fresh
// SeenOrAdd MUST return true (fail-closed) rather than evicting
// unrelated entries.
func TestReplayCacheCapacityFailClosed(t *testing.T) {
	c := NewReplayCache()
	c.maxLen = 4

	for i := 0; i < c.maxLen; i++ {
		var id [IDLen]byte
		id[0] = byte(i)
		var rnd [ClientRandLen]byte
		rnd[0] = byte(i)
		if c.SeenOrAdd(id, rnd) {
			t.Fatalf("entry %d unexpectedly marked seen", i)
		}
	}
	// One past capacity, fresh key, all entries still in window.
	var id [IDLen]byte
	id[0] = 0xFF
	var rnd [ClientRandLen]byte
	rnd[0] = 0xFF
	if !c.SeenOrAdd(id, rnd) {
		t.Fatal("capacity-exhausted cache must fail closed")
	}
}
