// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"sync"
	"time"
)

// ReplayCache holds the §11 nonce-cache state for a Responder.
//
// Two independent gates protect against replay:
//
//  1. Timestamp window: |now - timestamp_ns| ≤ 30s
//  2. Nonce cache: dedup on (client_id, client_random)
//
// Implementation: a two-generation map rotated every TTL window.
// New entries land in `active`; on insert we also probe `frozen`
// (the previous generation, still inside its TTL). When `now -
// frozenAt >= ttl`, `frozen` is dropped wholesale and the current
// `active` becomes the new `frozen`. This is O(1) per insert and
// O(1) per generation-flip (just rebind the map pointers). The
// worst-case admission window is between ttl and 2×ttl — any
// (id, rand) tuple is remembered for AT LEAST ttl seconds after
// its first appearance, which is what §11 requires.
//
// Memory bound: 2× maxLen entries (one ttl-window of each
// generation). At the §3 design budget of 2^20 entries per
// generation, that's ~6 MiB of `(clientID, clientRandom)` tuples in
// memory — within the 4 MiB Cuckoo target order-of-magnitude, with
// the operational advantage of O(1) flush instead of O(N) sweep.
//
// The previous implementation (single map + inline sweep at
// maxLen) was correct but degraded to O(N) per insert once the cap
// was reached, which a fuzzer or attacker can drive into the slow
// path. The two-generation rotation eliminates that.
type ReplayCache struct {
	mu       sync.Mutex
	active   map[replayKey]struct{}
	frozen   map[replayKey]struct{}
	frozenAt time.Time
	ttl      time.Duration
	maxLen   int // per-generation cap
	now      func() time.Time
}

type replayKey struct {
	clientID     [IDLen]byte
	clientRandom [ClientRandLen]byte
}

// NewReplayCache returns a ReplayCache with the §3 default TTL of 60s
// and a 2^20 per-generation entry cap.
func NewReplayCache() *ReplayCache {
	now := time.Now()
	return &ReplayCache{
		active:   make(map[replayKey]struct{}, 1<<14),
		frozen:   make(map[replayKey]struct{}, 1<<14),
		frozenAt: now,
		ttl:      time.Duration(ReplayCacheTTLSec) * time.Second,
		maxLen:   1 << 20,
		now:      time.Now,
	}
}

// SeenOrAdd reports whether (clientID, clientRandom) was seen within
// the TTL window. If not, the tuple is recorded and false is
// returned. A return of true means the caller MUST refuse the
// handshake with ErrReplayDetected.
//
// Returning true on cache saturation is fail-closed: if we cannot
// remember a tuple, we refuse it rather than risk admitting a replay.
func (c *ReplayCache) SeenOrAdd(clientID [IDLen]byte, clientRandom [ClientRandLen]byte) bool {
	key := replayKey{clientID: clientID, clientRandom: clientRandom}
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Generation flip: if the frozen generation has aged past TTL,
	// drop it and rotate `active` into `frozen`. The next ttl
	// window starts now.
	if now.Sub(c.frozenAt) >= c.ttl {
		c.frozen = c.active
		c.active = make(map[replayKey]struct{}, 1<<14)
		c.frozenAt = now
	}

	if _, ok := c.frozen[key]; ok {
		return true
	}
	if _, ok := c.active[key]; ok {
		return true
	}

	if len(c.active) >= c.maxLen {
		// Cap reached for this generation. Fail-closed rather than
		// silently evicting unrelated entries.
		return true
	}

	c.active[key] = struct{}{}
	return false
}

// CheckTimestamp implements the §11 ±30s window. Returns nil when
// inside the window, ErrReplayDetected otherwise.
func (c *ReplayCache) CheckTimestamp(timestampNS uint64) error {
	now := c.now().UnixNano()
	if now < 0 {
		return ErrReplayDetected
	}
	skew := int64(timestampNS) - now
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(ReplayWindowNS) {
		return ErrReplayDetected
	}
	return nil
}

// Sweep is a no-op under the two-generation design. The frozen
// generation is dropped on the next SeenOrAdd call past its TTL;
// callers do not need to invoke Sweep explicitly. Retained for API
// compatibility.
func (c *ReplayCache) Sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Sub(c.frozenAt) >= c.ttl {
		c.frozen = c.active
		c.active = make(map[replayKey]struct{}, 1<<14)
		c.frozenAt = now
	}
}

// Len reports the current cache size summed across both
// generations. Used by tests and metrics. Operationally it can
// briefly exceed maxLen up to 2×maxLen during the overlap window.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.active) + len(c.frozen)
}
