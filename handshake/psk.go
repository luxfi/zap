// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"sync"
	"time"
)

// PSKStore implements §12 PSK issuance and lookup on the responder.
//
//   - Issue records a fresh (psk_id, resumption_psk, client_id) at the
//     end of a full handshake.
//   - Redeem looks up a psk_id presented in HELLO_PSK; on hit it
//     atomically marks the entry consumed (single-use, §12.2).
//
// PSKs expire after PSKLifetimeSec. Expired or unknown lookups
// return (nil, false) and the caller MUST send ALERT 0x08.
//
// An ABSENT store (PSKStore == nil) disables resumption. The
// responder treats every HELLO_PSK as ErrPSKUnknown.
type PSKStore struct {
	mu      sync.Mutex
	entries map[[PSKIDLen]byte]*pskEntry
	ttl     time.Duration
	now     func() time.Time
}

type pskEntry struct {
	psk      [PSKKeyLen]byte
	clientID [IDLen]byte
	expires  time.Time
	redeemed bool
}

// NewPSKStore returns an empty in-memory store with §3's 3600s TTL.
func NewPSKStore() *PSKStore {
	return &PSKStore{
		entries: make(map[[PSKIDLen]byte]*pskEntry, 1024),
		ttl:     time.Duration(PSKLifetimeSec) * time.Second,
		now:     time.Now,
	}
}

// Issue records a PSK derived from the most recent full handshake.
// The psk_id is `SHA3-256(psk)[:16]` per §12.1. If a previous entry
// with the same psk_id exists (extremely unlikely — 128-bit ID
// collision), the new entry overwrites it.
func (s *PSKStore) Issue(psk [PSKKeyLen]byte, clientID [IDLen]byte) [PSKIDLen]byte {
	id := PSKID(psk)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = &pskEntry{
		psk:      psk,
		clientID: clientID,
		expires:  s.now().Add(s.ttl),
		redeemed: false,
	}
	return id
}

// Redeem looks up and atomically consumes a psk_id. Returns the
// cached resumption_psk and the issuing client_id on hit, or false
// for unknown / expired / already-redeemed entries.
//
// Single-use per §12.2: redemption deletes the entry whether the
// resumed handshake completes or not. A failed resumption forces the
// initiator into a fresh full handshake.
func (s *PSKStore) Redeem(id [PSKIDLen]byte) (psk [PSKKeyLen]byte, clientID [IDLen]byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, exists := s.entries[id]
	if !exists {
		return psk, clientID, false
	}
	if e.redeemed || s.now().After(e.expires) {
		delete(s.entries, id)
		return psk, clientID, false
	}
	e.redeemed = true
	out := e.psk
	cid := e.clientID
	delete(s.entries, id)
	return out, cid, true
}

// Sweep removes expired entries. Optional housekeeping; Redeem
// already handles expired lookups, but Sweep keeps memory bounded
// when many issued PSKs are never redeemed.
func (s *PSKStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, id)
		}
	}
}

// Len reports the current store size. Used by tests and metrics.
func (s *PSKStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// ClientPSK is the value the initiator caches after a successful full
// handshake. It is the §12.1 record minus the server-side state.
//
// PeerID is the verified responder identity from the ORIGINAL full
// handshake. The resumed handshake re-derives session keys but does
// NOT re-verify the responder's static_pk (possession of the PSK is
// the authentication, §12.2), so the trust anchor must be carried
// forward from when the responder's signature was last checked.
//
// Callers reading [Session.PeerID] after a resumed handshake see this
// value, ensuring authorization decisions remain anchored to the
// identity that the initiator originally pinned.
//
// Fields are exported ONLY to support persistence / serialization
// (KMS round-trip, sticky-session cache). Do NOT construct ClientPSK
// literals by hand — populating PeerID with a value that wasn't
// verified during the original handshake silently corrupts the
// resumed Session.PeerID() return. Always go through MakeClientPSK
// or copy a struct returned by Session.ResumptionPSK().
type ClientPSK struct {
	ID     [PSKIDLen]byte
	PSK    [PSKKeyLen]byte
	PeerID [IDLen]byte
	Until  time.Time
}

// MakeClientPSK packages a freshly-derived resumption_psk for the
// initiator to cache, applying §3's 3600s lifetime. peerID is the
// verified responder identity from the just-completed handshake.
func MakeClientPSK(psk [PSKKeyLen]byte, peerID [IDLen]byte, now time.Time) ClientPSK {
	return ClientPSK{
		ID:     PSKID(psk),
		PSK:    psk,
		PeerID: peerID,
		Until:  now.Add(time.Duration(PSKLifetimeSec) * time.Second),
	}
}
