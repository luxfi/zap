// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"crypto/rand"
	"errors"
)

// capability.go is the Cap'n-Proto-style authority model. A capability is an
// unforgeable reference to a NARROW slice of authority. The defining property of
// this whole layer:
//
//	NO CAPABILITY CAN MINT OR CREDIT A C BALANCE.
//
// This is true by EXHAUSTION, not by a runtime check alone. Enumerate the entire
// method set a capability can reach:
//
//	QuoteCap       -> Quote, GetState                  (READ)
//	IntentCap      -> PrepareSwapIntent, NotifyIntent   (BUILD calldata / trigger D scan)
//	WatchCap       -> Poll, OnCommitted                 (SUBSCRIBE)
//	SettlementCap  -> ImportSettlement                  (POINT at an existing D->C object)
//	AdminCap       -> Halt, Status                      (kill-switch / status only)
//
// There is NO creditBalance, settleFill, overrideMatch, adminWithdraw, mint, or
// any method that returns or asserts a balance change. The build methods return
// CALLDATA (bytes the user signs); the point method returns CALLDATA / a tx hash
// that names an object the chain independently verifies. So even a capability with
// EVERY authority bit set cannot move money — there is nothing value-moving to
// invoke. The Authority bitmask below is defence in depth on top of a surface that
// is value-free by construction.

// Authority is a bitmask of the operation classes a capability permits. Each bit
// maps to exactly one capability type; a bit grants ONLY the read/build/point/
// subscribe operations of that class — never a credit.
type Authority uint32

const (
	AuthQuote      Authority = 1 << 0 // read book/state (Quote, GetState)
	AuthIntent     Authority = 1 << 1 // build a C->D intent + notify (PrepareSwapIntent, NotifyIntent)
	AuthWatch      Authority = 1 << 2 // subscribe to a D result (Poll, OnCommitted)
	AuthSettlement Authority = 1 << 3 // point C at an existing D->C object (ImportSettlement)
	AuthAdmin      Authority = 1 << 4 // halt / status only (separately gated)
)

// AuthorityPublic is the grant a public API surface bootstraps with: everything a
// user needs to trade end-to-end, WITHOUT admin. Note this is the maximal
// user-facing grant and it STILL cannot move money — see the package invariant.
const AuthorityPublic = AuthQuote | AuthIntent | AuthWatch | AuthSettlement

// AuthorityReadOnly is a quote/state-only grant (e.g. a price widget).
const AuthorityReadOnly = AuthQuote

var (
	// ErrNoAuthority is returned when a session/capability is asked for an
	// operation outside its granted authority. Fail-closed: deny, never widen.
	ErrNoAuthority = errors.New("dexsession: capability lacks the required authority")
	// ErrRevoked is returned when a capability has been revoked at the session.
	ErrRevoked = errors.New("dexsession: capability revoked")
)

// token is a 32-byte unforgeable capability reference. It is generated with
// crypto/rand at grant time and never leaves the process boundary in a form a
// caller can mint: you obtain a capability ONLY by asking a session that holds the
// authority, and the session hands back a value whose token it generated. There is
// no exported constructor that takes a token, so a caller cannot fabricate a
// higher-authority capability.
type token [32]byte

func newToken() token {
	var t token
	// crypto/rand.Read never returns a short read on success; a failure here means
	// the OS RNG is unavailable, which is unrecoverable for a security token —
	// surface it by leaving the token zero, which the session's grant set will
	// reject (a zero token is never registered). Callers see ErrNoAuthority.
	_, _ = rand.Read(t[:])
	return t
}

// grant is the authority record a session keeps per issued capability. The token
// is the key; the bits are what it permits; revoked flips it off without
// forgetting (so a replayed token after revocation is explicitly ErrRevoked, not
// a silent miss).
type grant struct {
	bits    Authority
	revoked bool
}

// capCore is the unexported shared state every capability points at. It binds a
// capability to its issuing session's grant table, so authority is checked at the
// session of record — a capability cannot outlive or out-scope its session.
type capCore struct {
	session *clientSession
	tok     token
	bits    Authority
}

// authorize verifies the capability still holds `need` authority at its session.
// The check is at the SESSION of record (not the capability's own cached bits) so
// a revocation takes effect immediately. The cached bits are an early-out only.
func (c *capCore) authorize(need Authority) error {
	if c == nil || c.session == nil {
		return ErrNoAuthority
	}
	if c.bits&need != need {
		return ErrNoAuthority
	}
	return c.session.checkGrant(c.tok, need)
}

// --- The five capability types. Each exposes ONLY its class of operations. ----
//
// A capability is a thin typed handle over capCore: the type system is the first
// line ("a QuoteCap has no ImportSettlement method"), the authority gate is the
// second ("even if you somehow held the core, the bits must permit it"), and the
// surface being value-free is the third (no method moves money at all).

// QuoteCap permits read-only book/state queries. It can quote and observe; it
// cannot build an intent, notify, settle, or administer.
type QuoteCap struct{ core *capCore }

// IntentCap permits requesting a C->D intent (build calldata) and notifying D to
// scan/import the resulting object. It cannot reserve funds, claim a fill, credit,
// or settle.
type IntentCap struct{ core *capCore }

// WatchCap permits subscribing to a notified intent's D result. It cannot move
// value; OnCommitted yields a POINTER (DExportRef), not a credit.
type WatchCap struct{ core *capCore }

// SettlementCap permits asking C to import an EXISTING D->C object (build the
// finalization calldata / submit a pointing tx). It cannot credit C through RPC,
// nor substitute recipient/asset/amount — the chain binds those to the object.
type SettlementCap struct{ core *capCore }

// AdminCap permits halt/status only, and is granted SEPARATELY (AuthAdmin is not
// in AuthorityPublic). It cannot withdraw, credit, or override a match.
type AdminCap struct{ core *capCore }

// Authority reports the bits each capability was granted (introspection / tests).
func (c QuoteCap) Authority() Authority      { return c.core.bits }
func (c IntentCap) Authority() Authority     { return c.core.bits }
func (c WatchCap) Authority() Authority      { return c.core.bits }
func (c SettlementCap) Authority() Authority { return c.core.bits }
func (c AdminCap) Authority() Authority      { return c.core.bits }
