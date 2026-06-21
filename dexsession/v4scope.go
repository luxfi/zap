// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// v4scope.go is the PER-ACTION capability confinement. The existing capability.go
// gates by operation CLASS (a QuoteCap can quote, a SettlementCap can point). A V4
// session needs a finer grant: a capability bound to ONE V4 action — one swap, one
// route, one position commit. Holding a swap session's capability must not let you
// drive a DIFFERENT intent, pool, or params, nor a different action kind.
//
// This is defence in depth on top of the value-free surface: even though NO message
// moves money, scoping each session to one action means a leaked/confused capability
// cannot redirect orchestration onto a victim's intent (e.g. notify D about, or build
// settlement calldata for, an intent the holder was not granted). The scope is bound
// at open time and checked on every session operation; a mismatch fails closed.

// V4Action is the kind of V4 action a session capability is scoped to. A scoped
// capability is confined to exactly one kind — a swap cap cannot drive a liquidity
// action and vice versa.
type V4Action uint8

const (
	ActionSwap V4Action = iota
	ActionRoute
	ActionModifyLiquidity
	ActionCollect
	ActionCancel
	ActionState
)

func (a V4Action) String() string {
	switch a {
	case ActionSwap:
		return "swap"
	case ActionRoute:
		return "route"
	case ActionModifyLiquidity:
		return "modifyLiquidity"
	case ActionCollect:
		return "collect"
	case ActionCancel:
		return "cancel"
	case ActionState:
		return "state"
	default:
		return "unknown"
	}
}

var (
	// ErrScopeMismatch is returned when a session capability is used for an action
	// (intent / pool / params / kind) it was not scoped to. Fail-closed.
	ErrScopeMismatch = errors.New("dexsession: capability is scoped to a different V4 action")
	// ErrScopeUnset is returned when a scoped operation is attempted on a session
	// whose scope was never bound (a zero scope never authorizes).
	ErrScopeUnset = errors.New("dexsession: V4 session scope is unset")
)

// V4ActionScope binds a session capability to ONE V4 action. Every field that
// distinguishes one action from another is here; DeriveSessionID hashes them into a
// stable id. Two sessions for different intents/pools/params/kinds derive different
// ids and their capabilities cannot be cross-used.
//
//	NetworkID    — the Lux network the action runs on.
//	CChainID     — the C-Chain (EVM balance authority).
//	DChainID     — the D-Chain (matching authority).
//	Addr9999     — the on-chain settlement authority (the precompile address).
//	Account      — the caller / account the action is for (bound as the object owner).
//	PoolKeyHash  — hash of the V4 PoolKey (which market). For a route, hash of the
//	               whole path (see DeriveRoutePathHash).
//	ParamsHash   — hash of the action params (direction+amount for a swap; tick range
//	               +delta for liquidity; the collected/cancelled selector for those).
//	Kind         — the V4Action this scope permits.
//	IntentID     — the deterministic intent id (for swap/route) the action targets.
//	               Zero for actions whose object is not an intent (a position commit
//	               binds by PoolKeyHash+ParamsHash+Account instead).
type V4ActionScope struct {
	NetworkID   uint32
	CChainID    ID
	DChainID    ID
	Addr9999    Account
	Account     Account
	PoolKeyHash ID
	ParamsHash  ID
	Kind        V4Action
	IntentID    ID
}

// v4ScopeDomain separates the session-id hash from every other id in the system, so
// a session id can never collide with an intent id, a UTXO id, or an asset id.
const v4ScopeDomain = "lux.dex.v4.session.v1"

// DeriveSessionID is the stable, deterministic id of a V4 action scope. It binds
// EVERY distinguishing field, so the id is a faithful fingerprint of the action: any
// change to network/chain/account/pool/params/kind/intent yields a different id, and
// a capability presented for one session id cannot satisfy another.
func DeriveSessionID(s V4ActionScope) ID {
	h := sha256.New()
	h.Write([]byte(v4ScopeDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], s.NetworkID)
	h.Write(u4[:])
	h.Write(s.CChainID[:])
	h.Write(s.DChainID[:])
	h.Write(s.Addr9999[:])
	h.Write(s.Account[:])
	h.Write(s.PoolKeyHash[:])
	h.Write(s.ParamsHash[:])
	h.Write([]byte{byte(s.Kind)})
	h.Write(s.IntentID[:])
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}

// DerivePoolKeyHash hashes a V4 PoolKey tuple into the scope's PoolKeyHash. It binds
// the exact market a session may act on; a capability for pool P1 cannot drive pool
// P2 because the derived session ids differ.
func DerivePoolKeyHash(pk PoolKeyArgs) ID {
	h := sha256.New()
	h.Write([]byte("lux.dex.v4.poolkey.v1"))
	h.Write(pk.Currency0[:])
	h.Write(pk.Currency1[:])
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], pk.Fee)
	h.Write(u4[:])
	binary.BigEndian.PutUint32(u4[:], uint32(pk.TickSpacing))
	h.Write(u4[:])
	h.Write(pk.Hooks[:])
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}

// DeriveSwapParamsHash hashes the swap-defining params (direction + exact-input
// amount) into the scope's ParamsHash. Two swaps that differ in direction or amount
// derive different session ids — a capability for one cannot drive the other.
func DeriveSwapParamsHash(zeroForOne bool, amountIn uint64) ID {
	h := sha256.New()
	h.Write([]byte("lux.dex.v4.swapparams.v1"))
	var b [9]byte
	if zeroForOne {
		b[0] = 1
	}
	binary.BigEndian.PutUint64(b[1:9], amountIn)
	h.Write(b[:])
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}

// DeriveLiquidityParamsHash hashes the modifyLiquidity-defining params (tick range,
// signed liquidity delta, salt) into the scope's ParamsHash.
func DeriveLiquidityParamsHash(tickLower, tickUpper int32, liquidityDelta int64, salt ID) ID {
	h := sha256.New()
	h.Write([]byte("lux.dex.v4.lpparams.v1"))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(tickLower))
	h.Write(u4[:])
	binary.BigEndian.PutUint32(u4[:], uint32(tickUpper))
	h.Write(u4[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], uint64(liquidityDelta))
	h.Write(u8[:])
	h.Write(salt[:])
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}

// scopedCap is a capability CONFINED to one V4 action scope. It composes the
// existing capCore (operation-class authority) with a session scope (per-action
// confinement). Authority is checked in TWO independent gates:
//
//  1. core.authorize(need) — the operation class is permitted at the session of
//     record (the existing, revocation-aware grant table).
//  2. checkScope(scope)    — the action the operation is for matches the scope this
//     capability was bound to.
//
// Composition over inheritance (Hickey): scopedCap WRAPS capCore; it does not
// subclass or widen it. A scopedCap can never grant authority capCore lacks, and the
// scope can only NARROW, never broaden.
type scopedCap struct {
	core      *capCore
	scope     V4ActionScope
	sessionID ID
}

// newScopedCap binds a freshly-issued capability core to an action scope. The
// session id is derived once and frozen; subsequent checks compare against it.
func newScopedCap(core *capCore, scope V4ActionScope) *scopedCap {
	return &scopedCap{core: core, scope: scope, sessionID: DeriveSessionID(scope)}
}

// authorizeScoped is the combined gate: operation-class authority AND action-scope
// confinement. `need` is the operation class (AuthQuote/AuthIntent/...); `want` is
// the action scope the caller is acting on. Both must pass, or fail closed.
func (s *scopedCap) authorizeScoped(need Authority, want V4ActionScope) error {
	if s == nil || s.core == nil {
		return ErrNoAuthority
	}
	if s.sessionID == (ID{}) {
		return ErrScopeUnset
	}
	if err := s.core.authorize(need); err != nil {
		return err
	}
	if DeriveSessionID(want) != s.sessionID {
		return ErrScopeMismatch
	}
	return nil
}

// authorizeSelf is the gate for operations on the capability's OWN bound scope (the
// common case — a session driving its own action). It checks operation-class
// authority and that the scope is set; the scope match is trivially true.
func (s *scopedCap) authorizeSelf(need Authority) error {
	return s.authorizeScoped(need, s.scope)
}

// SessionID exposes the bound session id (for V4Event tagging and tests).
func (s *scopedCap) SessionID() ID { return s.sessionID }

// Authority reports the operation-class bits the underlying core holds.
func (s *scopedCap) Authority() Authority {
	if s == nil || s.core == nil {
		return 0
	}
	return s.core.bits
}
