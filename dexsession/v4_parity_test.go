// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/sha3"
)

// v4_parity_test.go pins the V4 reproduced byte formats against the canonical
// precompile/dex encodings — the "third home" guard. dexsession reproduces (does not
// import) the modifyLiquidity selector and the route-path hookData to stay free of
// the EVM/cgo dependency graph; if a precompile-side change drifts a format, a red
// test fires here. These are VALUES, not authority.

// keccak4 reproduces the precompile's keccak4 (the first 4 bytes of Keccak-256 of an
// ABI signature). Used to INDEPENDENTLY recompute the modifyLiquidity selector and
// assert dexsession's pinned constant equals the canonical derivation.
func keccak4(sig string) uint32 {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(sig))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}

// TestParity_V4_ModifyLiquiditySelector pins SelectorModifyLiquidity against
// precompile/dex/module.go (0x5A6BCFDA) AND against the canonical keccak4 of the V4
// modifyLiquidity ABI signature. Two independent checks: the frozen constant and the
// recomputed selector must agree, so the constant cannot silently drift.
func TestParity_V4_ModifyLiquiditySelector(t *testing.T) {
	if SelectorModifyLiquidity != 0x5A6BCFDA {
		t.Fatalf("SelectorModifyLiquidity = %08X, want 5A6BCFDA (precompile/dex/module.go)", SelectorModifyLiquidity)
	}
	// The canonical V4 signature the precompile registers.
	const sig = "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"
	if got := keccak4(sig); got != SelectorModifyLiquidity {
		t.Fatalf("keccak4(%q) = %08X, want %08X — selector drift", sig, got, SelectorModifyLiquidity)
	}
	// Sanity: it differs from the swap selector (distinct kernels).
	if SelectorModifyLiquidity == SelectorSwap {
		t.Fatalf("modifyLiquidity selector collides with swap selector")
	}
}

// TestParity_V4_ModifyLiquidityCalldata pins the modifyLiquidity calldata head
// layout: selector(4) + PoolKey(5 words) + ModifyParams(4 words) + hookData offset(1
// word) + hookData tail. It asserts the selector, the signed liquidityDelta encoding
// (+add / -remove), the tick words, the salt word, and the dynamic-bytes offset.
func TestParity_V4_ModifyLiquidityCalldata(t *testing.T) {
	pk := testPoolKey()
	salt := ID{0xAB}
	salt[31] = 0xCD

	// A POSITIVE delta (commit/add).
	add := EncodeModifyLiquidityCalldata(pk, ModifyLiquidityArgs{TickLower: -60, TickUpper: 60, LiquidityDelta: 1_000_000, Salt: salt}, EncodeIntentHookData(0, 0))
	if got := binary.BigEndian.Uint32(add[:4]); got != SelectorModifyLiquidity {
		t.Fatalf("selector = %08X, want %08X", got, SelectorModifyLiquidity)
	}
	const headWords = 5 + 4 + 1
	headEnd := 4 + headWords*32
	if len(add) < headEnd+32 {
		t.Fatalf("calldata too short: %d", len(add))
	}
	// Word layout (after selector): [0..4]=PoolKey, [5]=tickLower, [6]=tickUpper,
	// [7]=liquidityDelta, [8]=salt, [9]=hookData offset.
	word := func(b []byte, i int) []byte { return b[4+i*32 : 4+(i+1)*32] }
	// tickLower = -60 (int24, sign-extended).
	wantTickLow := wordI24(-60)
	if !bytes.Equal(word(add, 5), wantTickLow[:]) {
		t.Fatalf("tickLower word mismatch: got %x want %x", word(add, 5), wantTickLow[:])
	}
	wantTickHigh := wordI24(60)
	if !bytes.Equal(word(add, 6), wantTickHigh[:]) {
		t.Fatalf("tickUpper word mismatch")
	}
	// liquidityDelta = +1_000_000: low 8 bytes carry the value, high 24 bytes zero.
	dw := word(add, 7)
	if v := binary.BigEndian.Uint64(dw[24:32]); v != 1_000_000 {
		t.Fatalf("liquidityDelta low word = %d, want 1_000_000", v)
	}
	for i := 0; i < 24; i++ {
		if dw[i] != 0 {
			t.Fatalf("positive liquidityDelta has non-zero high byte at %d: %x", i, dw[i])
		}
	}
	// salt = the bytes32 verbatim.
	if !bytes.Equal(word(add, 8), salt[:]) {
		t.Fatalf("salt word mismatch: got %x want %x", word(add, 8), salt[:])
	}
	// hookData offset = headWords*32 (the dynamic tail begins after the head words).
	off := word(add, 9)
	if v := binary.BigEndian.Uint64(off[24:32]); v != uint64(headWords*32) {
		t.Fatalf("hookData offset = %d, want %d", v, headWords*32)
	}

	// A NEGATIVE delta (remove/collect/cancel): two's-complement sign-extended.
	rem := EncodeModifyLiquidityCalldata(pk, ModifyLiquidityArgs{TickLower: -60, TickUpper: 60, LiquidityDelta: -1_000_000, Salt: salt}, EncodeIntentHookData(0, 0))
	rdw := word(rem, 7)
	// High 24 bytes must be 0xff (sign extension of a negative int256).
	for i := 0; i < 24; i++ {
		if rdw[i] != 0xff {
			t.Fatalf("negative liquidityDelta not sign-extended at byte %d: %x", i, rdw[i])
		}
	}
	// The full 32-byte word equals two's-complement of -1_000_000.
	wantNeg := wordI256FromInt64(-1_000_000)
	if !bytes.Equal(rdw, wantNeg[:]) {
		t.Fatalf("negative liquidityDelta word mismatch:\n got %x\nwant %x", rdw, wantNeg[:])
	}
}

// TestParity_V4_RouteIntentHookData pins the route-intent hookData: DI01 (the on-chain
// Phase-A intent tag, so the precompile still classifies it as an INTENT) followed by
// the RT01 route marker, the hop count, and the path. Round-trips the path out.
func TestParity_V4_RouteIntentHookData(t *testing.T) {
	path := []ID{{0x4D, 0x01}, {0x4D, 0x02}, {0x4D, 0x03}}
	hook := EncodeRouteIntentHookData(path)

	// The hookData MUST begin with DI01 so the precompile's decodeSwapPhase classifies
	// it as a Phase-A intent (creates ONE C->D object); the route body follows.
	if !bytes.Equal(hook[0:4], []byte{'D', 'I', '0', '1'}) {
		t.Fatalf("route hookData does not lead with DI01: %x", hook[0:4])
	}
	// Then the RT01 route marker.
	if !bytes.Equal(hook[4:8], []byte{'R', 'T', '0', '1'}) {
		t.Fatalf("route hookData missing RT01 marker: %x", hook[4:8])
	}
	// Then the hop count (big-endian uint32).
	if n := binary.BigEndian.Uint32(hook[8:12]); n != 3 {
		t.Fatalf("route hop count = %d, want 3", n)
	}
	// Then the path verbatim.
	for i, m := range path {
		off := 12 + i*32
		if !bytes.Equal(hook[off:off+32], m[:]) {
			t.Fatalf("route path hop %d mismatch", i)
		}
	}
	// Total length is exact (no trailing slop).
	if len(hook) != 12+3*32 {
		t.Fatalf("route hookData len = %d, want %d", len(hook), 12+3*32)
	}

	// Round-trip via the decoder.
	got, ok := DecodeRouteIntentHookData(hook)
	if !ok || len(got) != 3 {
		t.Fatalf("route hookData round-trip: ok=%v len=%d", ok, len(got))
	}
	for i := range got {
		if got[i] != path[i] {
			t.Fatalf("route hookData round-trip hop %d mismatch", i)
		}
	}
	// A corrupt hop count (claims 5, has 3) is rejected (fail-closed, no over-read).
	bad := append([]byte(nil), hook...)
	binary.BigEndian.PutUint32(bad[8:12], 5)
	if _, ok := DecodeRouteIntentHookData(bad); ok {
		t.Fatalf("route decoder accepted a mismatched hop count")
	}
	// A non-route intent (plain DI01) is NOT a route body.
	if _, ok := DecodeRouteIntentHookData(EncodeIntentHookData(0, 0)); ok {
		t.Fatalf("plain DI01 decoded as a route")
	}
}

// TestParity_V4_RouteIntentIsPhaseAOnChain proves the route intent is, to the on-chain
// phase classifier, a PLAIN Phase-A INTENT. This is the structural guarantee that a
// route creates exactly ONE C->D object (no settlement, no second object): the
// precompile sees DI01 and classifies INTENT; the route body is the intent's body. We
// model decodeSwapPhase's rule (leading DI01 => intent) and assert it holds.
func TestParity_V4_RouteIntentIsPhaseAOnChain(t *testing.T) {
	path := []ID{{0x01}, {0x02}}
	hook := EncodeRouteIntentHookData(path)
	// Model the precompile's decodeSwapPhase: DI01-led hookData => Phase A (intent).
	// (settlement requires the DS01 tag; a route hookData NEVER carries DS01.)
	if len(hook) < 4 || !bytes.Equal(hook[0:4], []byte{'D', 'I', '0', '1'}) {
		t.Fatalf("route hookData is not DI01-classified as intent")
	}
	if bytes.Contains(hook, []byte{'D', 'S', '0', '1'}) {
		t.Fatalf("route hookData contains a DS01 settlement tag — a route must NEVER settle on the input leg")
	}
}

// TestParity_V4_SessionIDDomainSeparation proves a V4 session id can NEVER collide
// with an intent id, a UTXO id, or any other id in the system — its domain string is
// distinct, so DeriveSessionID and DeriveIntentID over the same-shaped inputs differ.
func TestParity_V4_SessionIDDomainSeparation(t *testing.T) {
	scope := V4ActionScope{NetworkID: 1, Kind: ActionSwap}
	sid := DeriveSessionID(scope)
	// An intent id over all-zero inputs (different domain) must differ.
	iid := DeriveIntentID(1, ID{}, ID{}, Account{}, ID{}, 0, ID{}, 0)
	if sid == iid {
		t.Fatalf("session id collided with intent id — domains not separated")
	}
	// A UTXO id (yet another domain) must differ too.
	uid := DeriveUTXOID(ID{}, 0)
	if sid == uid {
		t.Fatalf("session id collided with UTXO id")
	}
	// Changing the action kind changes the id (per-action confinement at the id level).
	scope2 := scope
	scope2.Kind = ActionRoute
	if DeriveSessionID(scope2) == sid {
		t.Fatalf("session id not sensitive to action kind")
	}
}
