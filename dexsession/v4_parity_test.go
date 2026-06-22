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

// TestParity_V4_RouteOnChainIsPlainIntent pins the RT01 scoping fix: a route's ON-CHAIN
// leg is a PLAIN DI01 intent on the entry market — a body width the precompile's
// decodeIntentBody ACCEPTS ({0,32,64}) — NOT a route-path body. The precompile has no
// route-marker awareness, so an RT01 path body (a marker + hop count + path) would be a
// width decodeIntentBody REJECTS and the swap would REVERT on-chain. The path instead
// travels to the D router over the ZAP control plane (the RouteRequest envelope), which is
// the one and only place it is serialized for the venue. This test is the regression guard
// against re-introducing an on-chain route-path body.
func TestParity_V4_RouteOnChainIsPlainIntent(t *testing.T) {
	// The on-chain intent body a route now signs is the plain DI01 body (deadline+nonce).
	// Build it the same way prepareRouteLocal does and assert it is a precompile-accepted
	// width and carries NO route marker.
	for _, tc := range []struct {
		deadline, nonce uint64
		wantLen         int
	}{
		{0, 0, 4},        // DI01 tag only
		{1 << 40, 0, 36}, // DI01 + deadline
		{1 << 40, 7, 68}, // DI01 + deadline + nonce
	} {
		hook := EncodeIntentHookData(tc.deadline, tc.nonce)
		if len(hook) != tc.wantLen {
			t.Fatalf("route on-chain intent body (deadline=%d nonce=%d) len=%d, want %d",
				tc.deadline, tc.nonce, len(hook), tc.wantLen)
		}
		// It is a Phase-A intent (DI01-led) the precompile classifies as INTENT.
		if !bytes.Equal(hook[0:4], []byte{'D', 'I', '0', '1'}) {
			t.Fatalf("route on-chain intent must lead with DI01, got %x", hook[0:4])
		}
		// It carries NO RT01 route marker and NO DS01 settlement tag — a route's input leg
		// is a clean intent, and the path is not in the signed calldata.
		if bytes.Contains(hook, []byte{'R', 'T', '0', '1'}) {
			t.Fatalf("route on-chain intent must NOT carry an RT01 path body (the precompile reverts on it)")
		}
		if bytes.Contains(hook, []byte{'D', 'S', '0', '1'}) {
			t.Fatalf("route on-chain intent must NOT carry a DS01 settlement tag")
		}
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
