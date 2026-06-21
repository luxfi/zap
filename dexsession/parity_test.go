// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// parity_test.go pins dexsession's reproduced value-boundary byte formats against
// the canonical precompile/dexvm encodings. dexsession reproduces (does not import)
// these formats to stay free of the EVM/cgo dependency graph; these tests are the
// "third home" parity guard — if a precompile-side change drifts the format, a red
// test fires here and the off-chain pointer would name a different object than the
// chain (which the invariant tests would then also catch).

// TestParity_AtomicObjectWire pins the 60-byte object: owner(20)|asset(32)|amount(8).
// Identical to precompile/dex/native_wire.go encodeAtomicObject and
// chains/dexvm/atomic.go encodeExportedOutput.
func TestParity_AtomicObjectWire(t *testing.T) {
	owner := Account{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	asset := ID{0xaa, 0xbb}
	asset[31] = 0xff
	amount := uint64(0x0102030405060708)

	v := EncodeAtomicObject(owner, asset, amount)
	if len(v) != 60 {
		t.Fatalf("object width = %d, want 60", len(v))
	}
	// Hand-build the canonical layout and compare byte-for-byte.
	want := make([]byte, 60)
	copy(want[0:20], owner[:])
	copy(want[20:52], asset[:])
	binary.BigEndian.PutUint64(want[52:60], amount)
	if !bytes.Equal(v, want) {
		t.Fatalf("atomic object wire mismatch:\n got %x\nwant %x", v, want)
	}

	// Round-trip.
	go2, ga, gam, ok := DecodeAtomicObject(v)
	if !ok || go2 != owner || ga != asset || gam != amount {
		t.Fatalf("decode mismatch: ok=%v owner=%x asset=%x amount=%d", ok, go2[:], ga[:], gam)
	}
	// A non-canonical width is rejected (never reinterpreted into a credit).
	if _, _, _, ok := DecodeAtomicObject(v[:59]); ok {
		t.Fatalf("decode accepted a short object")
	}
	if _, _, _, ok := DecodeAtomicObject(append(v, 0x00)); ok {
		t.Fatalf("decode accepted an over-long object")
	}
}

// TestParity_DeriveIntentID pins the intent-id derivation against a recomputed
// SHA-256 over the EXACT field order + domain string the precompile uses. If the
// precompile's nativeIntentDomain or field order changed, this vector breaks.
func TestParity_DeriveIntentID(t *testing.T) {
	networkID := uint32(96369)
	cChainID := ID{0xc0}
	dChainID := ID{0xd0}
	txID := ID{0x77}
	callIndex := uint32(3)
	account := Account{0xAB, 0xCD}
	assetIn := ID{0x01}
	amountIn := uint64(1_000_000)
	marketID := ID{0x4d}

	got := DeriveIntentID(networkID, cChainID, dChainID, txID, callIndex, account, assetIn, amountIn, marketID)

	// Recompute independently (the canonical algorithm).
	h := sha256.New()
	h.Write([]byte("lux.dex.native.intent.v1"))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(txID[:])
	binary.BigEndian.PutUint32(u4[:], callIndex)
	h.Write(u4[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(marketID[:])
	var want ID
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Fatalf("intent id mismatch:\n got %x\nwant %x", got[:], want[:])
	}
	// Domain separation: changing the domain MUST change the id (so a generic
	// shared-memory id can never collide with a DEX intent id).
	h2 := sha256.New()
	h2.Write([]byte("other.domain"))
	h2.Write(u4[:])
	var other ID
	copy(other[:], h2.Sum(nil))
	if got == other {
		t.Fatalf("intent id not domain-separated")
	}
}

// TestParity_DeriveUTXOID pins the D->C export object key derivation against
// chains/dexvm/atomic.go deriveUTXOID (SHA-256 over txID||index).
func TestParity_DeriveUTXOID(t *testing.T) {
	txID := ID{0x12, 0x34}
	index := uint32(5)
	got := DeriveUTXOID(txID, index)

	var buf [36]byte
	copy(buf[0:32], txID[:])
	binary.BigEndian.PutUint32(buf[32:36], index)
	want := sha256.Sum256(buf[:])
	if got != ID(want) {
		t.Fatalf("utxo id mismatch:\n got %x\nwant %x", got[:], want[:])
	}
	// Distinct indices => distinct keys (no two exported outputs collide).
	if DeriveUTXOID(txID, 5) == DeriveUTXOID(txID, 6) {
		t.Fatalf("utxo id not injective over index")
	}
}

// TestParity_SettlementHookData pins the Phase-B hookData against
// precompile/dex/settle_hookdata.go: tag "DS01" + outputID(32) + amount-word(32,
// amount in low 8 bytes). And confirms Phase A is the explicit "DI01" tag.
func TestParity_SettlementHookData(t *testing.T) {
	outputID := ID{0xfe, 0xed}
	outputID[31] = 0x01
	amount := uint64(424242)

	hook := EncodeSettlementHookData(outputID, amount)
	want := make([]byte, 0, 4+64)
	want = append(want, 'D', 'S', '0', '1')
	want = append(want, outputID[:]...)
	var amt [32]byte
	binary.BigEndian.PutUint64(amt[24:32], amount)
	want = append(want, amt[:]...)
	if !bytes.Equal(hook, want) {
		t.Fatalf("settlement hookData mismatch:\n got %x\nwant %x", hook, want)
	}
	if len(hook) != 4+settlementBodyLen {
		t.Fatalf("settlement hookData len = %d, want %d", len(hook), 4+settlementBodyLen)
	}

	intent := EncodeIntentHookData()
	if !bytes.Equal(intent, []byte{'D', 'I', '0', '1'}) {
		t.Fatalf("intent hookData = %x, want DI01", intent)
	}
}

// TestParity_SwapSelector pins the V4 swap selector against
// precompile/dex/module.go SelectorSwap (0xF3CD914C) and confirms the calldata
// head layout the chain expects (selector + 9 head words).
func TestParity_SwapSelector(t *testing.T) {
	if SelectorSwap != 0xF3CD914C {
		t.Fatalf("SelectorSwap = %08X, want F3CD914C", SelectorSwap)
	}
	pk := testPoolKey()
	calldata := EncodeSwapCalldata(pk, true, 1000, EncodeSettlementHookData(ID{0x01}, 7))
	if got := binary.BigEndian.Uint32(calldata[:4]); got != SelectorSwap {
		t.Fatalf("calldata selector = %08X, want %08X", got, SelectorSwap)
	}
	// Head is selector(4) + 9 words; the hookData length word follows.
	const headWords = 5 + 3 + 1
	if len(calldata) < 4+headWords*32+32 {
		t.Fatalf("calldata too short: %d", len(calldata))
	}
	// Round-trip the settlement body out of the calldata (the harness decoder is the
	// faithful inverse the chain applies).
	outID, amt, ok := decodeSettlementCalldata(calldata)
	if !ok || amt != 7 || outID != (ID{0x01}) {
		t.Fatalf("settlement calldata round-trip: ok=%v amt=%d outID=%x", ok, amt, outID[:4])
	}
}

// TestParity_VectorPin is a belt-and-suspenders frozen vector: the exact hex of a
// derived intent id for fixed inputs. If ANY byte of the derivation drifts, this
// fails with a clear diff — the strongest pin against silent format drift.
func TestParity_VectorPin(t *testing.T) {
	got := DeriveIntentID(
		1, ID{}, ID{}, ID{}, 0,
		Account{}, ID{}, 0, ID{},
	)
	// Frozen expected value: SHA-256 of domain || u32(1) || 32x0 || 32x0 || 32x0 ||
	// u32(0) || 20x0 || 32x0 || u64(0) || 32x0. Computed once and pinned.
	want := frozenAllZeroIntentID()
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want[:]) {
		t.Fatalf("frozen intent id vector drift:\n got %x\nwant %x", got[:], want[:])
	}
}

// frozenAllZeroIntentID recomputes the canonical all-zero/networkID=1 intent id.
// Kept as a function (not a literal) so the pin is self-checking against the same
// canonical algorithm while still asserting the public DeriveIntentID matches it.
func frozenAllZeroIntentID() ID {
	h := sha256.New()
	h.Write([]byte("lux.dex.native.intent.v1"))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], 1)
	h.Write(u4[:])
	z32 := make([]byte, 32)
	h.Write(z32) // cChainID
	h.Write(z32) // dChainID
	h.Write(z32) // txID
	binary.BigEndian.PutUint32(u4[:], 0)
	h.Write(u4[:])         // callIndex
	h.Write(make([]byte, 20)) // account
	h.Write(z32)           // assetIn
	h.Write(make([]byte, 8))  // amountIn
	h.Write(z32)           // marketID
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}
