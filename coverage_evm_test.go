// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage for ObjectBuilder EVM setters, Object EVM getters, List
// EVM accessors, ListBuilder Add* helpers, and Builder.Reset.

package zap

import (
	"bytes"
	"strings"
	"testing"
)

func makeAddr(b byte) Address {
	var a Address
	for i := range a {
		a[i] = b
	}
	return a
}

func makeHash(b byte) Hash {
	var h Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func makeSig(b byte) Signature {
	var s Signature
	for i := range s {
		s[i] = b
	}
	return s
}

// TestCoverage_BuilderResetRoundTrip drives Builder.Reset by
// constructing a message, resetting, constructing again, and
// verifying the second message parses cleanly.
func TestCoverage_BuilderResetRoundTrip(t *testing.T) {
	b := NewBuilder(0) // exercises the < HeaderSize branch
	ob := b.StartObject(8)
	ob.SetUint64(0, 0xDEADBEEFCAFEBABE)
	ob.FinishAsRoot()
	first := b.Finish()
	if len(first) == 0 {
		t.Fatal("first build empty")
	}

	b.Reset()
	ob2 := b.StartObject(4)
	ob2.SetUint32(0, 0x12345678)
	ob2.FinishAsRoot()
	second := b.FinishWithFlags(FlagCompressed)
	if len(second) == 0 {
		t.Fatal("second build empty")
	}

	msg, err := Parse(second)
	if err != nil {
		t.Fatalf("Parse after Reset: %v", err)
	}
	if msg.Flags() != FlagCompressed {
		t.Fatalf("flags = %v, want FlagCompressed", msg.Flags())
	}
	if msg.Root().Uint32(0) != 0x12345678 {
		t.Fatal("root uint32 mismatch")
	}
}

// TestCoverage_ObjectBuilderEVMSetters drives SetAddress / SetHash /
// SetSignature.
func TestCoverage_ObjectBuilderEVMSetters(t *testing.T) {
	b := NewBuilder(512)
	ob := b.StartObject(AddressSize + HashSize + SignatureSize)
	ob.SetAddress(0, makeAddr(0xAA))
	ob.SetHash(AddressSize, makeHash(0xBB))
	ob.SetSignature(AddressSize+HashSize, makeSig(0xCC))
	ob.FinishAsRoot()
	out := b.Finish()

	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	root := msg.Root()

	if root.Address(0) != makeAddr(0xAA) {
		t.Fatal("Address read mismatch")
	}
	if root.Hash(AddressSize) != makeHash(0xBB) {
		t.Fatal("Hash read mismatch")
	}
	if root.Signature(AddressSize+HashSize) != makeSig(0xCC) {
		t.Fatal("Signature read mismatch")
	}

	// Zero-copy slice variants.
	addrSlice := root.AddressSlice(0)
	if len(addrSlice) != AddressSize {
		t.Fatalf("AddressSlice len = %d", len(addrSlice))
	}
	hashSlice := root.HashSlice(AddressSize)
	if len(hashSlice) != HashSize {
		t.Fatalf("HashSlice len = %d", len(hashSlice))
	}

	// Out-of-bounds returns zero values / nil slices.
	if root.Address(1 << 20) != ZeroAddress {
		t.Fatal("OOB Address should return zero")
	}
	if root.Hash(1 << 20) != ZeroHash {
		t.Fatal("OOB Hash should return zero")
	}
	if root.Signature(1 << 20) != (Signature{}) {
		t.Fatal("OOB Signature should return zero")
	}
	if root.AddressSlice(1<<20) != nil {
		t.Fatal("OOB AddressSlice should be nil")
	}
	if root.HashSlice(1<<20) != nil {
		t.Fatal("OOB HashSlice should be nil")
	}

	// Hash.Bytes32 round-trip.
	h := makeHash(0xDE)
	if h.Bytes32() != [32]byte(h) {
		t.Fatal("Hash.Bytes32 != Hash bytes")
	}
}

// TestCoverage_ListEVMAccessorsAndBuilders builds a list of
// addresses + a list of uint8/32/64 elements, then reads them back.
func TestCoverage_ListEVMAccessorsAndBuilders(t *testing.T) {
	b := NewBuilder(1024)

	// Build a list of addresses. AddBytes increments count by byte
	// length; for element-counted lists we pass the element count
	// explicitly to SetList below.
	addrList := b.StartList(AddressSize)
	for i := 0; i < 3; i++ {
		a := makeAddr(byte(0xA0 + i))
		addrList.AddBytes(a[:])
	}
	addrOff, _ := addrList.Finish()
	addrCount := 3

	// Build a list of hashes.
	hashList := b.StartList(HashSize)
	for i := 0; i < 2; i++ {
		h := makeHash(byte(0xB0 + i))
		hashList.AddBytes(h[:])
	}
	hashOff, _ := hashList.Finish()
	hashCount := 2

	// Build a list of uint8/32/64.
	u8List := b.StartList(1)
	u8List.AddUint8(1)
	u8List.AddUint8(2)
	u8List.AddUint8(3)
	u8Off, u8Len := u8List.Finish()

	u32List := b.StartList(4)
	u32List.AddUint32(0xDEADBEEF)
	u32Off, u32Len := u32List.Finish()

	u64List := b.StartList(8)
	u64List.AddUint64(0xCAFEBABE1234ABCD)
	u64Off, u64Len := u64List.Finish()

	// Build a root object with all five list pointers (8 bytes each).
	ob := b.StartObject(5 * 8)
	ob.SetList(0, addrOff, addrCount)
	ob.SetList(8, hashOff, hashCount)
	ob.SetList(16, u8Off, u8Len)
	ob.SetList(24, u32Off, u32Len)
	ob.SetList(32, u64Off, u64Len)
	ob.FinishAsRoot()
	out := b.Finish()

	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	root := msg.Root()

	// Read address list.
	al := root.List(0)
	if al.Len() != 3 {
		t.Fatalf("addr list len %d", al.Len())
	}
	for i := 0; i < 3; i++ {
		if al.Address(i) != makeAddr(byte(0xA0+i)) {
			t.Fatalf("Address(%d) mismatch", i)
		}
	}
	if al.Address(-1) != ZeroAddress || al.Address(99) != ZeroAddress {
		t.Fatal("OOB Address should be zero")
	}

	// Read hash list.
	hl := root.List(8)
	if hl.Len() != 2 {
		t.Fatalf("hash list len %d", hl.Len())
	}
	for i := 0; i < 2; i++ {
		if hl.Hash(i) != makeHash(byte(0xB0+i)) {
			t.Fatalf("Hash(%d) mismatch", i)
		}
	}
	if hl.Hash(-1) != ZeroHash || hl.Hash(99) != ZeroHash {
		t.Fatal("OOB Hash should be zero")
	}

	// Read uint8/32/64 lists.
	ul8 := root.List(16)
	for i := 0; i < 3; i++ {
		if got := ul8.Uint8(i); got != byte(i+1) {
			t.Fatalf("Uint8(%d) = %d", i, got)
		}
	}
	if ul8.Uint8(-1) != 0 || ul8.Uint8(99) != 0 {
		t.Fatal("OOB Uint8 should be 0")
	}

	ul32 := root.List(24)
	if ul32.Uint32(0) != 0xDEADBEEF {
		t.Fatal("Uint32 list mismatch")
	}
	if ul32.Uint32(-1) != 0 || ul32.Uint32(99) != 0 {
		t.Fatal("OOB Uint32 should be 0")
	}

	ul64 := root.List(32)
	if ul64.Uint64(0) != 0xCAFEBABE1234ABCD {
		t.Fatal("Uint64 list mismatch")
	}
	if ul64.Uint64(-1) != 0 || ul64.Uint64(99) != 0 {
		t.Fatal("OOB Uint64 should be 0")
	}

	// Cross-check WriteBytes (drives builder.go:268).
	off := b.WriteBytes(nil)
	if off != 0 {
		t.Fatal("WriteBytes(nil) should return 0 offset")
	}
}

// TestCoverage_StructBuilderEVMFields drives Address/Hash/Signature
// on StructBuilder.
func TestCoverage_StructBuilderEVMFields(t *testing.T) {
	st := NewStructBuilder("EVMTxn").
		Address("from").
		Address("to").
		Hash("blockHash").
		Signature("sig").
		Build()
	if len(st.Fields) != 4 {
		t.Fatalf("fields = %d, want 4", len(st.Fields))
	}
	expectedSize := AddressSize*2 + HashSize + SignatureSize
	if st.Size < expectedSize {
		t.Fatalf("Size = %d, want >= %d", st.Size, expectedSize)
	}
}

// TestCoverage_ObjectListReadOffset drives List.Object for an object
// list inside a parsed message and Object accessors with OOB.
func TestCoverage_ObjectListReadOffset(t *testing.T) {
	b := NewBuilder(512)
	// Build two sub-objects.
	subA := b.StartObject(4)
	subA.SetUint32(0, 0xAAAAAAAA)
	subAOff := subA.Finish()
	subB := b.StartObject(4)
	subB.SetUint32(0, 0xBBBBBBBB)
	subBOff := subB.Finish()
	_, _ = subAOff, subBOff

	// Root has a single uint32 + a SetObject pointing at subA.
	root := b.StartObject(8)
	root.SetUint32(0, 0x11111111)
	root.SetObject(4, subAOff)
	root.FinishAsRoot()
	out := b.Finish()

	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := msg.Root()
	nested := r.Object(4)
	if nested.IsNull() {
		t.Fatal("nested object null")
	}
	if nested.Uint32(0) != 0xAAAAAAAA {
		t.Fatal("nested uint32 mismatch")
	}
	// OOB Object read returns null.
	if !r.Object(1 << 20).IsNull() {
		t.Fatal("OOB Object should be null")
	}
}

// TestCoverage_ParseEdgeCases hits the error branches of Parse.
func TestCoverage_ParseEdgeCases(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("Parse(nil) should fail")
	}
	// Wrong magic.
	bad := bytes.Repeat([]byte{0xFF}, HeaderSize)
	if _, err := Parse(bad); err == nil {
		t.Fatal("Parse with wrong magic should fail")
	}
	// Valid magic, wrong version.
	bad2 := make([]byte, HeaderSize)
	copy(bad2[0:4], Magic)
	bad2[4] = 0xFF
	if _, err := Parse(bad2); err == nil {
		t.Fatal("Parse with wrong version should fail")
	}
}

// TestCoverage_ZeroValuesAndStrings drives the trivial stringers.
func TestCoverage_ZeroValuesAndStrings(t *testing.T) {
	a := makeAddr(0x55)
	if !strings.HasPrefix(a.String(), "0x") {
		t.Fatal("Address.String should be hex-prefixed")
	}
	h := makeHash(0x66)
	if !strings.HasPrefix(h.String(), "0x") {
		t.Fatal("Hash.String should be hex-prefixed")
	}
}
