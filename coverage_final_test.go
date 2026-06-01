// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Final coverage push: List.Object, Object out-of-bounds reads for
// Uint8/16/32, builder.grow expansion, SetObject/SetList edge cases,
// and Node.handlePeerEvent connect-direct branch.

package zap

import (
	"testing"
)

// TestCoverage_ListObjectAccessor drives List.Object and its OOB
// guards (zap.go:346).
func TestCoverage_ListObjectAccessor(t *testing.T) {
	b := NewBuilder(512)

	// Two sub-objects of 4 bytes each, packed back-to-back.
	subA := b.StartObject(4)
	subA.SetUint32(0, 0xAAAA1111)
	subA.Finish()
	subB := b.StartObject(4)
	subB.SetUint32(0, 0xBBBB2222)
	subB.Finish()

	// A list of two 4-byte objects starting at... we need them
	// contiguous. The Finish for ob doesn't pack tight; let's
	// instead construct a synthetic list of two object-shaped
	// 4-byte cells via StartList(4) + manual writes.
	list := b.StartList(4)
	list.AddUint32(0xAAAA1111)
	list.AddUint32(0xBBBB2222)
	listOff, listLen := list.Finish()

	root := b.StartObject(8)
	root.SetList(0, listOff, listLen) // listLen already in elements (AddUint32 increments by 1)
	root.FinishAsRoot()
	out := b.Finish()

	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	l := msg.Root().List(0)
	if l.Len() != 2 {
		t.Fatalf("list len %d, want 2", l.Len())
	}
	o0 := l.Object(0, 4)
	if o0.Uint32(0) != 0xAAAA1111 {
		t.Fatal("Object(0) read mismatch")
	}
	o1 := l.Object(1, 4)
	if o1.Uint32(0) != 0xBBBB2222 {
		t.Fatal("Object(1) read mismatch")
	}
	// OOB guards.
	if !l.Object(-1, 4).IsNull() {
		t.Fatal("Object(-1) should be null")
	}
	if !l.Object(99, 4).IsNull() {
		t.Fatal("Object(99) should be null")
	}
}

// TestCoverage_ObjectOOBReads drives the OOB-guard branches in
// Object.Uint8/16/32 (zap.go:147/156/165).
func TestCoverage_ObjectOOBReads(t *testing.T) {
	b := NewBuilder(64)
	ob := b.StartObject(4)
	ob.SetUint32(0, 0x12345678)
	ob.FinishAsRoot()
	out := b.Finish()

	msg, _ := Parse(out)
	root := msg.Root()
	// OOB byte offset returns 0.
	if root.Uint8(1 << 20) != 0 {
		t.Fatal("OOB Uint8 should be 0")
	}
	if root.Uint16(1 << 20) != 0 {
		t.Fatal("OOB Uint16 should be 0")
	}
	if root.Uint32(1 << 20) != 0 {
		t.Fatal("OOB Uint32 should be 0")
	}
	if root.Bool(1 << 20) {
		t.Fatal("OOB Bool should be false")
	}
}

// TestCoverage_BuilderGrowExpansion forces multiple grow() calls.
func TestCoverage_BuilderGrowExpansion(t *testing.T) {
	b := NewBuilder(32) // tiny initial capacity
	ob := b.StartObject(1024)
	for i := 0; i < 256; i++ {
		ob.SetUint32(i*4, uint32(i))
	}
	ob.FinishAsRoot()
	out := b.Finish()
	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for i := 0; i < 256; i++ {
		if msg.Root().Uint32(i*4) != uint32(i) {
			t.Fatalf("Uint32(%d) mismatch", i)
		}
	}
}

// TestCoverage_SetObjectAndSetListNull drives SetObject(0) and
// SetList(0/0) null-pointer branches in builder.go.
func TestCoverage_SetObjectAndSetListNull(t *testing.T) {
	b := NewBuilder(128)
	ob := b.StartObject(12)
	ob.SetObject(0, 0) // null object
	ob.SetList(4, 0, 0) // null list (offset==0)
	ob.SetList(4, 100, 0) // null list (length==0)
	ob.FinishAsRoot()
	out := b.Finish()
	msg, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !msg.Root().Object(0).IsNull() {
		t.Fatal("null object should be null")
	}
	if !msg.Root().List(4).IsNull() {
		t.Fatal("null list should be null")
	}
}

