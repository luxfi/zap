// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1_test

import (
	"testing"

	"github.com/luxfi/zap"
	zapv1 "github.com/luxfi/zap/v1"
)

// This file proves the singular-nested machinery (NestedAt / WriteNested)
// on the wire, using only the exported API a generated consumer package
// can reach. It deliberately exercises the hardest composition: an OUTER
// message that carries BOTH a parent-level string tail AND a nested INNER
// object that itself carries a string tail. If the tail interleaving is
// wrong, one of the four relative pointers (inner ptr, inner-label ptr,
// outer-name ptr, seq) reads garbage.

// --- Inner: a flat ELEMENT schema (no kind byte; fields start at 0). ---
//
//	@0: ID    (uint64)
//	@8: Label (string tail-pointer: relOffset u32 + length u32)
type innerSchema struct{}

func (innerSchema) Kind() zapv1.KindByte { return 0x42 }
func (innerSchema) Size() int            { return 16 }
func (innerSchema) Name() string         { return "Inner" }

const offInnerLabel uint32 = 8

var innerFields = struct {
	ID zapv1.Field[innerSchema, uint64]
}{
	ID: zapv1.At[innerSchema, uint64](0),
}

// --- Outer: a top-level kinded message with a nested Inner + own tail. ---
//
//	@0:  Kind  (uint8)
//	@1:  Seq   (uint64)
//	@9:  Inner (nested object pointer: relOffset u32)
//	@13: Name  (string tail-pointer: relOffset u32 + length u32)
type outerSchema struct{}

func (outerSchema) Kind() zapv1.KindByte { return 0x41 }
func (outerSchema) Size() int            { return 21 }
func (outerSchema) Name() string         { return "Outer" }

const (
	offOuterKind  = 0
	offOuterSeq   = 1
	offOuterInner = 9
	offOuterName  = 13
)

var outerFields = struct {
	Seq zapv1.Field[outerSchema, uint64]
}{
	Seq: zapv1.At[outerSchema, uint64](offOuterSeq),
}

// innerData is the per-nested value input (the shape codegen will accept
// for an optional nested message field: a pointer, nil => unset => null).
type innerData struct {
	ID    uint64
	Label string
}

// newOuter builds the message directly into a ZAP buffer. When inner is
// nil the nested pointer is left zero (null) — exactly how codegen will
// encode an unset proto3 message field.
func newOuter(seq uint64, inner *innerData, name string) (zapv1.View[outerSchema], []byte) {
	capHint := zap.HeaderSize + 21 + len(name)
	if inner != nil {
		capHint += 16 + len(inner.Label)
	}
	b := zap.NewBuilder(capHint)
	ob := b.StartObject(21)
	ob.SetUint8(offOuterKind, uint8(outerSchema{}.Kind()))
	ob.SetUint64(offOuterSeq, seq)
	ob.SetText(offOuterName, name)
	if inner != nil {
		ls := zapv1.SetterFrom[outerSchema](ob, b)
		zapv1.WriteNested[outerSchema, innerSchema](ls, offOuterInner, func(e zapv1.Setter[innerSchema]) {
			zapv1.Write(e, innerFields.ID, inner.ID)
			zapv1.WriteString(e, offInnerLabel, inner.Label)
		})
	}
	rootOff := ob.FinishAsRoot()
	buf := b.Finish()
	end := rootOff + 21
	if end > len(buf) {
		end = len(buf)
	}
	return zapv1.AsView[outerSchema](zapv1.RawFromSlices(buf, rootOff, end)), buf
}

func wrapOuter(b []byte) (zapv1.View[outerSchema], error) {
	msg, err := zap.Parse(b)
	if err != nil {
		return zapv1.View[outerSchema]{}, err
	}
	root := msg.Root()
	if got := root.Uint8(offOuterKind); got != uint8(outerSchema{}.Kind()) {
		return zapv1.View[outerSchema]{}, zapv1.NewSchemaError(
			outerSchema{}.Kind(), zapv1.KindByte(got), "Outer")
	}
	data := msg.Bytes()
	rootOff := root.Offset()
	end := rootOff + 21
	if end > len(data) {
		end = len(data)
	}
	return zapv1.AsView[outerSchema](zapv1.RawFromSlices(data, rootOff, end)), nil
}

// reanchor re-synthesizes a zap.Object at a view's root for tail reads —
// the exact helper codegen emits (see s3/wire/remote_storage_location_zap.go).
func reanchorOuter(v zapv1.View[outerSchema]) zap.Object {
	return zap.WrapBuffer(v.Bytes()).RootObjectAt(int(zapv1.RootOff(v)))
}
func reanchorInner(v zapv1.View[innerSchema]) zap.Object {
	return zap.WrapBuffer(v.Bytes()).RootObjectAt(int(zapv1.RootOff(v)))
}

func outerName(v zapv1.View[outerSchema]) string { return reanchorOuter(v).Text(offOuterName) }
func outerInner(v zapv1.View[outerSchema]) zapv1.View[innerSchema] {
	return zapv1.NestedAt[outerSchema, innerSchema](v, offOuterInner)
}
func innerLabel(v zapv1.View[innerSchema]) string { return reanchorInner(v).Text(int(offInnerLabel)) }

// TestRoundTrip_Nested proves a present nested object with its own string
// tail round-trips, coexisting with the parent's own string tail.
func TestRoundTrip_Nested(t *testing.T) {
	t.Parallel()

	_, buf := newOuter(0xABCD, &innerData{ID: 42, Label: "inner-label"}, "outer-name")

	got, err := wrapOuter(buf)
	if err != nil {
		t.Fatalf("wrapOuter: %v", err)
	}

	// Parent scalar + parent string tail.
	if seq := zapv1.Read(got, outerFields.Seq); seq != 0xABCD {
		t.Errorf("Seq = %#x, want 0xABCD", seq)
	}
	if n := outerName(got); n != "outer-name" {
		t.Errorf("Name = %q, want %q", n, "outer-name")
	}

	// Nested object: present, with its own scalar + its own string tail.
	inner := outerInner(got)
	if inner.IsZero() {
		t.Fatal("nested Inner is zero, want present")
	}
	if id := zapv1.Read(inner, innerFields.ID); id != 42 {
		t.Errorf("Inner.ID = %d, want 42", id)
	}
	if lbl := innerLabel(inner); lbl != "inner-label" {
		t.Errorf("Inner.Label = %q, want %q", lbl, "inner-label")
	}
}

// TestRoundTrip_NestedNull proves an unset nested message encodes as a
// null pointer and reads back as the zero View (IsZero), while the
// parent's own fields still round-trip.
func TestRoundTrip_NestedNull(t *testing.T) {
	t.Parallel()

	_, buf := newOuter(7, nil, "no-inner")
	got, err := wrapOuter(buf)
	if err != nil {
		t.Fatalf("wrapOuter: %v", err)
	}
	if seq := zapv1.Read(got, outerFields.Seq); seq != 7 {
		t.Errorf("Seq = %d, want 7", seq)
	}
	if n := outerName(got); n != "no-inner" {
		t.Errorf("Name = %q, want %q", n, "no-inner")
	}
	if inner := outerInner(got); !inner.IsZero() {
		t.Error("unset nested Inner should be the zero View, got present")
	}
}
