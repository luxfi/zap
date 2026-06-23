// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1_test

import (
	"testing"

	"github.com/luxfi/zap"
	zapv1 "github.com/luxfi/zap/v1"
)

// This file proves the repeated-nested-object machinery (ListNestedAt /
// WriteListNested) on the wire — the "repeated message" shape, where every
// element carries its OWN variable-length tail (here a string). A flat
// [zapv1.List] cannot encode this: its fixed stride has nowhere to put each
// element's string. ListNested gives each element an out-of-line object.

// --- Child: a flat element with a scalar + a string tail. ---
type childSchema struct{}

func (childSchema) Kind() zapv1.KindByte { return 0x62 }
func (childSchema) Size() int            { return 16 } // ID @0, Name @8 (string ptr)
func (childSchema) Name() string         { return "Child" }

const offChildName uint32 = 8

var childFields = struct {
	ID zapv1.Field[childSchema, uint64]
}{
	ID: zapv1.At[childSchema, uint64](0),
}

// --- Parent: a scalar + a REPEATED Child (list of object pointers). ---
type parentSchema struct{}

func (parentSchema) Kind() zapv1.KindByte { return 0x61 }
func (parentSchema) Size() int            { return 17 } // kind@0, Count@1 (u64), Children@9 (list-ptr 8)
func (parentSchema) Name() string         { return "Parent" }

const (
	offParentKind     = 0
	offParentCount    = 1
	offParentChildren = 9
)

var parentFields = struct {
	Count zapv1.Field[parentSchema, uint64]
}{
	Count: zapv1.At[parentSchema, uint64](offParentCount),
}

type childData struct {
	ID   uint64
	Name string
}

func newParent(count uint64, children []childData) (zapv1.View[parentSchema], []byte) {
	b := zap.NewBuilder(zap.HeaderSize + 17 + 128)
	ob := b.StartObject(17)
	ob.SetUint8(offParentKind, uint8(parentSchema{}.Kind()))
	ob.SetUint64(offParentCount, count)
	ls := zapv1.SetterFrom[parentSchema](ob, b)
	zapv1.WriteListNested[parentSchema, childSchema](ls, offParentChildren, func(es *zapv1.NestedElemSetter[childSchema]) {
		for _, c := range children {
			es.Append(func(e zapv1.Setter[childSchema]) {
				zapv1.Write(e, childFields.ID, c.ID)
				zapv1.WriteString(e, offChildName, c.Name)
			})
		}
	})
	rootOff := ob.FinishAsRoot()
	buf := b.Finish()
	end := rootOff + 17
	if end > len(buf) {
		end = len(buf)
	}
	return zapv1.AsView[parentSchema](zapv1.RawFromSlices(buf, rootOff, end)), buf
}

func wrapParent(b []byte) (zapv1.View[parentSchema], error) {
	msg, err := zap.Parse(b)
	if err != nil {
		return zapv1.View[parentSchema]{}, err
	}
	root := msg.Root()
	if got := root.Uint8(offParentKind); got != uint8(parentSchema{}.Kind()) {
		return zapv1.View[parentSchema]{}, zapv1.NewSchemaError(
			parentSchema{}.Kind(), zapv1.KindByte(got), "Parent")
	}
	data := msg.Bytes()
	rootOff := root.Offset()
	end := rootOff + 17
	if end > len(data) {
		end = len(data)
	}
	return zapv1.AsView[parentSchema](zapv1.RawFromSlices(data, rootOff, end)), nil
}

func parentChildren(v zapv1.View[parentSchema]) zapv1.ListNested[childSchema] {
	return zapv1.ListNestedAt[parentSchema, childSchema](v, offParentChildren)
}

func childName(v zapv1.View[childSchema]) string {
	return zap.WrapBuffer(v.Bytes()).RootObjectAt(int(zapv1.RootOff(v))).Text(int(offChildName))
}

// TestRoundTrip_ListNested proves a repeated message whose elements each
// carry their own string tail round-trips: build, wrap, then read every
// element's scalar + string zero-copy via At and via All.
func TestRoundTrip_ListNested(t *testing.T) {
	t.Parallel()

	children := []childData{
		{ID: 1, Name: "alpha"},
		{ID: 2, Name: "bravo"},
		{ID: 3, Name: "charlie-a-deliberately-longer-name"},
	}
	_, buf := newParent(0x99, children)

	got, err := wrapParent(buf)
	if err != nil {
		t.Fatalf("wrapParent: %v", err)
	}
	if c := zapv1.Read(got, parentFields.Count); c != 0x99 {
		t.Errorf("Count = %#x, want 0x99", c)
	}

	list := parentChildren(got)
	if list.Len() != len(children) {
		t.Fatalf("list len = %d, want %d", list.Len(), len(children))
	}

	// Index access (At) — verify each element's scalar + its own string.
	for i, want := range children {
		ch := list.At(i)
		if ch.IsZero() {
			t.Fatalf("child[%d] is zero", i)
		}
		if id := zapv1.Read(ch, childFields.ID); id != want.ID {
			t.Errorf("child[%d].ID = %d, want %d", i, id, want.ID)
		}
		if nm := childName(ch); nm != want.Name {
			t.Errorf("child[%d].Name = %q, want %q", i, nm, want.Name)
		}
	}

	// Iterator access (All) — same elements, range-over-func.
	i := 0
	for ch := range list.All() {
		if nm := childName(ch); nm != children[i].Name {
			t.Errorf("All child[%d].Name = %q, want %q", i, nm, children[i].Name)
		}
		i++
	}
	if i != len(children) {
		t.Errorf("All iterated %d, want %d", i, len(children))
	}
}

// TestRoundTrip_ListNestedEmpty proves an empty repeated field encodes as a
// null list and reads back length 0.
func TestRoundTrip_ListNestedEmpty(t *testing.T) {
	t.Parallel()
	_, buf := newParent(0, nil)
	got, err := wrapParent(buf)
	if err != nil {
		t.Fatalf("wrapParent: %v", err)
	}
	if n := parentChildren(got).Len(); n != 0 {
		t.Errorf("empty repeated len = %d, want 0", n)
	}
}
