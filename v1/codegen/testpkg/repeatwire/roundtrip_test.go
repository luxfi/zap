// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package repeatwire

import (
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestRoundTrip_Repeated proves the GENERATED repeated-message code works
// on the wire: a Parent with a repeated Child where every Child carries its
// own string tail — the case the codegen routes to ListNested. Build, wrap,
// read each element's scalar + string zero-copy via the generated accessor.
func TestRoundTrip_Repeated(t *testing.T) {
	t.Parallel()

	children := []Child{
		{ID: 11, Name: "one"},
		{ID: 22, Name: "two"},
		{ID: 33, Name: "three-is-a-longer-string"},
	}
	_, buf := NewParent(0x7, children)

	got, err := WrapParent(buf)
	if err != nil {
		t.Fatalf("WrapParent: %v", err)
	}
	if c := zapv1.Read(got, ParentSchemaFields.Count); c != 0x7 {
		t.Errorf("Count = %d, want 7", c)
	}

	list := ParentChildren(got)
	if list.Len() != len(children) {
		t.Fatalf("len = %d, want %d", list.Len(), len(children))
	}
	for i, want := range children {
		ch := list.At(i)
		if ch.IsZero() {
			t.Fatalf("child[%d] zero", i)
		}
		if id := zapv1.Read(ch, ChildSchemaFields.ID); id != want.ID {
			t.Errorf("child[%d].ID = %d, want %d", i, id, want.ID)
		}
		if nm := ChildName(ch); nm != want.Name {
			t.Errorf("child[%d].Name = %q, want %q", i, nm, want.Name)
		}
	}
}

// TestRoundTrip_RepeatedEmpty proves the empty repeated field round-trips.
func TestRoundTrip_RepeatedEmpty(t *testing.T) {
	t.Parallel()
	_, buf := NewParent(0, nil)
	got, err := WrapParent(buf)
	if err != nil {
		t.Fatalf("WrapParent: %v", err)
	}
	if n := ParentChildren(got).Len(); n != 0 {
		t.Errorf("empty len = %d, want 0", n)
	}
}
