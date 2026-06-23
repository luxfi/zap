// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nestwire

import (
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestRoundTrip_Nested proves the GENERATED singular-nested code works on
// the wire: build an Outer with a nested Inner (which itself has a string
// tail), wrap the bytes back, and read the nested scalar + string zero-copy
// through the generated NestedAt accessor.
func TestRoundTrip_Nested(t *testing.T) {
	t.Parallel()

	_, buf := NewOuter(0xBEEF, &Inner{ID: 7, Label: "hello-nested"})

	got, err := WrapOuter(buf)
	if err != nil {
		t.Fatalf("WrapOuter: %v", err)
	}

	// Parent scalar.
	if seq := zapv1.Read(got, OuterSchemaFields.Seq); seq != 0xBEEF {
		t.Errorf("Seq = %#x, want 0xBEEF", seq)
	}

	// Nested object: present, with its own scalar + string tail.
	inner := OuterInner(got)
	if inner.IsZero() {
		t.Fatal("nested Inner is zero, want present")
	}
	if id := zapv1.Read(inner, InnerSchemaFields.ID); id != 7 {
		t.Errorf("Inner.ID = %d, want 7", id)
	}
	if lbl := InnerLabel(inner); lbl != "hello-nested" {
		t.Errorf("Inner.Label = %q, want %q", lbl, "hello-nested")
	}
}

// TestRoundTrip_NestedNull proves an unset nested message (nil) encodes as
// a null pointer and reads back as the zero View.
func TestRoundTrip_NestedNull(t *testing.T) {
	t.Parallel()

	_, buf := NewOuter(1, nil)
	got, err := WrapOuter(buf)
	if err != nil {
		t.Fatalf("WrapOuter: %v", err)
	}
	if seq := zapv1.Read(got, OuterSchemaFields.Seq); seq != 1 {
		t.Errorf("Seq = %d, want 1", seq)
	}
	if inner := OuterInner(got); !inner.IsZero() {
		t.Error("unset nested Inner should be the zero View, got present")
	}
}
