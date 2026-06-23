// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luxfi/zap/v1/codegen"
)

// innerNestedSchema is a flat element with a scalar AND a string tail —
// the realistic nested-message shape (proto messages almost always carry
// at least one string). Proves the nested build emits both a typed
// zapv1.Write and a zapv1.WriteString against the element's offsets.
var innerNestedSchema = codegen.Schema{
	GoName:   "InnerSchema",
	WireName: "Inner",
	Kind:     0x52,
	Size:     16, // ID @0 (u64), Label @8 (string tail-ptr, 8 bytes)
	Package:  "nestwire",
	Element:  true,
	Fields: []codegen.Field{
		{Name: "ID", Type: "uint64", Offset: 0},
		{Name: "Label", Type: "string", Offset: 8},
	},
}

// outerNestedSchema carries a scalar + a SINGULAR nested Inner object.
var outerNestedSchema = codegen.Schema{
	GoName:   "OuterSchema",
	WireName: "Outer",
	Kind:     0x51,
	Size:     13, // kind@0, Seq@1 (u64), Inner@9 (object-ptr, 4 bytes)
	Package:  "nestwire",
	Fields: []codegen.Field{
		{Name: "Seq", Type: "uint64", Offset: 1},
		{Name: "Inner", Offset: 9, Nested: &codegen.NestedMsg{
			Schema: "InnerSchema",
			Wire:   "Inner",
			Value:  "Inner",
			Fields: []codegen.Field{
				{Name: "ID", Type: "uint64", Offset: 0},
				{Name: "Label", Type: "string", Offset: 8},
			},
		}},
	},
}

// TestEmit_NestedField checks the full singular-nested emission: the
// value-input struct (string field => Go `string`), the *pointer*
// constructor param, the nil-guarded WriteNested build (scalar via Write,
// string via WriteString against Offset<Wire>_<Field>), and the NestedAt
// read accessor returning a View[N].
func TestEmit_NestedField(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, outerNestedSchema); err != nil {
		t.Fatalf("Emit(outer): %v", err)
	}
	out := buf.String()
	mustParse(t, out)

	wants := []string{
		// Offsets: scalar + 4-byte object pointer.
		"OffsetOuter_Seq = 1",
		"OffsetOuter_Inner = 9",
		// Value-input struct, string field typed as Go string.
		"type Inner struct {",
		"\tID uint64",
		"\tLabel string",
		// Constructor takes the nested value by POINTER (nil => unset).
		"func NewOuter(seq uint64, inner *Inner)",
		// Bridge + nil-guarded nested build.
		"ls := zapv1.SetterFrom[OuterSchema](ob, b)",
		"if inner != nil {",
		"zapv1.WriteNested[OuterSchema, InnerSchema](ls, OffsetOuter_Inner, func(e zapv1.Setter[InnerSchema]) {",
		// Scalar via typed handle, string via WriteString + element offset.
		"zapv1.Write(e, InnerSchemaFields.ID, inner.ID)",
		"zapv1.WriteString(e, OffsetInner_Label, inner.Label)",
		// Zero-copy nested read accessor returns a typed View.
		"func OuterInner(v zapv1.View[OuterSchema]) zapv1.View[InnerSchema] {",
		"return zapv1.NestedAt[OuterSchema, InnerSchema](v, OffsetOuter_Inner)",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("generated outer missing %q\n--- output ---\n%s", want, out)
		}
	}
	// A nested field is NOT a scalar Field handle and NOT a list.
	if strings.Contains(out, "Inner zapv1.Field[OuterSchema") {
		t.Error("nested field must not be a scalar Field handle")
	}
	if strings.Contains(out, "zapv1.WriteList[OuterSchema, InnerSchema]") {
		t.Error("singular nested field must use WriteNested, not WriteList")
	}
}

// TestEmit_TailedListRoutesToNested checks the codegen's automatic
// routing: a repeated field whose element carries a string tail must use
// the out-of-line ListNested machinery, while a scalar-only element stays
// in the inline List. One declaration shape, the generator picks the
// correct wire encoding.
func TestEmit_TailedListRoutesToNested(t *testing.T) {
	t.Parallel()

	// Element WITH a string tail -> ListNested.
	tailed := codegen.Schema{
		GoName: "ParentSchema", WireName: "Parent", Kind: 0x61, Size: 9,
		Package: "x",
		Fields: []codegen.Field{
			{Name: "Kids", Offset: 1, Elem: &codegen.ListElem{
				Schema: "KidSchema", Wire: "Kid", Value: "Kid", Stride: 16,
				Fields: []codegen.Field{
					{Name: "ID", Type: "uint64", Offset: 0},
					{Name: "Name", Type: "string", Offset: 8},
				},
			}},
		},
	}
	var tb bytes.Buffer
	if err := codegen.Emit(&tb, tailed); err != nil {
		t.Fatalf("Emit(tailed): %v", err)
	}
	out := tb.String()
	mustParse(t, out)
	for _, want := range []string{
		"zapv1.WriteListNested[ParentSchema, KidSchema]",
		"*zapv1.NestedElemSetter[KidSchema]",
		"zapv1.ListNested[KidSchema]",
		"zapv1.ListNestedAt[ParentSchema, KidSchema]",
		"zapv1.WriteString(e, OffsetKid_Name, it.Name)", // element string write
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tailed list missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "zapv1.WriteList[ParentSchema, KidSchema]") {
		t.Error("tailed element must NOT use the inline WriteList")
	}

	// Element with ONLY scalars -> inline List (unchanged).
	flat := codegen.Schema{
		GoName: "BagSchema", WireName: "Bag", Kind: 0x71, Size: 9,
		Package: "x",
		Fields: []codegen.Field{
			{Name: "Nums", Offset: 1, Elem: &codegen.ListElem{
				Schema: "NumSchema", Wire: "Num", Value: "Num", Stride: 8,
				Fields: []codegen.Field{{Name: "V", Type: "uint64", Offset: 0}},
			}},
		},
	}
	var fb bytes.Buffer
	if err := codegen.Emit(&fb, flat); err != nil {
		t.Fatalf("Emit(flat): %v", err)
	}
	fout := fb.String()
	mustParse(t, fout)
	if !strings.Contains(fout, "zapv1.WriteList[BagSchema, NumSchema]") ||
		!strings.Contains(fout, "zapv1.ListAt[BagSchema, NumSchema]") {
		t.Errorf("scalar-only list must use inline List/WriteList\n%s", fout)
	}
	if strings.Contains(fout, "ListNested") {
		t.Error("scalar-only list must NOT use ListNested")
	}
}

// TestEmit_NestedElementHasOffsets checks the nested element schema emits
// the Offset<Wire>_<Field> constants the parent's WriteString references,
// so the two generated files compile together.
func TestEmit_NestedElementHasOffsets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, innerNestedSchema); err != nil {
		t.Fatalf("Emit(inner): %v", err)
	}
	out := buf.String()
	mustParse(t, out)
	for _, want := range []string{
		"OffsetInner_Label = 8",
		"InnerSchemaFields",                // scalar ID handle
		"func InnerLabel(v zapv1.View[InnerSchema]) string {", // string accessor
	} {
		if !strings.Contains(out, want) {
			t.Errorf("nested element missing %q\n--- output ---\n%s", want, out)
		}
	}
}
