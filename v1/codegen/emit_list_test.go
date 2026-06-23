// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codegen_test

import (
	"bytes"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/luxfi/zap/v1/codegen"
)

// itemSchema is a flat list-element schema (no kind byte in the slot):
// id @0, value @8 — exactly the BatchItem shape proven by hand in
// examples/batch_tx.go.
var itemSchema = codegen.Schema{
	GoName:   "ItemSchema",
	WireName: "BatchItem",
	Kind:     0x22,
	Size:     16,
	Package:  "listwire",
	Element:  true, // flat element: fields may start at offset 0
	Fields: []codegen.Field{
		{Name: "ID", Type: "uint64", Offset: 0},
		{Name: "Value", Type: "uint64", Offset: 8},
	},
}

// batchSchema carries a scalar + a variable-length LIST of itemSchema.
var batchSchema = codegen.Schema{
	GoName:   "BatchSchema",
	WireName: "BatchTx",
	Kind:     0x21,
	Size:     17, // kind@0, ID@1 (u64), Items list-ptr@9 (8 bytes)
	Package:  "listwire",
	Fields: []codegen.Field{
		{Name: "ID", Type: "uint64", Offset: 1},
		{Name: "Items", Offset: 9, Elem: &codegen.ListElem{
			Schema: "ItemSchema",
			Value:  "Item",
			Stride: 16,
			Fields: []codegen.Field{
				{Name: "ID", Type: "uint64", Offset: 0},
				{Name: "Value", Type: "uint64", Offset: 8},
			},
		}},
	},
}

// TestEmit_FlatElement checks that an Element schema emits a flat slot:
// no kind byte stamped at offset 0, fields legal at offset 0, no kind
// check in Wrap.
func TestEmit_FlatElement(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, itemSchema); err != nil {
		t.Fatalf("Emit(item): %v", err)
	}
	out := buf.String()
	mustParse(t, out)

	// Fields may start at offset 0 (no kind reservation).
	if !strings.Contains(out, "OffsetBatchItem_ID = 0") {
		t.Errorf("element ID should be at offset 0; got:\n%s", out)
	}
	// The flat slot must NOT stamp a kind byte at offset 0.
	if strings.Contains(out, "ob.SetUint8(0, uint8(KindBatchItem))") {
		t.Error("flat element must not write a kind discriminator at offset 0")
	}
	// Wrap on a flat element must NOT validate a kind byte.
	if strings.Contains(out, "got != uint8(KindBatchItem)") {
		t.Error("flat element Wrap must not validate a kind byte")
	}
	// Still a proper Schema (List[E]/registry need Kind/Size/Name).
	for _, want := range []string{
		"func (ItemSchema) Kind() zapv1.KindByte { return KindBatchItem }",
		"func (ItemSchema) Size() int            { return SizeBatchItem }",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in element output", want)
		}
	}
}

// TestEmit_ListField checks the full list emission on the parent: the
// per-element value struct, the typed constructor param, the WriteList
// build (bridged via SetterFrom, one Write per element field), and the
// ListAt read accessor — matching examples/batch_tx.go mechanically.
func TestEmit_ListField(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, batchSchema); err != nil {
		t.Fatalf("Emit(batch): %v", err)
	}
	out := buf.String()
	mustParse(t, out)

	wants := []string{
		// Offsets: scalar + list pointer.
		"OffsetBatchTx_ID = 1",
		"OffsetBatchTx_Items = 9",
		// Per-element value-input struct.
		"type Item struct {",
		"\tID uint64",
		"\tValue uint64",
		// Constructor takes scalars then the typed list slice (the scalar
		// param is lowerFirst("ID")=="iD"; the list slice is what matters).
		"func NewBatchTx(iD uint64, items []Item)",
		// Bridge from the hand-rolled ObjectBuilder to the typed writer.
		"ls := zapv1.SetterFrom[BatchSchema](ob, b)",
		// Typed list build, one Write per element field, inline.
		"zapv1.WriteList[BatchSchema, ItemSchema](ls, OffsetBatchTx_Items,",
		"es.Append(func(e zapv1.Setter[ItemSchema]) {",
		"zapv1.Write(e, ItemSchemaFields.ID, it.ID)",
		"zapv1.Write(e, ItemSchemaFields.Value, it.Value)",
		// Zero-copy read accessor.
		"func BatchTxItems(v zapv1.View[BatchSchema]) zapv1.List[ItemSchema] {",
		"return zapv1.ListAt[BatchSchema, ItemSchema](v, OffsetBatchTx_Items)",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("generated batch missing %q\n--- output ---\n%s", w, out)
		}
	}
	// A list field is NOT a scalar Field handle.
	if strings.Contains(out, "Items zapv1.Field[BatchSchema") {
		t.Error("list field must not be emitted as a scalar Field handle")
	}
}

// mustParse fails the test if out is not syntactically valid Go.
func mustParse(t *testing.T, out string) {
	t.Helper()
	if _, err := parser.ParseFile(token.NewFileSet(), "gen.go", out, parser.AllErrors); err != nil {
		t.Fatalf("generated code is not valid Go: %v\n--- output ---\n%s", err, out)
	}
}
