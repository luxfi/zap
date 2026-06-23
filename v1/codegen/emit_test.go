// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codegen_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luxfi/zap/v1/codegen"
)

// TestEmit_AdvanceTime: the canary schema emits source that compiles
// and matches the hand-rolled pattern in examples/advance_time_tx.go.
//
// We don't actually compile the emitted code in this test — that
// would require a temp dir + go-tool round trip. Instead we assert
// the emitted code contains the load-bearing identifiers + structure.
// The codegen_test/ subdirectory will hold an end-to-end compile test
// in a follow-up.
func TestEmit_AdvanceTime(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "AdvanceTimeSchema",
		WireName: "AdvanceTimeTx",
		Kind:     1,
		Size:     9,
		Package:  "examples",
		Fields: []codegen.Field{
			{Name: "Time", Type: "uint64", Offset: 1},
		},
	}
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, s); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()

	// Load-bearing markers — the things downstream code uses.
	wants := []string{
		"package examples",
		"KindAdvanceTimeTx zapv1.KindByte = 0x01",
		"SizeAdvanceTimeTx = 9",
		"type AdvanceTimeSchema struct{}",
		"OffsetAdvanceTimeTx_Time = 1",
		"AdvanceTimeSchemaFields",
		"Time zapv1.Field[AdvanceTimeSchema, uint64]",
		"func NewAdvanceTimeTx(time uint64)",
		"func WrapAdvanceTimeTx(b []byte)",
		"zap.NewBuilder(zap.HeaderSize + SizeAdvanceTimeTx)",
		"b.StartObject(SizeAdvanceTimeTx)",
		"ob.SetUint64(OffsetAdvanceTimeTx_Time, time)",
		"zap.Parse(b)",
		"msg.Root()",
		"root.Uint8(0)",
		"zapv1.AsView[AdvanceTimeSchema]",
		"zapv1.RawFromSlices",
		"zapv1.Register[AdvanceTimeSchema](zapv1.DefaultRegistry)",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("emitted code missing marker %q\n---\n%s", want, out)
		}
	}
}

// TestEmit_UnsupportedType: the codegen rejects unknown field types
// (the only types it knows about are the FieldKind union members).
func TestEmit_UnsupportedType(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "BadSchema",
		WireName: "BadTx",
		Kind:     42,
		Size:     16,
		Package:  "bad",
		Fields: []codegen.Field{
			// "complex128" is not a FieldKind, not "bytes<N>", and not a
			// variable-length tail ("string"/"bytes") — genuinely unsupported.
			{Name: "X", Type: "complex128", Offset: 8},
		},
	}
	err := codegen.Emit(new(bytes.Buffer), s)
	if err == nil {
		t.Fatal("expected error for unsupported field type 'complex128'")
	}
	if !strings.Contains(err.Error(), "complex128") {
		t.Errorf("error %q should name the bad type", err.Error())
	}
}

// TestEmit_VarLength: a schema with variable-length string + bytes
// fields emits SetText/SetBytes in the constructor, standalone zero-copy
// accessors over Object.Text/Object.Bytes, and grows the buffer estimate
// by each tail value's length.
func TestEmit_VarLength(t *testing.T) {
	s := codegen.Schema{
		GoName:   "VarSchema",
		WireName: "VarTx",
		Kind:     7,
		Size:     24, // kind(0..7) + Name ptr(8@8) + Data ptr(8@16)
		Package:  "varpkg",
		Fields: []codegen.Field{
			{Name: "Name", Type: "string", Offset: 8},
			{Name: "Data", Type: "bytes", Offset: 16},
		},
		SkipRegistry: true,
	}
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, s); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()
	wants := []string{
		"func NewVarTx(name string, data []byte)",          // arg types
		"zap.HeaderSize + SizeVarTx + len(name) + len(data)", // buffer estimate
		"ob.SetText(OffsetVarTx_Name, name)",
		"ob.SetBytes(OffsetVarTx_Data, data)",
		"func VarTxName(v zapv1.View[VarSchema]) string",
		"return obj.Text(OffsetVarTx_Name)",
		"func VarTxData(v zapv1.View[VarSchema]) []byte",
		"return obj.Bytes(OffsetVarTx_Data)",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("emitted source missing %q\n---\n%s", want, out)
		}
	}
	// Variable fields must NOT appear in the scalar Fields struct.
	if strings.Contains(out, "Name zapv1.Field[") || strings.Contains(out, "Data zapv1.Field[") {
		t.Errorf("variable fields must not be in the scalar Fields struct")
	}
}

// TestEmit_BytesField: a schema with a fixed-width byte-array field
// emits a typed [N]byte accessor function and the constructor takes
// the array by value.
func TestEmit_BytesField(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "BlockReqSchema",
		WireName: "BlockRequest",
		Kind:     0x53,
		Size:     34, // 1 kind + 1 version + 32 blockID
		Package:  "p2p",
		Fields: []codegen.Field{
			{Name: "Version", Type: "uint8", Offset: 1},
			{Name: "BlockID", Type: "bytes32", Offset: 2},
		},
	}
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, s); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()
	wants := []string{
		"KindBlockRequest zapv1.KindByte = 0x53",
		"SizeBlockRequest = 34",
		"OffsetBlockRequest_Version = 1",
		"OffsetBlockRequest_BlockID = 2",
		// Scalar field in Fields struct
		"Version zapv1.Field[BlockReqSchema, uint8]",
		// Byte-array field NOT in Fields struct, instead its own function:
		"func BlockRequestBlockID(v zapv1.View[BlockReqSchema]) [32]byte",
		// Constructor takes both scalar and byte-array args
		"func NewBlockRequest(version uint8, blockID [32]byte)",
		// Constructor body writes both
		"ob.SetUint8(OffsetBlockRequest_Version, version)",
		"ob.SetBytesFixed(OffsetBlockRequest_BlockID, blockID[:])",
		// Reader uses BytesFixedSlice
		"obj.BytesFixedSlice(OffsetBlockRequest_BlockID, 32)",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("emitted code missing marker %q\n---\n%s", want, out)
		}
	}
}

// TestEmit_OverlapDetected: a schema with overlapping field offsets
// is rejected at Emit time, not silently emitted as garbage.
func TestEmit_OverlapDetected(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "OverlapSchema",
		WireName: "OverlapTx",
		Kind:     0xFF,
		Size:     16,
		Package:  "bad",
		Fields: []codegen.Field{
			{Name: "A", Type: "uint64", Offset: 1}, // occupies 1..8
			{Name: "B", Type: "uint64", Offset: 5}, // occupies 5..12 — OVERLAP
		},
	}
	err := codegen.Emit(new(bytes.Buffer), s)
	if err == nil {
		t.Fatal("expected overlap error")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("error %q should mention overlap", err.Error())
	}
}

// TestEmit_PastSize: a field whose offset+size extends past the
// declared payload Size is rejected at Emit time.
func TestEmit_PastSize(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "TooBigSchema",
		WireName: "TooBigTx",
		Kind:     0xFE,
		Size:     8,
		Package:  "bad",
		Fields: []codegen.Field{
			{Name: "BigHash", Type: "bytes32", Offset: 1}, // 1..33 > Size 8
		},
	}
	err := codegen.Emit(new(bytes.Buffer), s)
	if err == nil {
		t.Fatal("expected past-size error")
	}
	if !strings.Contains(err.Error(), "past") {
		t.Errorf("error %q should mention extending past size", err.Error())
	}
}

// TestEmit_MultiField: a schema with multiple fields of mixed types
// emits a complete file.
func TestEmit_MultiField(t *testing.T) {
	t.Parallel()
	s := codegen.Schema{
		GoName:   "BatchSchema",
		WireName: "BatchTx",
		Kind:     0x21,
		Size:     17,
		Package:  "examples",
		Fields: []codegen.Field{
			{Name: "Flag", Type: "bool", Offset: 1},
			{Name: "ID", Type: "uint64", Offset: 9},
		},
	}
	var buf bytes.Buffer
	if err := codegen.Emit(&buf, s); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()
	wants := []string{
		"KindBatchTx zapv1.KindByte = 0x21",
		"Flag zapv1.Field[BatchSchema, bool]",
		"ID zapv1.Field[BatchSchema, uint64]",
		"OffsetBatchTx_Flag = 1",
		"OffsetBatchTx_ID = 9",
		"ob.SetBool(OffsetBatchTx_Flag, flag)",
		"ob.SetUint64(OffsetBatchTx_ID, iD)", // lowerFirst("ID") = "iD"
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("emitted code missing marker %q\n---\n%s", want, out)
		}
	}
}
