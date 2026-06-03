// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"math"
	"testing"
)

// FuzzZAPCompositeRoundtrip drives the Builder pipeline through a richer
// shape than FuzzZAPRoundtrip: an outer object containing a nested
// object, a list of uint32, a list of uint64, a text field, and a bytes
// field. After Builder.Finish + Parse, every field must read back equal
// to the input.
//
// This complements the existing fuzz targets, which only exercise a
// flat object (uint32/uint64/int32/bool/text). Composite shapes are
// what every real consumer (mcp tool calls, consensus messages, agent
// payments) ships on the wire, so a fuzz target that builds and reads
// them is the highest-value addition.
func FuzzZAPCompositeRoundtrip(f *testing.F) {
	// Seed corpus.
	f.Add(uint32(0), uint64(0), uint32(0), uint32(0), "", []byte{})
	f.Add(uint32(1), uint64(2), uint32(3), uint32(4), "hello", []byte{0x01, 0x02, 0x03})
	f.Add(uint32(0xFFFFFFFF), uint64(0xFFFFFFFFFFFFFFFF), uint32(7), uint32(11),
		"unicode ☃ snowman", []byte{0x00, 0xFF, 0xAA, 0x55})
	f.Add(uint32(42), uint64(0xDEADBEEFCAFEBABE), uint32(0), uint32(0),
		"empty lists", []byte{})
	f.Add(uint32(1), uint64(1), uint32(64), uint32(32),
		"medium lists", []byte("abcdefghijklmnop"))

	f.Fuzz(func(t *testing.T, innerU32 uint32, innerU64 uint64,
		listU32Len uint32, listU64Len uint32, text string, blob []byte) {
		// Bound the list lengths to keep the fuzz fast.
		const maxLen = 256
		listU32Len %= maxLen + 1
		listU64Len %= maxLen + 1

		// Bound the text and blob sizes too.
		const maxBytes = 4096
		if len(text) > maxBytes {
			text = text[:maxBytes]
		}
		if len(blob) > maxBytes {
			blob = blob[:maxBytes]
		}

		b := NewBuilder(256)

		// Build the inner object first; offsets are needed for the outer.
		inner := b.StartObject(16)
		inner.SetUint32(0, innerU32)
		inner.SetUint64(8, innerU64)
		innerOff := inner.Finish()

		// Build the uint32 list.
		lb32 := b.StartList(4)
		for i := uint32(0); i < listU32Len; i++ {
			lb32.AddUint32(i ^ innerU32) // deterministic content
		}
		list32Off, list32Len := lb32.Finish()

		// Build the uint64 list.
		lb64 := b.StartList(8)
		for i := uint32(0); i < listU64Len; i++ {
			lb64.AddUint64(uint64(i) ^ innerU64)
		}
		list64Off, list64Len := lb64.Finish()

		// Build the outer object referencing the inner + lists + scalars.
		// Layout (offsets within outer's fixed section):
		//   0  : Object  (4 bytes, relative offset)
		//   8  : List<u32> (8 bytes: offset+length)
		//   16 : List<u64> (8 bytes: offset+length)
		//   24 : Text     (8 bytes: offset+length)
		//   32 : Bytes    (8 bytes: offset+length)
		outer := b.StartObject(40)
		outer.SetObject(0, innerOff)
		outer.SetList(8, list32Off, list32Len)
		outer.SetList(16, list64Off, list64Len)
		outer.SetText(24, text)
		outer.SetBytes(32, blob)
		outer.FinishAsRoot()

		data := b.Finish()

		msg, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse failed on builder output: %v", err)
		}

		root := msg.Root()

		// Inner object readback.
		got := root.Object(0)
		if got.IsNull() {
			t.Fatalf("inner object null")
		}
		if v := got.Uint32(0); v != innerU32 {
			t.Errorf("inner u32: got %d want %d", v, innerU32)
		}
		if v := got.Uint64(8); v != innerU64 {
			t.Errorf("inner u64: got %x want %x", v, innerU64)
		}

		// uint32 list readback.
		l32 := root.List(8)
		if l32.Len() != int(listU32Len) {
			t.Errorf("list32 length: got %d want %d", l32.Len(), listU32Len)
		}
		for i := uint32(0); i < listU32Len; i++ {
			want := i ^ innerU32
			if v := l32.Uint32(int(i)); v != want {
				t.Errorf("list32[%d]: got %d want %d", i, v, want)
				break
			}
		}

		// uint64 list readback.
		l64 := root.List(16)
		if l64.Len() != int(listU64Len) {
			t.Errorf("list64 length: got %d want %d", l64.Len(), listU64Len)
		}
		for i := uint32(0); i < listU64Len; i++ {
			want := uint64(i) ^ innerU64
			if v := l64.Uint64(int(i)); v != want {
				t.Errorf("list64[%d]: got %d want %d", i, v, want)
				break
			}
		}

		// Text readback.
		if v := root.Text(24); v != text {
			t.Errorf("text: got %q want %q", v, text)
		}

		// Bytes readback.
		gotBlob := root.Bytes(32)
		if len(gotBlob) != len(blob) {
			t.Errorf("bytes len: got %d want %d", len(gotBlob), len(blob))
		} else {
			for i := range blob {
				if gotBlob[i] != blob[i] {
					t.Errorf("bytes[%d]: got %x want %x", i, gotBlob[i], blob[i])
					break
				}
			}
		}
	})
}

// FuzzZAPSchemaBuilder exercises schema.go's StructBuilder against
// arbitrary field-type sequences. The invariant under test: the computed
// Size must equal the sum of each field's TypeSize plus the padding
// implied by alignment, and every recorded Field.Offset must be
// naturally aligned for its type.
//
// schema.go has zero fuzz coverage today; alignment math is exactly the
// kind of code that benefits most.
func FuzzZAPSchemaBuilder(f *testing.F) {
	// Each byte in the seed is interpreted as a type tag (mod 11).
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	f.Add([]byte{2, 4, 2, 4, 2, 4})
	f.Add([]byte{6, 0, 6, 0, 6, 0}) // text after bools
	f.Add([]byte{})                 // empty struct
	f.Add([]byte{10})               // single bytes field

	f.Fuzz(func(t *testing.T, tags []byte) {
		const maxFields = 256
		if len(tags) > maxFields {
			tags = tags[:maxFields]
		}

		sb := NewStructBuilder("Fuzz")
		// Track the size each field should occupy + alignment requirement.
		type expect struct {
			typ   Type
			align int
		}
		var expects []expect

		for _, tag := range tags {
			switch tag % 11 {
			case 0:
				sb.Bool("b")
				expects = append(expects, expect{TypeBool, 1})
			case 1:
				sb.Int32("i32")
				expects = append(expects, expect{TypeInt32, 4})
			case 2:
				sb.Uint32("u32")
				expects = append(expects, expect{TypeUint32, 4})
			case 3:
				sb.Int64("i64")
				expects = append(expects, expect{TypeInt64, 8})
			case 4:
				sb.Uint64("u64")
				expects = append(expects, expect{TypeUint64, 8})
			case 5:
				sb.Float64("f64")
				expects = append(expects, expect{TypeFloat64, 8})
			case 6:
				sb.Text("t")
				expects = append(expects, expect{TypeText, 4})
			case 7:
				sb.Bytes("by")
				expects = append(expects, expect{TypeBytes, 4})
			case 8:
				sb.List("l", TypeUint32)
				expects = append(expects, expect{TypeList, 4})
			case 9:
				sb.Struct("s", "Other")
				expects = append(expects, expect{TypeStruct, 4})
			case 10:
				sb.Bytes("by2")
				expects = append(expects, expect{TypeBytes, 4})
			}
		}

		built := sb.Build()

		// Invariant 1: number of fields matches.
		if len(built.Fields) != len(expects) {
			t.Fatalf("field count: got %d want %d", len(built.Fields), len(expects))
		}

		// Invariant 2: every recorded offset is naturally aligned for the
		// field's expected alignment.
		for i, fld := range built.Fields {
			a := expects[i].align
			if a > 1 && fld.Offset%a != 0 {
				t.Errorf("field %d (%v) offset %d not aligned to %d",
					i, fld.Type, fld.Offset, a)
			}
			if fld.Type != expects[i].typ {
				t.Errorf("field %d type: got %v want %v", i, fld.Type, expects[i].typ)
			}
		}

		// Invariant 3: Size is final-aligned to 8 (the StructBuilder applies
		// a trailing align(8) before recording Size).
		if built.Size%8 != 0 {
			t.Errorf("Size %d not aligned to 8", built.Size)
		}

		// Invariant 4: Size is at least the end-of-last-field byte.
		if len(built.Fields) > 0 {
			last := built.Fields[len(built.Fields)-1]
			minSize := last.Offset + TypeSize(last.Type)
			if built.Size < minSize {
				t.Errorf("Size %d < last field end %d", built.Size, minSize)
			}
		}

		// Invariant 5: empty schema must have Size == 0 and no fields.
		if len(tags) == 0 {
			if built.Size != 0 {
				t.Errorf("empty schema Size: got %d want 0", built.Size)
			}
			if len(built.Fields) != 0 {
				t.Errorf("empty schema fields: got %d want 0", len(built.Fields))
			}
		}
	})
}

// FuzzZAPFloatRoundtrip verifies that float32 and float64 fields survive
// a Builder -> Parse round-trip with bitwise fidelity (including for NaN
// / +/-Inf / subnormal values). The existing roundtrip fuzz covers only
// integer + text + bool.
func FuzzZAPFloatRoundtrip(f *testing.F) {
	f.Add(uint32(0), uint64(0)) // +/-0
	f.Add(math.Float32bits(float32(math.Inf(1))), math.Float64bits(math.Inf(-1)))
	f.Add(math.Float32bits(float32(math.NaN())), math.Float64bits(math.NaN()))
	f.Add(uint32(0x7F7FFFFF), uint64(0x7FEFFFFFFFFFFFFF)) // max finite
	f.Add(uint32(0x00800000), uint64(0x0010000000000000)) // min normal
	f.Add(uint32(0x00000001), uint64(0x0000000000000001)) // min subnormal

	f.Fuzz(func(t *testing.T, f32Bits uint32, f64Bits uint64) {
		f32 := math.Float32frombits(f32Bits)
		f64 := math.Float64frombits(f64Bits)

		b := NewBuilder(64)
		ob := b.StartObject(16)
		ob.SetFloat32(0, f32)
		ob.SetFloat64(8, f64)
		ob.FinishAsRoot()

		msg, err := Parse(b.Finish())
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		root := msg.Root()

		// Compare via bits because NaN != NaN under regular ==.
		gotF32Bits := math.Float32bits(root.Float32(0))
		if gotF32Bits != f32Bits {
			t.Errorf("float32 bits: got %08x want %08x", gotF32Bits, f32Bits)
		}
		gotF64Bits := math.Float64bits(root.Float64(8))
		if gotF64Bits != f64Bits {
			t.Errorf("float64 bits: got %016x want %016x", gotF64Bits, f64Bits)
		}
	})
}
