// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/binary"
	"testing"
)

func TestBuilder(t *testing.T) {
	b := NewBuilder(256)

	// Write some text data first
	textOffset := b.WriteText("hello world")

	// Build a simple object
	ob := b.StartObject(24) // 24 bytes for our fields
	ob.SetUint32(0, 42)
	ob.SetUint64(8, 0xDEADBEEF)
	ob.SetBool(16, true)
	ob.FinishAsRoot()

	data := b.Finish()

	// Parse it back
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	root := msg.Root()

	if got := root.Uint32(0); got != 42 {
		t.Errorf("Uint32(0) = %d, want 42", got)
	}

	if got := root.Uint64(8); got != 0xDEADBEEF {
		t.Errorf("Uint64(8) = %x, want DEADBEEF", got)
	}

	if got := root.Bool(16); !got {
		t.Errorf("Bool(16) = %v, want true", got)
	}

	_ = textOffset
}

func TestPrimitives(t *testing.T) {
	b := NewBuilder(256)

	ob := b.StartObject(64)
	ob.SetInt8(0, -42)
	ob.SetInt16(2, -1000)
	ob.SetInt32(4, -100000)
	ob.SetInt64(8, -1000000000)
	ob.SetUint8(16, 255)
	ob.SetUint16(18, 65535)
	ob.SetUint32(20, 4294967295)
	ob.SetUint64(24, 18446744073709551615)
	ob.SetFloat32(32, 3.14)
	ob.SetFloat64(40, 2.718281828)
	ob.FinishAsRoot()

	data := b.Finish()
	msg, _ := Parse(data)
	root := msg.Root()

	if got := root.Int8(0); got != -42 {
		t.Errorf("Int8 = %d, want -42", got)
	}
	if got := root.Int16(2); got != -1000 {
		t.Errorf("Int16 = %d, want -1000", got)
	}
	if got := root.Int32(4); got != -100000 {
		t.Errorf("Int32 = %d, want -100000", got)
	}
	if got := root.Int64(8); got != -1000000000 {
		t.Errorf("Int64 = %d, want -1000000000", got)
	}
	if got := root.Uint8(16); got != 255 {
		t.Errorf("Uint8 = %d, want 255", got)
	}
	if got := root.Uint16(18); got != 65535 {
		t.Errorf("Uint16 = %d, want 65535", got)
	}
	if got := root.Uint32(20); got != 4294967295 {
		t.Errorf("Uint32 = %d, want 4294967295", got)
	}
	if got := root.Uint64(24); got != 18446744073709551615 {
		t.Errorf("Uint64 = %d, want max uint64", got)
	}
}

func TestList(t *testing.T) {
	b := NewBuilder(256)

	// Write a list of uint32s
	lb := b.StartList(4)
	lb.AddUint32(100)
	lb.AddUint32(200)
	lb.AddUint32(300)
	listOffset, listLen := lb.Finish()

	// Build object referencing the list
	ob := b.StartObject(16)
	ob.SetUint32(0, 999)
	ob.SetList(4, listOffset, listLen)
	ob.FinishAsRoot()

	data := b.Finish()
	msg, _ := Parse(data)
	root := msg.Root()

	if got := root.Uint32(0); got != 999 {
		t.Errorf("Uint32(0) = %d, want 999", got)
	}

	list := root.List(4)
	if list.Len() != 3 {
		t.Errorf("List.Len() = %d, want 3", list.Len())
	}

	if got := list.Uint32(0); got != 100 {
		t.Errorf("List[0] = %d, want 100", got)
	}
	if got := list.Uint32(1); got != 200 {
		t.Errorf("List[1] = %d, want 200", got)
	}
	if got := list.Uint32(2); got != 300 {
		t.Errorf("List[2] = %d, want 300", got)
	}
}

func TestByteList(t *testing.T) {
	b := NewBuilder(256)

	lb := b.StartList(1)
	lb.AddBytes([]byte("hello"))
	listOffset, listLen := lb.Finish()

	ob := b.StartObject(16)
	ob.SetList(0, listOffset, listLen)
	ob.FinishAsRoot()

	data := b.Finish()
	msg, _ := Parse(data)
	root := msg.Root()

	list := root.List(0)
	if got := string(list.Bytes()); got != "hello" {
		t.Errorf("List.Bytes() = %q, want %q", got, "hello")
	}
}

func TestNestedObject(t *testing.T) {
	b := NewBuilder(256)

	// Build inner object
	inner := b.StartObject(8)
	inner.SetUint32(0, 111)
	inner.SetUint32(4, 222)
	innerOffset := inner.Finish()

	// Build outer object
	outer := b.StartObject(16)
	outer.SetUint32(0, 333)
	outer.SetObject(4, innerOffset)
	outer.FinishAsRoot()

	data := b.Finish()
	msg, _ := Parse(data)
	root := msg.Root()

	if got := root.Uint32(0); got != 333 {
		t.Errorf("outer.Uint32(0) = %d, want 333", got)
	}

	innerObj := root.Object(4)
	if innerObj.IsNull() {
		t.Fatal("inner object is null")
	}

	if got := innerObj.Uint32(0); got != 111 {
		t.Errorf("inner.Uint32(0) = %d, want 111", got)
	}
	if got := innerObj.Uint32(4); got != 222 {
		t.Errorf("inner.Uint32(4) = %d, want 222", got)
	}
}

func TestTextRoundTrip(t *testing.T) {
	b := NewBuilder(256)

	// Build object with text fields using SetText
	ob := b.StartObject(24) // id(uint32=4) + name(text=8) + age(int32=4) => 16, aligned to 24
	ob.SetUint32(0, 42)
	ob.SetText(4, "Alice")
	ob.SetInt32(12, 30)
	ob.FinishAsRoot()

	data := b.Finish()
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	root := msg.Root()

	if got := root.Uint32(0); got != 42 {
		t.Errorf("Uint32(0) = %d, want 42", got)
	}
	if got := root.Text(4); got != "Alice" {
		t.Errorf("Text(4) = %q, want %q", got, "Alice")
	}
	if got := root.Int32(12); got != 30 {
		t.Errorf("Int32(12) = %d, want 30", got)
	}
}

func TestMultipleTextFields(t *testing.T) {
	b := NewBuilder(256)

	ob := b.StartObject(24) // 3 text fields * 8 bytes = 24
	ob.SetText(0, "hello")
	ob.SetText(8, "world")
	ob.SetText(16, "!")
	ob.FinishAsRoot()

	data := b.Finish()
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	root := msg.Root()

	if got := root.Text(0); got != "hello" {
		t.Errorf("Text(0) = %q, want %q", got, "hello")
	}
	if got := root.Text(8); got != "world" {
		t.Errorf("Text(8) = %q, want %q", got, "world")
	}
	if got := root.Text(16); got != "!" {
		t.Errorf("Text(16) = %q, want %q", got, "!")
	}
}

func TestNestedObjectWithText(t *testing.T) {
	b := NewBuilder(512)

	// Build inner object with text
	inner := b.StartObject(16) // text(8) + uint32(4) = 12, aligned to 16
	inner.SetText(0, "inner-text")
	inner.SetUint32(8, 999)
	innerOffset := inner.Finish()

	// Build outer object with text + nested
	outer := b.StartObject(16) // text(8) + object(4) = 12, aligned to 16
	outer.SetText(0, "outer-text")
	outer.SetObject(8, innerOffset)
	outer.FinishAsRoot()

	data := b.Finish()
	msg, _ := Parse(data)
	root := msg.Root()

	if got := root.Text(0); got != "outer-text" {
		t.Errorf("outer.Text(0) = %q, want %q", got, "outer-text")
	}

	innerObj := root.Object(8)
	if innerObj.IsNull() {
		t.Fatal("inner object is null")
	}
	if got := innerObj.Text(0); got != "inner-text" {
		t.Errorf("inner.Text(0) = %q, want %q", got, "inner-text")
	}
	if got := innerObj.Uint32(8); got != 999 {
		t.Errorf("inner.Uint32(8) = %d, want 999", got)
	}
}

func TestInvalidMagic(t *testing.T) {
	data := []byte("INVALID_MAGIC___")
	_, err := Parse(data)
	if err != ErrInvalidMagic {
		t.Errorf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestBufferTooSmall(t *testing.T) {
	_, err := Parse([]byte{1, 2, 3})
	if err != ErrBufferTooSmall {
		t.Errorf("expected ErrBufferTooSmall, got %v", err)
	}
}

// TestBytesNegativeRelOffsetRejected pins the F1 fix: Object.Bytes treats the
// relative offset as an UNSIGNED forward pointer. A bit-pattern that previously
// sign-extended to a negative int32 (e.g. 0xFFFFFFE0 → -32) must now flow
// through uint32→int as a very large positive value and be caught by the
// absPos+length > size bounds check.
//
// Background: SetBytes always defers payload writing to ObjectBuilder.Finish,
// which writes after the fixed section — the resulting relOffset is always a
// positive forward pointer. Object/List offsets, by contrast, may legitimately
// be negative because builders can finalize a nested object/list BEFORE the
// outer object (TestList, TestNestedObject). Therefore Bytes is uniquely safe
// to reject negative relOffsets at parse time; Object/List keep the signed
// decoding.
//
// Without this fix an attacker crafts a buffer where a Bytes field's relOffset
// points BACK into the fixed section and aliases bytes that were never
// intended to be returned as Bytes content — a transaction-malleability
// surface the moment a hash(buffer) TxID is wired up.
func TestBytesNegativeRelOffsetRejected(t *testing.T) {
	// Build a minimal object with one fixed uint32 field at offset 0 and one
	// Bytes field at offset 4 (rel-offset + length = 8 bytes).
	b := NewBuilder(128)
	ob := b.StartObject(12)
	ob.SetUint32(0, 0xDEADBEEF)
	ob.SetBytes(4, []byte("hello"))
	ob.FinishAsRoot()
	buf := b.Finish()

	// Locate the bytes-field's relOffset cell and rewrite it to a sign-extended
	// negative bit-pattern. Under the old signed-int32 cast, this would alias
	// bytes BACKWARD into the fixed-section payload; under the F1 fix, the
	// unsigned cast bubbles to the absPos > len(data) check → return nil.
	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	bytesFieldPos := rootOffset + 4
	// 0xFFFFFFE0 = -32 if sign-extended.
	binary.LittleEndian.PutUint32(buf[bytesFieldPos:], 0xFFFFFFE0)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected mutated buffer (unexpected): %v", err)
	}
	got := msg.Root().Bytes(4)
	if got != nil {
		t.Fatalf("Bytes() returned %x on negative-relOffset buffer; want nil (F1 regression)", got)
	}
}

// TestBytesMaxUintRelOffsetRejected covers the wraparound side of the F1 fix:
// a relOffset of 0xFFFFFFFF flows through uint32→int as ~4 GiB, far past any
// realistic message size; the bounds check returns nil.
func TestBytesMaxUintRelOffsetRejected(t *testing.T) {
	b := NewBuilder(128)
	ob := b.StartObject(12)
	ob.SetBytes(4, []byte("hello"))
	ob.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	binary.LittleEndian.PutUint32(buf[rootOffset+4:], 0xFFFFFFFF)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected mutated buffer: %v", err)
	}
	got := msg.Root().Bytes(4)
	if got != nil {
		t.Fatalf("Bytes() returned %x; want nil on MaxUint32 relOffset", got)
	}
}

func TestSchema(t *testing.T) {
	// Define a schema
	schema := NewSchema("test")

	person := NewStructBuilder("Person").
		Uint32("id").
		Text("name").
		Int32("age").
		Bool("active").
		Build()

	schema.AddStruct(person)

	// Verify the struct
	if person.Size != 24 { // Aligned to 8
		t.Errorf("Person.Size = %d, want 24", person.Size)
	}

	if len(person.Fields) != 4 {
		t.Errorf("Person has %d fields, want 4", len(person.Fields))
	}

	// Check field offsets
	expected := map[string]int{
		"id":     0,
		"name":   4,
		"age":    12,
		"active": 16,
	}

	for _, f := range person.Fields {
		if exp, ok := expected[f.Name]; ok {
			if f.Offset != exp {
				t.Errorf("Field %s offset = %d, want %d", f.Name, f.Offset, exp)
			}
		}
	}
}

func BenchmarkParse(b *testing.B) {
	builder := NewBuilder(256)
	ob := builder.StartObject(24)
	ob.SetUint64(0, 12345)
	ob.SetUint64(8, 67890)
	ob.SetUint64(16, 11111)
	ob.FinishAsRoot()
	data := builder.Finish()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := Parse(data)
		root := msg.Root()
		_ = root.Uint64(0)
		_ = root.Uint64(8)
		_ = root.Uint64(16)
	}
}

func BenchmarkBuild(b *testing.B) {
	b.ReportAllocs()

	builder := NewBuilder(256)
	for i := 0; i < b.N; i++ {
		builder.Reset()
		ob := builder.StartObject(24)
		ob.SetUint64(0, 12345)
		ob.SetUint64(8, 67890)
		ob.SetUint64(16, 11111)
		ob.FinishAsRoot()
		_ = builder.Finish()
	}
}

// -----------------------------------------------------------------------------
// LP-023 v3.1 — Red round 2 regression tests
// -----------------------------------------------------------------------------
//
// Each test below pins a Red-confirmed attack against the wire layer. The
// originals live at /tmp/red_zap_attacks/*_test.go; we copy them in-tree so
// future Red re-attacks cannot reopen the same gap without first changing
// our regression suite.

// TestRedRound2_HIGH1_UncappedListLength pins the Red repro:
// an attacker overwrites the list length field with 0xFFFFFFFF; the
// downstream consumer iterates 4G times. After the fix, Object.List clamps
// length against len(data) and returns a zero-length list view.
func TestRedRound2_HIGH1_UncappedListLength(t *testing.T) {
	b := NewBuilder(128)
	lb := b.StartList(4)
	lb.AddUint32(42)
	listOff, listLen := lb.Finish()
	ob := b.StartObject(8)
	ob.SetList(0, listOff, listLen)
	ob.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	// Poison the list length field with MaxUint32.
	binary.LittleEndian.PutUint32(buf[rootOffset+4:], 0xFFFFFFFF)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}
	list := msg.Root().List(0)
	if list.Len() == int(0xFFFFFFFF) {
		t.Fatalf("RED-HIGH-1 regression: list length unbounded; List.Len()=%d", list.Len())
	}
	if list.Len() > len(buf) {
		t.Fatalf("RED-HIGH-1 regression: List.Len()=%d > len(buf)=%d", list.Len(), len(buf))
	}
}

// TestNewV1_ListStrideTighterClamp pins the per-element-stride clamp
// (NEW-V1 follow-up, LP-023 Red round 3). A poisoned length field that
// passes the permissive `length <= len(data)` baseline at stride 0 gets
// rejected at the tighter `length*stride <= bufRem` bound when the caller
// passes the correct minStride. We craft the buffer so the poisoned
// length satisfies `length <= len(data)` (bare List accepts) but
// `length * 4 > bufRem` (ListStride rejects).
func TestNewV1_ListStrideTighterClamp(t *testing.T) {
	b := NewBuilder(512)
	lb := b.StartList(4)
	for i := 0; i < 32; i++ {
		lb.AddUint32(uint32(i))
	}
	listOff, listLen := lb.Finish()
	ob := b.StartObject(8)
	ob.SetList(0, listOff, listLen)
	ob.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	// Poison length: pick L such that L <= len(buf) (bare passes) but
	// L*4 > bufRem after absOffset (ListStride rejects). len(buf) ~ 200.
	// Bare clamp: int(length) > len(o.msg.data) → reject. So we need
	// length <= len(buf). bufRem after list start is ~ len(buf) - absOffset
	// (~70). 4 * 100 = 400 > 70 — easy reject. Length=100 satisfies bare
	// (100 <= 200) but fails stride*length (400 > 70).
	binary.LittleEndian.PutUint32(buf[rootOffset+4:], 100)

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}

	// Bare List() accepts length=100 since 100 <= len(buf) (~200).
	bareList := msg.Root().List(0)
	if bareList.Len() != 100 {
		t.Fatalf("bare List() expected len=100 (permissive baseline), got %d (len(buf)=%d)", bareList.Len(), len(buf))
	}

	// ListStride(0, 4) rejects: 100 * 4 = 400 > bufRem (~70).
	stridedList := msg.Root().ListStride(0, 4)
	if !stridedList.IsNull() {
		t.Fatalf("ListStride(0, 4) regression: poisoned length=100 stride=4 not rejected; Len()=%d", stridedList.Len())
	}
}

// TestNewV1_ListStrideAcceptsHonestLength pins the false-positive guard:
// honest lists with stride and length matching buffer must pass the
// tighter clamp.
func TestNewV1_ListStrideAcceptsHonestLength(t *testing.T) {
	b := NewBuilder(256)
	lb := b.StartList(4)
	for i := 0; i < 5; i++ {
		lb.AddUint32(uint32(0xAA00 + i))
	}
	listOff, listLen := lb.Finish()
	ob := b.StartObject(8)
	ob.SetList(0, listOff, listLen)
	ob.FinishAsRoot()
	buf := b.Finish()

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}

	list := msg.Root().ListStride(0, 4)
	if list.IsNull() {
		t.Fatalf("ListStride rejected honest length=5 stride=4 buffer")
	}
	if list.Len() != 5 {
		t.Fatalf("ListStride Len()=%d want 5", list.Len())
	}
	for i := 0; i < 5; i++ {
		got := list.Uint32(i)
		want := uint32(0xAA00 + i)
		if got != want {
			t.Errorf("element %d: got %x want %x", i, got, want)
		}
	}
}

// TestRedRound2_HIGH2_BackwardListPointer pins the Red repro:
// craft a List with relOffset that, under signed decoding, points into the
// wire header (Magic bytes). After the fix, Object.List returns an empty
// view (absOffset < HeaderSize is rejected).
func TestRedRound2_HIGH2_BackwardListPointer(t *testing.T) {
	b := NewBuilder(256)
	lb := b.StartList(4)
	lb.AddUint32(0xAA)
	lb.AddUint32(0xBB)
	listOff, listLen := lb.Finish()
	outer := b.StartObject(8)
	outer.SetList(0, listOff, listLen)
	outer.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	// Replace list relOffset with a backward pointer (signed-decoding
	// → absOffset=0; unsigned-decoding → enormous absOffset; either way
	// the HeaderSize floor + len(data) clamp rejects).
	negRel := int32(-rootOffset)
	binary.LittleEndian.PutUint32(buf[rootOffset:], uint32(negRel))

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}
	list := msg.Root().List(0)
	if list.Len() != 0 {
		val := list.Uint32(0)
		if val == 0x0050415A { // "ZAP\x00" little-endian
			t.Fatalf("RED-HIGH-2 regression: backward List pointer reads Magic bytes 0x%08x", val)
		}
		t.Fatalf("RED-HIGH-2 regression: backward List pointer returned non-empty list (len=%d, val=%#x)",
			list.Len(), val)
	}
}

// TestRedRound2_HIGH2_BackwardObjectPointer pins the same root cause for
// Object.Object. The original Red test (TestV7_BackwardObjectPointer) didn't
// trip because the test buffer was too small to bypass; we mirror the fix
// across all three accessors uniformly.
func TestRedRound2_HIGH2_BackwardObjectPointer(t *testing.T) {
	b := NewBuilder(256)
	inner := b.StartObject(8)
	inner.SetUint32(0, 0xCAFEBABE)
	innerOff := inner.Finish()

	outer := b.StartObject(8)
	outer.SetObject(0, innerOff)
	outer.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	// Inject backward relOffset such that absOffset would land in the header.
	negRel := int32(-rootOffset)
	binary.LittleEndian.PutUint32(buf[rootOffset:], uint32(negRel))

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}
	nested := msg.Root().Object(0)
	if !nested.IsNull() {
		got := nested.Uint32(0)
		if got == 0x0050415A { // "ZAP\x00"
			t.Fatalf("RED-HIGH-2 regression: backward Object reads Magic bytes 0x%08x", got)
		}
		t.Fatalf("RED-HIGH-2 regression: backward Object pointer accepted (offset alias=%#x)", got)
	}
}

// TestRedRound2_HIGH2_BackwardBytesPointer mirrors the same defense for
// Object.Bytes — payload cannot land inside the wire header.
func TestRedRound2_HIGH2_BackwardBytesPointer(t *testing.T) {
	b := NewBuilder(128)
	ob := b.StartObject(12)
	ob.SetBytes(4, []byte("hello"))
	ob.FinishAsRoot()
	buf := b.Finish()

	rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
	// Set relOffset to a backward value that, under unsigned decoding, would
	// overflow past EOF; OR a small positive that aliases the header. The
	// safer probe: set relOffset such that absPos = 0 (the Magic bytes).
	relForHeaderAlias := uint32(-(rootOffset + 4)) // pos = rootOffset+4; absPos = pos + rel = 0
	binary.LittleEndian.PutUint32(buf[rootOffset+4:], relForHeaderAlias)
	binary.LittleEndian.PutUint32(buf[rootOffset+8:], 4) // length=4

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected: %v", err)
	}
	got := msg.Root().Bytes(4)
	if got != nil {
		t.Fatalf("RED-HIGH-2 regression (Bytes): backward Bytes pointer accepted, got %x", got)
	}
}

// TestRedRound2_MEDIUM1_VersionParse confirms Parse accepts both v1 and v2
// headers (forward-compatible) and rejects anything else.
func TestRedRound2_MEDIUM1_VersionParse(t *testing.T) {
	// v1 header — must parse (legacy read path).
	v1 := make([]byte, HeaderSize)
	copy(v1[0:4], Magic)
	binary.LittleEndian.PutUint16(v1[4:6], Version1)
	binary.LittleEndian.PutUint32(v1[8:12], HeaderSize) // root at header (degenerate)
	binary.LittleEndian.PutUint32(v1[12:16], HeaderSize)
	if _, err := Parse(v1); err != nil {
		t.Fatalf("RED-MEDIUM-1 regression: Parse rejected v1 header: %v", err)
	}
	// v2 header — must parse (current write path).
	v2 := make([]byte, HeaderSize)
	copy(v2[0:4], Magic)
	binary.LittleEndian.PutUint16(v2[4:6], Version2)
	binary.LittleEndian.PutUint32(v2[8:12], HeaderSize)
	binary.LittleEndian.PutUint32(v2[12:16], HeaderSize)
	if _, err := Parse(v2); err != nil {
		t.Fatalf("RED-MEDIUM-1 regression: Parse rejected v2 header: %v", err)
	}
	// Unknown version (e.g. 99) — must reject.
	bad := make([]byte, HeaderSize)
	copy(bad[0:4], Magic)
	binary.LittleEndian.PutUint16(bad[4:6], 99)
	binary.LittleEndian.PutUint32(bad[8:12], HeaderSize)
	binary.LittleEndian.PutUint32(bad[12:16], HeaderSize)
	if _, err := Parse(bad); err != ErrInvalidVersion {
		t.Fatalf("RED-MEDIUM-1 regression: Parse should reject Version=99, got err=%v", err)
	}
}

// TestRedRound2_MEDIUM1_NewBuilderEmitsV2 confirms NewBuilder writes
// Version2 by default (the gating mechanism for cross-schema confusion).
func TestRedRound2_MEDIUM1_NewBuilderEmitsV2(t *testing.T) {
	b := NewBuilder(128)
	ob := b.StartObject(8)
	ob.SetUint32(0, 42)
	ob.FinishAsRoot()
	buf := b.Finish()
	got := binary.LittleEndian.Uint16(buf[4:6])
	if got != Version2 {
		t.Fatalf("RED-MEDIUM-1 regression: NewBuilder emitted Version=%d, want Version2=%d", got, Version2)
	}
	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse rejected own builder output: %v", err)
	}
	if msg.Version() != Version2 {
		t.Fatalf("Message.Version() = %d, want %d", msg.Version(), Version2)
	}
}

// TestRedRound2_V18_SizeZeroRejected pins V18 — a buffer with size=0 used
// to pass Parse and then panic on Root()/Flags() reads against an empty
// slice. Now rejected at Parse.
func TestRedRound2_V18_SizeZeroRejected(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	copy(hdr, Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], Version2)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // size=0 — must reject
	if _, err := Parse(hdr); err == nil {
		t.Fatalf("RED-V18 regression: Parse accepted size=0 buffer")
	}
}

// TestRedRound2_F1_NegativeBitPatternSweep mirrors Red's exhaustive sweep
// from /tmp/red_zap_attacks/attacks_test.go::TestF1_NegativeBitPatternSweep
// to confirm every high-bit relOffset is rejected by Object.Bytes.
func TestRedRound2_F1_NegativeBitPatternSweep(t *testing.T) {
	for v := uint32(0xFFFFFFE0); v != 0; v++ {
		b := NewBuilder(128)
		ob := b.StartObject(12)
		ob.SetUint32(0, 0xDEADBEEF)
		ob.SetBytes(4, []byte("hello"))
		ob.FinishAsRoot()
		buf := b.Finish()

		rootOffset := int(binary.LittleEndian.Uint32(buf[8:12]))
		binary.LittleEndian.PutUint32(buf[rootOffset+4:], v)
		msg, err := Parse(buf)
		if err != nil {
			t.Fatalf("Parse rejected v=%#x: %v", v, err)
		}
		got := msg.Root().Bytes(4)
		if got != nil {
			t.Fatalf("v=%#x: Bytes() returned %x; want nil (F1 regression)", v, got)
		}
		if v == 0xFFFFFFFF {
			break
		}
	}
}
