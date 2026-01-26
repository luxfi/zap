// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
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
