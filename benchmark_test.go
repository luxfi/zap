// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"testing"
)

// Benchmark ZAP message building
func BenchmarkZAPBuild(b *testing.B) {
	builder := NewBuilder(256)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder.Reset()

		obj := builder.StartObject(64)
		obj.SetUint64(0, uint64(i))
		obj.SetUint64(8, 0xDEADBEEF)
		obj.SetUint32(16, 12345)
		obj.SetBool(20, true)
		obj.FinishAsRoot()

		_ = builder.Finish()
	}
}

// Benchmark ZAP message parsing (zero-copy)
func BenchmarkZAPParse(b *testing.B) {
	// Build a message once
	builder := NewBuilder(256)
	obj := builder.StartObject(64)
	obj.SetUint64(0, 12345678)
	obj.SetUint64(8, 0xDEADBEEF)
	obj.SetUint32(16, 12345)
	obj.SetBool(20, true)
	obj.FinishAsRoot()
	data := builder.Finish()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := Parse(data)
		root := msg.Root()
		_ = root.Uint64(0)
		_ = root.Uint64(8)
		_ = root.Uint32(16)
		_ = root.Bool(20)
	}
}

// Benchmark ZAP with text fields
func BenchmarkZAPBuildWithText(b *testing.B) {
	builder := NewBuilder(512)
	text := "Hello, World! This is a test message for benchmarking."

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder.Reset()

		textOffset := builder.WriteText(text)

		obj := builder.StartObject(32)
		obj.SetUint64(0, uint64(i))
		obj.SetUint32(8, uint32(len(text)))
		// Store text offset reference
		obj.SetUint32(12, uint32(textOffset))
		obj.FinishAsRoot()

		_ = builder.Finish()
	}
}

// Benchmark ZAP with EVM types
func BenchmarkZAPBuildEVM(b *testing.B) {
	builder := NewBuilder(256)
	addr := Address{0x74, 0x2d, 0x35, 0xcc, 0x66, 0x34, 0xc0, 0x53, 0x29, 0x25,
		0xa3, 0xb8, 0x44, 0xbc, 0x9e, 0x75, 0x95, 0xf0, 0x12, 0x34}
	hash := Hash{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder.Reset()

		obj := builder.StartObject(64)
		obj.SetAddress(0, addr)
		obj.SetHash(20, hash)
		obj.SetUint64(52, uint64(i))
		obj.FinishAsRoot()

		_ = builder.Finish()
	}
}

// Benchmark ZAP parse with EVM types
func BenchmarkZAPParseEVM(b *testing.B) {
	builder := NewBuilder(256)
	addr := Address{0x74, 0x2d, 0x35, 0xcc, 0x66, 0x34, 0xc0, 0x53, 0x29, 0x25,
		0xa3, 0xb8, 0x44, 0xbc, 0x9e, 0x75, 0x95, 0xf0, 0x12, 0x34}
	hash := Hash{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}

	obj := builder.StartObject(64)
	obj.SetAddress(0, addr)
	obj.SetHash(20, hash)
	obj.SetUint64(52, 12345)
	obj.FinishAsRoot()
	data := builder.Finish()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := Parse(data)
		root := msg.Root()
		_ = root.Address(0)
		_ = root.Hash(20)
		_ = root.Uint64(52)
	}
}

// Benchmark ZAP list building
func BenchmarkZAPBuildList(b *testing.B) {
	builder := NewBuilder(1024)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		builder.Reset()

		// Build list of 100 uint64s
		lb := builder.StartList(8)
		for j := 0; j < 100; j++ {
			lb.AddUint64(uint64(j))
		}
		listOffset, listLen := lb.Finish()

		obj := builder.StartObject(16)
		obj.SetList(0, listOffset, listLen)
		obj.FinishAsRoot()

		_ = builder.Finish()
	}
}

// Benchmark ZAP list reading
func BenchmarkZAPParseList(b *testing.B) {
	builder := NewBuilder(1024)

	lb := builder.StartList(8)
	for j := 0; j < 100; j++ {
		lb.AddUint64(uint64(j))
	}
	listOffset, listLen := lb.Finish()

	obj := builder.StartObject(16)
	obj.SetList(0, listOffset, listLen)
	obj.FinishAsRoot()
	data := builder.Finish()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg, _ := Parse(data)
		root := msg.Root()
		list := root.List(0)
		sum := uint64(0)
		for j := 0; j < list.Len(); j++ {
			sum += list.Uint64(j)
		}
		_ = sum
	}
}
