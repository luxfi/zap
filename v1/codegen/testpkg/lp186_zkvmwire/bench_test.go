// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvmwire

import (
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

var benchTxID = [32]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
}

// BenchmarkZKVMUTXO_Build measures NewZKVMUTXO — the codegen-emitted
// constructor for the mixed scalar + bytes-fixed + var-len-pointer
// shape used by 38 LP-186 chains-VM schemas.
func BenchmarkZKVMUTXO_Build(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewZKVMUTXO(
			0x99887766, 0xDEADBEEFCAFEF00D,
			0x01000000, 32,
			0x02000000, 580,
			0x03000000, 32,
			benchTxID,
		)
	}
}

// BenchmarkZKVMUTXO_Wrap measures WrapZKVMUTXO — the parse path. Zero
// heap allocs on the happy path.
func BenchmarkZKVMUTXO_Wrap(b *testing.B) {
	_, buf := NewZKVMUTXO(
		0x99887766, 0xDEADBEEFCAFEF00D,
		0x01000000, 32, 0x02000000, 580, 0x03000000, 32,
		benchTxID,
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WrapZKVMUTXO(buf)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
	}
}

// BenchmarkZKVMUTXO_RoundTrip measures Build+Wrap+ReadHeight.
func BenchmarkZKVMUTXO_RoundTrip(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, buf := NewZKVMUTXO(
			0x99887766, 0xDEADBEEFCAFEF00D,
			0x01000000, 32, 0x02000000, 580, 0x03000000, 32,
			benchTxID,
		)
		view, err := WrapZKVMUTXO(buf)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		_ = zapv1.Read(view, ZKVMUTXOSchemaFields.Height)
	}
}

// BenchmarkZKVMUTXO_Read measures one field read through the typed
// accessor.
func BenchmarkZKVMUTXO_Read(b *testing.B) {
	_, buf := NewZKVMUTXO(
		0x99887766, 0xDEADBEEFCAFEF00D,
		0x01000000, 32, 0x02000000, 580, 0x03000000, 32,
		benchTxID,
	)
	view, err := WrapZKVMUTXO(buf)
	if err != nil {
		b.Fatalf("Wrap: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = zapv1.Read(view, ZKVMUTXOSchemaFields.Height)
	}
}

// BenchmarkZKVMUTXO_ReadTxID measures the byte-array accessor that the
// codegen emits as a standalone function (not a generic Field).
func BenchmarkZKVMUTXO_ReadTxID(b *testing.B) {
	_, buf := NewZKVMUTXO(
		0x99887766, 0xDEADBEEFCAFEF00D,
		0x01000000, 32, 0x02000000, 580, 0x03000000, 32,
		benchTxID,
	)
	view, err := WrapZKVMUTXO(buf)
	if err != nil {
		b.Fatalf("Wrap: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ZKVMUTXOTxID(view)
	}
}
