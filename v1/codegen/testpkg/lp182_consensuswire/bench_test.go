// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package consensuswire

import (
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// BenchmarkQuasarCert_Build measures the codegen-emitted NewQuasarCert
// constructor (one heap alloc for the buffer; everything else inlined
// per the zap codegen contract).
func BenchmarkQuasarCert_Build(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewQuasarCert(
			0xDEADBEEFCAFEF00D, 1766708400_000_000_000, 21,
			0x01000000, 96,
			0x02000000, 1280,
			0x03000000, 3309,
			0x04000000, 7856,
			0x05000000, 256,
		)
	}
}

// BenchmarkQuasarCert_Wrap measures WrapQuasarCert — the parse path.
// Zero heap allocs on the happy path per the codegen contract.
func BenchmarkQuasarCert_Wrap(b *testing.B) {
	_, buf := NewQuasarCert(
		0xDEADBEEFCAFEF00D, 1766708400_000_000_000, 21,
		0x01000000, 96, 0x02000000, 1280, 0x03000000, 3309,
		0x04000000, 7856, 0x05000000, 256,
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WrapQuasarCert(buf)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
	}
}

// BenchmarkQuasarCert_RoundTrip measures Build+Wrap+ReadEpoch — a
// representative end-to-end emit+consume.
func BenchmarkQuasarCert_RoundTrip(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, buf := NewQuasarCert(
			0xDEADBEEFCAFEF00D, 1766708400_000_000_000, 21,
			0x01000000, 96, 0x02000000, 1280, 0x03000000, 3309,
			0x04000000, 7856, 0x05000000, 256,
		)
		view, err := WrapQuasarCert(buf)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		_ = zapv1.Read(view, QuasarCertSchemaFields.Epoch)
	}
}

// BenchmarkQuasarCert_Read measures one field read through the typed
// accessor. This is the inner-loop primitive: every consumer reads
// fields out of a parsed view repeatedly.
func BenchmarkQuasarCert_Read(b *testing.B) {
	_, buf := NewQuasarCert(
		0xDEADBEEFCAFEF00D, 1766708400_000_000_000, 21,
		0x01000000, 96, 0x02000000, 1280, 0x03000000, 3309,
		0x04000000, 7856, 0x05000000, 256,
	)
	view, err := WrapQuasarCert(buf)
	if err != nil {
		b.Fatalf("Wrap: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = zapv1.Read(view, QuasarCertSchemaFields.Epoch)
	}
}
