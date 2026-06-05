// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// BenchmarkRead_* measures the per-frame allocator cost of readMessageRaw
// (legacy heap-alloc path). BenchmarkReadPooled_* measures the new pool-
// aware variant readMessageRawPooled — same wire format, same payloads.
//
// Six size classes spanning the proposed pool quantization (64B / 256B /
// 1KB / 4KB / 16KB / 64KB) plus 192KB to confirm the over-class fallback
// behaves correctly (one heap alloc per frame, GC-managed).
func BenchmarkRead_64B(b *testing.B)   { benchRead(b, 64) }
func BenchmarkRead_256B(b *testing.B)  { benchRead(b, 256) }
func BenchmarkRead_1KB(b *testing.B)   { benchRead(b, 1024) }
func BenchmarkRead_4KB(b *testing.B)   { benchRead(b, 4*1024) }
func BenchmarkRead_16KB(b *testing.B)  { benchRead(b, 16*1024) }
func BenchmarkRead_64KB(b *testing.B)  { benchRead(b, 64*1024) }
func BenchmarkRead_192KB(b *testing.B) { benchRead(b, 192*1024) }

func BenchmarkReadPooled_64B(b *testing.B)   { benchReadPooled(b, 64) }
func BenchmarkReadPooled_256B(b *testing.B)  { benchReadPooled(b, 256) }
func BenchmarkReadPooled_1KB(b *testing.B)   { benchReadPooled(b, 1024) }
func BenchmarkReadPooled_4KB(b *testing.B)   { benchReadPooled(b, 4*1024) }
func BenchmarkReadPooled_16KB(b *testing.B)  { benchReadPooled(b, 16*1024) }
func BenchmarkReadPooled_64KB(b *testing.B)  { benchReadPooled(b, 64*1024) }
func BenchmarkReadPooled_192KB(b *testing.B) { benchReadPooled(b, 192*1024) }

// benchRead drives readMessageRaw N times on a static in-memory stream.
//
// Each iteration:
//   1. Reads one length-prefixed frame (4-byte header + payload).
//   2. Releases the buffer back to the pool (if the returned slice
//      is pool-owned). For the legacy path Release is a no-op and
//      the GC reclaims the buffer.
//
// The stream is rebuilt every b.N iterations so the bench is steady-
// state — no growing buffer effects.
func benchRead(b *testing.B, payloadSize int) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Build a stream with `framesPerStream` frames; we cycle the reader.
	const framesPerStream = 64
	var stream bytes.Buffer
	for i := 0; i < framesPerStream; i++ {
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(payloadSize))
		stream.Write(hdr[:])
		stream.Write(payload)
	}
	streamBytes := stream.Bytes()

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(streamBytes)
	for i := 0; i < b.N; i++ {
		if r.Len() < 4+payloadSize {
			r.Reset(streamBytes)
		}
		data, err := readMessageRaw(r)
		if err != nil {
			b.Fatalf("readMessageRaw: %v", err)
		}
		if len(data) != payloadSize {
			b.Fatalf("len=%d want %d", len(data), payloadSize)
		}
		// Discard reference so the GC can reclaim the buffer for the
		// legacy path. Pool-aware Release on the wrapper is exercised
		// by BenchmarkReadPooled_* below.
		_ = data
	}
}

// benchReadPooled is the pool-aware mirror of benchRead. Each iteration
// reads one frame into a refcounted *bufRef and releases it back to the
// pool. Steady-state, the pool reuses the same slab across all b.N
// iterations after the first one — so allocs/op should be 0 once the
// pool warms (modulo bufRef header churn, which is also pooled).
func benchReadPooled(b *testing.B, payloadSize int) {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	const framesPerStream = 64
	var stream bytes.Buffer
	for i := 0; i < framesPerStream; i++ {
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(payloadSize))
		stream.Write(hdr[:])
		stream.Write(payload)
	}
	streamBytes := stream.Bytes()

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(streamBytes)
	for i := 0; i < b.N; i++ {
		if r.Len() < 4+payloadSize {
			r.Reset(streamBytes)
		}
		ref, err := readMessageRawPooled(r)
		if err != nil {
			b.Fatalf("readMessageRawPooled: %v", err)
		}
		if ref.n != payloadSize {
			b.Fatalf("len=%d want %d", ref.n, payloadSize)
		}
		ref.release()
	}
}

