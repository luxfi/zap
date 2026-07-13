// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"testing"
)

// buildSample writes a representative object (fixed fields + two deferred
// bytes payloads) and returns a detached copy of the wire bytes.
func buildSample(b *Builder, seed byte) []byte {
	payloadA := bytes.Repeat([]byte{seed}, 33)
	payloadB := bytes.Repeat([]byte{seed ^ 0xff}, 7)
	ob := b.StartObject(48)
	ob.SetUint32(0, uint32(seed))
	ob.SetBytesFixed(4, bytes.Repeat([]byte{seed + 1}, 32))
	ob.SetBytes(36, payloadA)
	// leave 44..48 unset — must stay zero even on a dirty pooled buffer
	ob.SetBytes(44, payloadB)
	ob.FinishAsRoot()
	return append([]byte(nil), b.Finish()...)
}

// TestBuilderPool_ByteIdentical proves a pooled (dirty, reused) Builder emits
// bytes identical to a fresh Builder for the same input — the invariant that
// makes GetBuilder/PutBuilder safe for canonical wire construction.
func TestBuilderPool_ByteIdentical(t *testing.T) {
	fresh := buildSample(NewBuilder(64), 0x2a)

	// Dirty a pooled builder with different content, recycle it, rebuild.
	pb := GetBuilder()
	_ = buildSample(pb, 0x77) // different content grows + dirties the buffer
	PutBuilder(pb)

	pb2 := GetBuilder()
	reused := buildSample(pb2, 0x2a)
	PutBuilder(pb2)

	if !bytes.Equal(fresh, reused) {
		t.Fatalf("pooled builder bytes differ from fresh:\nfresh:  %x\nreused: %x", fresh, reused)
	}

	// And the message must parse with the exact declared size.
	msg, err := Parse(reused)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Size() != len(reused) {
		t.Fatalf("size %d != len %d", msg.Size(), len(reused))
	}
}

// BenchmarkBuild_FreshVsPooled quantifies the pool + zero-copy SetBytes win.
func BenchmarkBuild_Fresh(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb := NewBuilder(64)
		_ = buildSample(bb, byte(i))
	}
}

func BenchmarkBuild_Pooled(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb := GetBuilder()
		_ = buildSample(bb, byte(i))
		PutBuilder(bb)
	}
}
