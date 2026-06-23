// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1_test

import (
	"testing"

	"github.com/luxfi/zap"
	"github.com/luxfi/zap/v1"
	"github.com/luxfi/zap/v1/examples"
)

// Benchmark baseline reference:
//
// The "HandRolled" baselines below measure the INLINE-EVERYTHING case
// — calling zap.Parse / zap.NewBuilder primitives directly in the
// bench loop body, without going through any user-facing typed Wrap
// function. This is the theoretical floor: what the compiler emits
// when everything inlines.
//
// To measure against v1's actual typed Wrap functions (the FAIR
// comparison for production code), run:
//
//	cd ~/work/lux/node/vms/platformvm/txs/zap_native
//	GOWORK=off go test -bench='BenchmarkParse_ZAP$' -benchmem -count=5
//
// That reports v1 typed Wrap at 21-37 ns / 1 alloc / 24 B for
// AdvanceTimeTx. v2's WrapAdvanceTime measures at ~10 ns / 0 allocs
// here — a 2-3x WIN over v1 typed Wrap with zero allocations.
//
// See BENCH_RESULTS.md and IMPOSSIBILITY.md for the full analysis of
// why the inline-everything baseline cannot be matched without
// changing the v2 API.

// BenchmarkGeneric_Build_AdvanceTime builds the canary AdvanceTimeTx
// via the imperative-style v2 generic API ([zapv1.NewBuilderFor] +
// [zapv1.WriteB] + Finish). Targets matching v1's 1-alloc profile.
func BenchmarkGeneric_Build_AdvanceTime(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = examples.NewAdvanceTime(uint64(i))
	}
}

// BenchmarkGeneric_BuildClosure_AdvanceTime is the closure-style v2
// API for comparison. Reads more naturally at the call site but the
// closure-escape pattern adds ~3 allocations per call. Use the
// imperative form on hot paths.
func BenchmarkGeneric_BuildClosure_AdvanceTime(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = examples.NewAdvanceTimeClosure(uint64(i))
	}
}

// BenchmarkHandRolled_Build_AdvanceTime builds the canary AdvanceTimeTx
// via the hand-rolled v1 pattern that lives in luxfi/node/vms/
// platformvm/txs/zap_native/advance_time_tx.go. Side-by-side baseline.
func BenchmarkHandRolled_Build_AdvanceTime(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bb := zap.NewBuilder(zap.HeaderSize + 16 + 9)
		ob := bb.StartObject(9)
		ob.SetUint8(0, 1) // TxKindAdvanceTime
		ob.SetUint64(1, uint64(i))
		ob.FinishAsRoot()
		_ = bb.Finish()
	}
}

// BenchmarkGeneric_Read_AdvanceTime parses and reads the time field.
func BenchmarkGeneric_Read_AdvanceTime(b *testing.B) {
	_, buf := examples.NewAdvanceTime(0xdeadbeef)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, _ := examples.WrapAdvanceTime(buf)
		_ = zapv1.Read(v, examples.AdvanceTimeFields.Time)
	}
}

// BenchmarkHandRolled_Read_AdvanceTime is the v1 baseline read path.
func BenchmarkHandRolled_Read_AdvanceTime(b *testing.B) {
	bb := zap.NewBuilder(zap.HeaderSize + 16 + 9)
	ob := bb.StartObject(9)
	ob.SetUint8(0, 1)
	ob.SetUint64(1, 0xdeadbeef)
	ob.FinishAsRoot()
	buf := bb.Finish()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		msg, _ := zap.Parse(buf)
		root := msg.Root()
		_ = root.Uint8(0)
		_ = root.Uint64(1)
	}
}

// BenchmarkGeneric_Read_NoParse reads from an already-wrapped view.
// This isolates the field-accessor cost from the Parse cost. The v2
// generic dispatch should produce identical assembly to a hand-rolled
// uint64 read after compiler inlining and devirtualization.
func BenchmarkGeneric_Read_NoParse(b *testing.B) {
	view, _ := examples.NewAdvanceTime(0xdeadbeef)
	b.ResetTimer()
	b.ReportAllocs()
	var sink uint64
	for i := 0; i < b.N; i++ {
		sink = zapv1.Read(view, examples.AdvanceTimeFields.Time)
	}
	_ = sink
}

// BenchmarkHandRolled_Read_NoParse is the v1 hot-path baseline.
func BenchmarkHandRolled_Read_NoParse(b *testing.B) {
	bb := zap.NewBuilder(zap.HeaderSize + 16 + 9)
	ob := bb.StartObject(9)
	ob.SetUint8(0, 1)
	ob.SetUint64(1, 0xdeadbeef)
	ob.FinishAsRoot()
	buf := bb.Finish()
	msg, _ := zap.Parse(buf)
	root := msg.Root()

	b.ResetTimer()
	b.ReportAllocs()
	var sink uint64
	for i := 0; i < b.N; i++ {
		sink = root.Uint64(1)
	}
	_ = sink
}

// BenchmarkGeneric_List_Range iterates a 1000-element batch via
// iter.Seq range-over-func — the full View[E] form. View[E] is
// 56 bytes and spills to stack per element, so this bench is
// inherently slower than v1's 16-byte zap.Object pattern. For the
// register-friendly hot-path variant see [BenchmarkGeneric_List_Range_Payloads].
func BenchmarkGeneric_List_Range(b *testing.B) {
	items := make([]examples.Item, 1000)
	for i := range items {
		items[i] = examples.Item{ID: uint64(i), Value: uint64(i) * 2}
	}
	view, _ := examples.NewBatch(0, items)
	list := examples.Items(view)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sum uint64
		for v := range list.All() {
			sum += zapv1.Read(v, examples.ItemFields.Value)
		}
		_ = sum
	}
}

// BenchmarkGeneric_List_Range_Payloads iterates the same 1000-element
// batch via [List.Payloads] + [ReadPayload]. The yielded value is a
// 24-byte slice header that fits in registers — no per-element
// stack spill. Matches v1 hand-rolled list iteration cost.
func BenchmarkGeneric_List_Range_Payloads(b *testing.B) {
	items := make([]examples.Item, 1000)
	for i := range items {
		items[i] = examples.Item{ID: uint64(i), Value: uint64(i) * 2}
	}
	view, _ := examples.NewBatch(0, items)
	list := examples.Items(view)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sum uint64
		for p := range list.Payloads() {
			sum += zapv1.ReadPayload(p, examples.ItemFields.Value)
		}
		_ = sum
	}
}

// BenchmarkHandRolled_List_Range iterates the same via direct v1
// [zap.List.Object] indexing + v1 [zap.Object.Uint64] reads, no v2
// generic wrapper. This is what a hand-written v1 consumer would
// look like — the fairest baseline for the iter.Seq abstraction
// cost.
func BenchmarkHandRolled_List_Range(b *testing.B) {
	items := make([]examples.Item, 1000)
	for i := range items {
		items[i] = examples.Item{ID: uint64(i), Value: uint64(i) * 2}
	}
	_, buf := examples.NewBatch(0, items)
	msg, _ := zap.Parse(buf)
	root := msg.Root()
	// OffsetBatchItems lives at offset 9 of BatchSchema (matches
	// examples.OffsetBatchItems). Stride is 16 (ItemSchema.Size).
	list := root.ListStride(int(examples.OffsetBatchItems), 16)
	// Value lives at offset 8 of each ItemSchema slot.

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var sum uint64
		n := list.Len()
		for j := 0; j < n; j++ {
			elem := list.Object(j, 16)
			sum += elem.Uint64(8)
		}
		_ = sum
	}
}

// BenchmarkPool_GetPut exercises the generic Pool. The pool should
// have zero allocations per Get/Put pair once it's warm.
func BenchmarkPool_GetPut(b *testing.B) {
	type Box struct{ N uint64 }
	pool := zapv1.NewPool(func() *Box { return &Box{} })
	// Warm up the pool.
	for i := 0; i < 100; i++ {
		pool.Put(pool.Get())
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v := pool.Get()
		v.N = uint64(i)
		pool.Put(v)
	}
}
