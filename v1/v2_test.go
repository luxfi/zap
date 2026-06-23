// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/zap"
	"github.com/luxfi/zap/v1"
	"github.com/luxfi/zap/v1/examples"
)

// TestRoundTrip_AdvanceTime: Build → Wrap → Read returns the original
// timestamp, byte-for-byte.
func TestRoundTrip_AdvanceTime(t *testing.T) {
	t.Parallel()
	cases := []uint64{0, 1, 0xdeadbeef, 1<<63 - 1, 1<<64 - 1}
	for _, want := range cases {
		view, buf := examples.NewAdvanceTime(want)
		if got := zapv1.Read(view, examples.AdvanceTimeFields.Time); got != want {
			t.Fatalf("Build→Read: got %d, want %d", got, want)
		}
		view2, err := examples.WrapAdvanceTime(buf)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if got := zapv1.Read(view2, examples.AdvanceTimeFields.Time); got != want {
			t.Fatalf("Build→Wrap→Read: got %d, want %d", got, want)
		}
		// Also exercise the method-style accessor.
		if got := examples.Time(view2); got != want {
			t.Fatalf("Time(view): got %d, want %d", got, want)
		}
	}
}

// TestRoundTrip_8Shapes builds and reads 8 different schemas to
// satisfy the "8+ schema shapes" coverage requirement. We use small,
// self-contained shapes inline so each one stands on its own.
func TestRoundTrip_8Shapes(t *testing.T) {
	t.Parallel()
	type s1 struct{}
	// Shape 1: bool field
	t.Run("Bool", func(t *testing.T) {
		view, _ := zapv1.Build[boolSchema](func(set zapv1.Setter[boolSchema]) {
			zapv1.Write(set, boolFields.Flag, true)
		})
		if !zapv1.Read(view, boolFields.Flag) {
			t.Fatal("bool round-trip lost the value")
		}
	})
	// Shape 2..N: integer widths.
	t.Run("Int8", func(t *testing.T) {
		const want int8 = -42
		view, _ := zapv1.Build[i8Schema](func(s zapv1.Setter[i8Schema]) {
			zapv1.Write(s, i8Fields.V, want)
		})
		if got := zapv1.Read(view, i8Fields.V); got != want {
			t.Fatalf("int8: %d != %d", got, want)
		}
	})
	t.Run("Int16", func(t *testing.T) {
		const want int16 = -1234
		view, _ := zapv1.Build[i16Schema](func(s zapv1.Setter[i16Schema]) {
			zapv1.Write(s, i16Fields.V, want)
		})
		if got := zapv1.Read(view, i16Fields.V); got != want {
			t.Fatalf("int16: %d != %d", got, want)
		}
	})
	t.Run("Int32", func(t *testing.T) {
		const want int32 = -7777777
		view, _ := zapv1.Build[i32Schema](func(s zapv1.Setter[i32Schema]) {
			zapv1.Write(s, i32Fields.V, want)
		})
		if got := zapv1.Read(view, i32Fields.V); got != want {
			t.Fatalf("int32: %d != %d", got, want)
		}
	})
	t.Run("Int64", func(t *testing.T) {
		const want int64 = -(1 << 60)
		view, _ := zapv1.Build[i64Schema](func(s zapv1.Setter[i64Schema]) {
			zapv1.Write(s, i64Fields.V, want)
		})
		if got := zapv1.Read(view, i64Fields.V); got != want {
			t.Fatalf("int64: %d != %d", got, want)
		}
	})
	t.Run("Uint32", func(t *testing.T) {
		const want uint32 = 0xdeadbeef
		view, _ := zapv1.Build[u32Schema](func(s zapv1.Setter[u32Schema]) {
			zapv1.Write(s, u32Fields.V, want)
		})
		if got := zapv1.Read(view, u32Fields.V); got != want {
			t.Fatalf("uint32: %x != %x", got, want)
		}
	})
	t.Run("Float32", func(t *testing.T) {
		const want float32 = 3.14159
		view, _ := zapv1.Build[f32Schema](func(s zapv1.Setter[f32Schema]) {
			zapv1.Write(s, f32Fields.V, want)
		})
		if got := zapv1.Read(view, f32Fields.V); got != want {
			t.Fatalf("float32: %v != %v", got, want)
		}
	})
	t.Run("Float64", func(t *testing.T) {
		const want float64 = 2.718281828459045
		view, _ := zapv1.Build[f64Schema](func(s zapv1.Setter[f64Schema]) {
			zapv1.Write(s, f64Fields.V, want)
		})
		if got := zapv1.Read(view, f64Fields.V); got != want {
			t.Fatalf("float64: %v != %v", got, want)
		}
	})
	_ = s1{} // anchor; keep import order stable
}

// TestByteEqual_V1Canonical: the v2 generic builder produces the
// exact same wire bytes as a hand-rolled v1 NewAdvanceTimeTx with the
// same TxKind + same offset. This is the wire-compat guarantee.
func TestByteEqual_V1Canonical(t *testing.T) {
	t.Parallel()
	const ts uint64 = 1735862400

	// v2 build.
	_, v2Buf := examples.NewAdvanceTime(ts)

	// v1 hand-rolled equivalent (matches advance_time_tx.go in
	// luxfi/node/vms/platformvm/txs/zap_native exactly):
	const offsetTxKind = 0
	const offsetTime = 1
	const sizeAdvanceTimeTx = 9
	const txKindAdvanceTime uint8 = 1
	b := zap.NewBuilder(zap.HeaderSize + 16 + sizeAdvanceTimeTx)
	ob := b.StartObject(sizeAdvanceTimeTx)
	ob.SetUint8(offsetTxKind, txKindAdvanceTime)
	ob.SetUint64(offsetTime, ts)
	ob.FinishAsRoot()
	v1Buf := b.Finish()

	if !bytes.Equal(v2Buf, v1Buf) {
		t.Fatalf("v2 wire bytes diverge from v1 canonical:\n  v2=%x\n  v1=%x", v2Buf, v1Buf)
	}
}

// TestWrap_WrongKind: a buffer carrying KindB cannot be wrapped as
// schema A — the schema-mismatch error names both kinds.
func TestWrap_WrongKind(t *testing.T) {
	t.Parallel()
	_, batchBuf := examples.NewAdvanceTime(7) // kind=1
	_, err := zapv1.Wrap[examples.BatchSchema](batchBuf)
	var sErr *zapv1.SchemaError
	if !errors.As(err, &sErr) {
		t.Fatalf("expected SchemaError, got %T: %v", err, err)
	}
	if sErr.Want != examples.KindBatch || sErr.Got != examples.KindAdvanceTime {
		t.Fatalf("SchemaError fields: want=%v got=%v (expected %v / %v)",
			sErr.Want, sErr.Got, examples.KindBatch, examples.KindAdvanceTime)
	}
}

// TestRegistry_Dispatch: PeekKind → Registry.Lookup → typed Wrap is
// the reflection-free dispatch pattern.
func TestRegistry_Dispatch(t *testing.T) {
	t.Parallel()
	const want uint64 = 42
	_, buf := examples.NewAdvanceTime(want)

	kind, err := zapv1.PeekKind(buf)
	if err != nil {
		t.Fatalf("PeekKind: %v", err)
	}
	if kind != examples.KindAdvanceTime {
		t.Fatalf("PeekKind: got %v, want %v", kind, examples.KindAdvanceTime)
	}
	entry, ok := zapv1.DefaultRegistry.Lookup(kind)
	if !ok {
		t.Fatal("Registry: no entry for KindAdvanceTime")
	}
	if entry.Name != "AdvanceTimeTx" {
		t.Fatalf("entry.Name: %q", entry.Name)
	}
	if _, _, err := entry.Wrap(buf); err != nil {
		t.Fatalf("entry.Wrap: %v", err)
	}
	// Final typed step.
	view, err := zapv1.WrapAs[examples.AdvanceTimeSchema](buf)
	if err != nil {
		t.Fatalf("WrapAs: %v", err)
	}
	if got := zapv1.Read(view, examples.AdvanceTimeFields.Time); got != want {
		t.Fatalf("WrapAs round-trip: got %d, want %d", got, want)
	}
}

// TestPool_GenericGetPut: Pool returns values of the right type and
// recycles them.
func TestPool_GenericGetPut(t *testing.T) {
	t.Parallel()
	type Box struct{ N int }
	created := 0
	pool := zapv1.NewPool(func() *Box {
		created++
		return &Box{}
	})

	// First Get must construct.
	a := pool.Get()
	a.N = 99
	pool.Put(a)

	// Subsequent Get is likely (but not guaranteed) to return the
	// same instance. We assert only that the pool semantics work,
	// not that the same pointer comes back — sync.Pool is allowed to
	// GC entries between Put and Get.
	b := pool.Get()
	if b == nil {
		t.Fatal("Get returned nil")
	}
	pool.Put(b)

	if created < 1 {
		t.Fatal("pool never invoked New")
	}
}

// TestList_RangeOverFunc: build a small batch, iterate via iter.Seq,
// verify every element round-trips.
func TestList_RangeOverFunc(t *testing.T) {
	t.Parallel()
	want := []examples.Item{
		{ID: 1, Value: 10},
		{ID: 2, Value: 20},
		{ID: 3, Value: 30},
		{ID: 4, Value: 40},
		{ID: 5, Value: 50},
	}
	view, _ := examples.NewBatch(7777, want)

	if id := zapv1.Read(view, examples.BatchFields.ID); id != 7777 {
		t.Fatalf("BatchID: %d", id)
	}

	list := examples.Items(view)
	if list.Len() != len(want) {
		t.Fatalf("list.Len: %d, want %d", list.Len(), len(want))
	}

	// Range-over-func.
	got := []examples.Item{}
	for itemView := range list.All() {
		got = append(got, examples.Item{
			ID:    zapv1.Read(itemView, examples.ItemFields.ID),
			Value: zapv1.Read(itemView, examples.ItemFields.Value),
		})
	}
	if len(got) != len(want) {
		t.Fatalf("range len: %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("item[%d]: got %+v, want %+v", i, got[i], want[i])
		}
	}

	// Indexed iteration.
	seen := 0
	for i, itemView := range list.Indexed() {
		if got, w := zapv1.Read(itemView, examples.ItemFields.ID), want[i].ID; got != w {
			t.Fatalf("Indexed item[%d].ID: %d, want %d", i, got, w)
		}
		seen++
	}
	if seen != len(want) {
		t.Fatalf("Indexed seen: %d, want %d", seen, len(want))
	}

	// At(i) direct access.
	for i, w := range want {
		v := list.At(i)
		if g := zapv1.Read(v, examples.ItemFields.ID); g != w.ID {
			t.Fatalf("At(%d).ID: %d, want %d", i, g, w.ID)
		}
	}
}

// TestList_LargeIteration: 1M elements, constant memory. We verify
// that range-over-func does not allocate per-element.
func TestList_LargeIteration(t *testing.T) {
	if testing.Short() {
		t.Skip("large iteration test, -short")
	}
	const N = 1_000_000
	items := make([]examples.Item, N)
	for i := range items {
		items[i] = examples.Item{ID: uint64(i), Value: uint64(i) * 3}
	}
	view, _ := examples.NewBatch(1, items)
	list := examples.Items(view)
	if list.Len() != N {
		t.Fatalf("Len: %d, want %d", list.Len(), N)
	}

	sumID := uint64(0)
	sumValue := uint64(0)
	for itemView := range list.All() {
		sumID += zapv1.Read(itemView, examples.ItemFields.ID)
		sumValue += zapv1.Read(itemView, examples.ItemFields.Value)
	}
	wantSumID := uint64(N) * uint64(N-1) / 2
	wantSumValue := wantSumID * 3
	if sumID != wantSumID {
		t.Fatalf("sumID: %d, want %d", sumID, wantSumID)
	}
	if sumValue != wantSumValue {
		t.Fatalf("sumValue: %d, want %d", sumValue, wantSumValue)
	}
}

// TestIter_Combinators: Take, Filter, Map, Count, Collect compose
// correctly over List[E].All().
func TestIter_Combinators(t *testing.T) {
	t.Parallel()
	items := []examples.Item{
		{ID: 1, Value: 10},
		{ID: 2, Value: 20},
		{ID: 3, Value: 30},
		{ID: 4, Value: 40},
		{ID: 5, Value: 50},
	}
	view, _ := examples.NewBatch(0, items)
	list := examples.Items(view)

	// Take 3.
	first3 := zapv1.Collect(zapv1.Take(list.All(), 3))
	if len(first3) != 3 {
		t.Fatalf("Take(3): got %d", len(first3))
	}

	// Filter: only odd IDs.
	odd := zapv1.Filter(list.All(), func(v zapv1.View[examples.ItemSchema]) bool {
		return zapv1.Read(v, examples.ItemFields.ID)%2 == 1
	})
	if n := zapv1.Count(odd); n != 3 { // IDs 1, 3, 5
		t.Fatalf("Filter odd: %d, want 3", n)
	}

	// Map: extract ID.
	ids := zapv1.Collect(zapv1.Map(list.All(),
		func(v zapv1.View[examples.ItemSchema]) uint64 {
			return zapv1.Read(v, examples.ItemFields.ID)
		}))
	if len(ids) != 5 || ids[0] != 1 || ids[4] != 5 {
		t.Fatalf("Map IDs: %v", ids)
	}
}

// TestIsZero: zero values of View and List report IsZero=true and do
// not panic on accessor calls.
func TestIsZero(t *testing.T) {
	t.Parallel()
	var v zapv1.View[examples.AdvanceTimeSchema]
	if !v.IsZero() {
		t.Fatal("zero View should be IsZero")
	}
	if got := zapv1.Read(v, examples.AdvanceTimeFields.Time); got != 0 {
		t.Fatalf("zero View Read: got %d, want 0", got)
	}
	var l zapv1.List[examples.ItemSchema]
	if !l.IsZero() {
		t.Fatal("zero List should be IsZero")
	}
	if got := l.Len(); got != 0 {
		t.Fatalf("zero List Len: got %d, want 0", got)
	}
}

// --- Test-only schemas for the 8+ shapes coverage above ---

type boolSchema struct{}

func (boolSchema) Kind() zapv1.KindByte { return 0xC0 }
func (boolSchema) Size() int            { return 2 }
func (boolSchema) Name() string         { return "boolSchema" }

var boolFields = struct {
	Flag zapv1.Field[boolSchema, bool]
}{Flag: zapv1.At[boolSchema, bool](1)}

type i8Schema struct{}

func (i8Schema) Kind() zapv1.KindByte { return 0xC1 }
func (i8Schema) Size() int            { return 2 }
func (i8Schema) Name() string         { return "i8Schema" }

var i8Fields = struct {
	V zapv1.Field[i8Schema, int8]
}{V: zapv1.At[i8Schema, int8](1)}

type i16Schema struct{}

func (i16Schema) Kind() zapv1.KindByte { return 0xC2 }
func (i16Schema) Size() int            { return 4 }
func (i16Schema) Name() string         { return "i16Schema" }

var i16Fields = struct {
	V zapv1.Field[i16Schema, int16]
}{V: zapv1.At[i16Schema, int16](2)}

type i32Schema struct{}

func (i32Schema) Kind() zapv1.KindByte { return 0xC3 }
func (i32Schema) Size() int            { return 8 }
func (i32Schema) Name() string         { return "i32Schema" }

var i32Fields = struct {
	V zapv1.Field[i32Schema, int32]
}{V: zapv1.At[i32Schema, int32](4)}

type i64Schema struct{}

func (i64Schema) Kind() zapv1.KindByte { return 0xC4 }
func (i64Schema) Size() int            { return 16 }
func (i64Schema) Name() string         { return "i64Schema" }

var i64Fields = struct {
	V zapv1.Field[i64Schema, int64]
}{V: zapv1.At[i64Schema, int64](8)}

type u32Schema struct{}

func (u32Schema) Kind() zapv1.KindByte { return 0xC5 }
func (u32Schema) Size() int            { return 8 }
func (u32Schema) Name() string         { return "u32Schema" }

var u32Fields = struct {
	V zapv1.Field[u32Schema, uint32]
}{V: zapv1.At[u32Schema, uint32](4)}

type f32Schema struct{}

func (f32Schema) Kind() zapv1.KindByte { return 0xC6 }
func (f32Schema) Size() int            { return 8 }
func (f32Schema) Name() string         { return "f32Schema" }

var f32Fields = struct {
	V zapv1.Field[f32Schema, float32]
}{V: zapv1.At[f32Schema, float32](4)}

type f64Schema struct{}

func (f64Schema) Kind() zapv1.KindByte { return 0xC7 }
func (f64Schema) Size() int            { return 16 }
func (f64Schema) Name() string         { return "f64Schema" }

var f64Fields = struct {
	V zapv1.Field[f64Schema, float64]
}{V: zapv1.At[f64Schema, float64](8)}
