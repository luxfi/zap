// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package examples contains worked examples that demonstrate how to
// express a schema with the v2 generic ZAP API. The canary schema is
// AdvanceTimeTx — the same one that the v1 [zap_native] package uses
// as its C-port-shape canary. Comparing the two side-by-side shows
// exactly what generics buy you.
//
// v1 shape (one file per tx, ~80 lines of hand-rolled boilerplate):
//
//	const OffsetAdvanceTimeTx_Time = 1
//	type AdvanceTimeTx struct { msg *zap.Message; obj zap.Object }
//	func WrapAdvanceTimeTx(b []byte) (AdvanceTimeTx, error) { ... }
//	func (t AdvanceTimeTx) Time() uint64 {
//	    return t.obj.Uint64(OffsetAdvanceTimeTx_Time)
//	}
//	// ... and so on for every field, every type
//
// v2 shape (declarations only; the generic API does the rest):
//
//	type AdvanceTimeSchema struct{}
//	func (AdvanceTimeSchema) Kind() zapv1.KindByte { return 0x14 }
//	func (AdvanceTimeSchema) Size() int            { return 9 }
//	func (AdvanceTimeSchema) Name() string         { return "AdvanceTimeTx" }
//
//	var AdvanceTimeFields = struct {
//	    Time zapv1.Field[AdvanceTimeSchema, uint64]
//	}{
//	    Time: zapv1.At[AdvanceTimeSchema, uint64](1),
//	}
//
// That's it. Wrap, Build, Read, Write are all expressed through the
// generic API.
package examples

import (
	"github.com/luxfi/zap"
	"github.com/luxfi/zap/v1"
)

// KindAdvanceTime is the wire discriminator for AdvanceTimeTx. It
// matches the value in luxfi/node/vms/platformvm/txs/zap_native/
// (TxKindAdvanceTime = 1). The byte-equality test in
// advance_time_tx_test.go pins this so the v2 generic builder
// produces the exact same bytes as the v1 hand-rolled
// NewAdvanceTimeTx.
const KindAdvanceTime zapv1.KindByte = 1

// AdvanceTimeSchema is the v2 schema marker for AdvanceTimeTx. The
// type is the schema's identity; the methods describe its wire shape.
type AdvanceTimeSchema struct{}

// Kind returns the discriminator byte at object offset 0.
func (AdvanceTimeSchema) Kind() zapv1.KindByte { return KindAdvanceTime }

// Size returns the fixed object payload (1 byte kind + 8 byte time).
func (AdvanceTimeSchema) Size() int { return 9 }

// Name returns the human-readable schema name.
func (AdvanceTimeSchema) Name() string { return "AdvanceTimeTx" }

// AdvanceTimeFields is the namespace of every field accessor for
// AdvanceTimeSchema. There is exactly ONE place where offsets are
// declared; everywhere else uses these typed handles.
//
// Reading: zapv1.Read(view, AdvanceTimeFields.Time) → uint64
// Writing: zapv1.Write(setter, AdvanceTimeFields.Time, ts)
//
// A compile error guards against using these handles with any view
// other than View[AdvanceTimeSchema] — see
// _compile_fail_test/cross_schema_field.go for the demonstration.
var AdvanceTimeFields = struct {
	Time zapv1.Field[AdvanceTimeSchema, uint64]
}{
	Time: zapv1.At[AdvanceTimeSchema, uint64](1),
}

// NewAdvanceTime builds a fresh AdvanceTimeTx with the given
// timestamp. Returns the typed view and the underlying buffer (they
// alias the same memory).
//
// Per-schema hand-rolled fast path: calls v1's [zap.NewBuilder] and
// [zap.StartObject] directly so their inlineable bodies fold into
// the call site (escape analysis then stack-allocates the transient
// *Builder and *ObjectBuilder — the only heap alloc is the buffer
// itself). Result: matches v1's hand-rolled 1-alloc / 48-B profile.
//
// This pattern is what a codegen tool would emit per schema. The
// generic [zapv1.NewBuilderFor] / [zapv1.Build] paths are equivalent
// in wire semantics but incur extra allocations because Go generics
// hide the inlineable v1 primitives behind a non-inlineable shape
// function — see the BENCH_RESULTS table for the measured cost
// breakdown.
func NewAdvanceTime(ts uint64) (zapv1.View[AdvanceTimeSchema], []byte) {
	const size = 9 // AdvanceTimeSchema{}.Size()
	b := zap.NewBuilder(zap.HeaderSize + size)
	ob := b.StartObject(size)
	ob.SetUint8(0, uint8(KindAdvanceTime))
	ob.SetUint64(1, ts) // AdvanceTimeFields.Time.Offset == 1
	rootOff := ob.FinishAsRoot()
	buf := b.Finish()
	end := rootOff + size
	return zapv1.AsView[AdvanceTimeSchema](zapv1.RawFromSlices(buf, rootOff, end)), buf
}

// NewAdvanceTimeClosure is the closure-style equivalent of
// [NewAdvanceTime]. Kept as a documented alternative: it reads more
// like English at the call site, at the cost of ~3 extra allocations
// per Build. Use it for cold paths (CLI tools, test fixtures) and
// reach for the imperative form on hot paths (per-block tx assembly).
func NewAdvanceTimeClosure(ts uint64) (zapv1.View[AdvanceTimeSchema], []byte) {
	return zapv1.Build[AdvanceTimeSchema](func(s zapv1.Setter[AdvanceTimeSchema]) {
		zapv1.Write(s, AdvanceTimeFields.Time, ts)
	})
}

// WrapAdvanceTime is the typed accessor over an existing buffer.
//
// Per-schema hand-rolled fast path: parses the wire frame inline,
// validates the kind discriminator, and composes a typed
// [zapv1.View[AdvanceTimeSchema]]. Result: matches v1 hand-rolled
// performance to within compiler noise. Zero heap allocs on the
// happy path.
//
// Defense-in-depth: the explicit payload bounds check is folded into
// the per-Read bounds check that lives in [zapv1.Read] — wrapping a
// short buffer succeeds, but any out-of-range Read returns the zero
// value (matches v1 graceful-degradation semantics, see
// [zap.Object.Uint64]).
//
// This pattern is what a codegen tool emits per schema. For cold
// paths where ergonomics matter more than the last few ns, use the
// generic [zapv1.Wrap[AdvanceTimeSchema]] instead.
func WrapAdvanceTime(b []byte) (zapv1.View[AdvanceTimeSchema], error) {
	const size = 9 // AdvanceTimeSchema{}.Size()
	msg, err := zap.Parse(b)
	if err != nil {
		return zapv1.View[AdvanceTimeSchema]{}, err
	}
	root := msg.Root()
	if got := root.Uint8(0); got != uint8(KindAdvanceTime) {
		return zapv1.View[AdvanceTimeSchema]{},
			advanceTimeKindError(got)
	}
	data := msg.Bytes()
	rootOff := root.Offset()
	end := rootOff + size
	if end > len(data) {
		end = len(data)
	}
	return zapv1.AsView[AdvanceTimeSchema](
		zapv1.RawFromSlices(data, rootOff, end)), nil
}

// advanceTimeKindError builds the kind-mismatch error for
// AdvanceTimeTx. Pulled out of [WrapAdvanceTime]'s body so the
// happy-path body fits under the Go inliner's 80-cost budget when
// possible — when [WrapAdvanceTime] inlines into the caller, the
// error path stays an out-of-line tail call.
func advanceTimeKindError(got uint8) error {
	return zapv1.NewSchemaError(
		zapv1.KindByte(KindAdvanceTime),
		zapv1.KindByte(got),
		"AdvanceTimeTx")
}

// Time returns the timestamp the proposer is suggesting the network
// advance to. Zero copy, zero allocation.
//
// This is the value-side accessor — a thin one-line wrapper around
// zapv1.Read for callers who prefer method syntax. It is NOT what
// you'd write in a fresh project; just use zapv1.Read(view, Fields.X)
// directly. Kept here so the example covers both forms.
func Time(v zapv1.View[AdvanceTimeSchema]) uint64 {
	return zapv1.Read(v, AdvanceTimeFields.Time)
}

func init() {
	// Register with the package-level Registry so generic dispatch
	// (PeekKind → Registry.Lookup → WrapAs) finds this schema.
	zapv1.Register[AdvanceTimeSchema](zapv1.DefaultRegistry)
}
