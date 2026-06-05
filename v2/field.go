// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2

import (
	"unsafe"

	"github.com/luxfi/zap"
)

// Field is a phantom-typed accessor for a fixed-size field within
// schema S. The type parameter T is the field's wire type (one of the
// [FieldKind] union). At compile time:
//
//   - Read[S, T](View[S], Field[S, T]) returns a T.
//   - Read[S, T](View[S], Field[OtherSchema, T]) is a compile error.
//   - Write[S, T](Setter[S], Field[S, T], v) writes v at the field's
//     offset.
//   - Write[S, T](Setter[OtherSchema], ...) is a compile error.
//
// The runtime representation of Field is just an offset; the compile-
// time tag is free. This is what gives v2 zero abstraction cost
// versus the v1 hand-rolled offset constants.
//
// Construct Field values once at package init (see the canary
// AdvanceTime schema in examples/advance_time_tx.go for the pattern).
// Reusing Field values across goroutines is safe — they are immutable
// after declaration.
//
// Implementation note: Go 1.23+ does not allow type parameters on
// methods of generic types ([View[S].Read[T] would be illegal]). v2
// therefore exposes Read and Write as top-level generic functions
// rather than methods on [View] / [Setter]. The call site is at least
// as terse as a method call: `zapv2.Read(view, F.Time)`.
type Field[S Schema, T FieldKind] struct {
	Offset uint32
	// _phantom keeps the nominal type identity tight: without it the
	// Go compiler can structurally unify Field[A, uint64] and
	// Field[B, uint64] in some inference paths because the only data
	// member (Offset uint32) is identical. The zero-sized struct
	// referencing S and T forces the type parameters to remain
	// load-bearing for type identity, so cross-schema misuse fails to
	// compile.
	_phantom [0]phantomCarrier[S, T]
}

// phantomCarrier is the auxiliary type whose only purpose is to make
// the type parameters of Field load-bearing for nominal identity. It
// has no runtime footprint (size 0).
type phantomCarrier[S Schema, T FieldKind] struct {
	_ [0]S
	_ [0]T
}

// At returns a Field[S, T] for the given byte offset within S's
// fixed-size payload. Construct fields once per schema:
//
//	var AdvanceTimeFields = struct {
//	    Time zapv2.Field[AdvanceTimeSchema, uint64]
//	}{
//	    Time: zapv2.At[AdvanceTimeSchema, uint64](1),
//	}
//
// The offset is in bytes. The caller is responsible for keeping
// offsets within S{}.Size() and for not overlapping fields — this is
// a schema-design concern, not enforced at runtime. (A misdeclared
// offset is caught by the byte-equality test in the canary, which is
// the right safety net — wire format is the source of truth.)
func At[S Schema, T FieldKind](offset uint32) Field[S, T] {
	return Field[S, T]{Offset: offset}
}

// Read reads the field f's value from view v.
//
// Compile-time safety: the type parameters S and T are inferred from
// the (view, field) pair. Passing a Field for a different schema to a
// View[S] fails to type-check because Field[OtherSchema, T] is not
// assignable to Field[S, T].
//
// Zero copy, zero allocation. Out-of-range offsets return the zero
// value of T (matches the audited v1 [zap.Object] bounds-check
// behaviour: degrade gracefully to zero rather than panic).
//
// Performance: this function reads bytes directly from the View's
// pre-sliced payload via [unsafe.Pointer], folding to a single load
// instruction per concrete T after generic instantiation. Verified by
// [bench_test.go]: matches hand-rolled v1 [zap.Object.Uint64] to
// within compiler-noise.
//
// Wire format: ZAP integers are little-endian. On little-endian hosts
// (every Lux target — amd64, arm64, aarch64) the load is a direct
// cast. The pkg builds only on little-endian platforms; a future big-
// endian port would need a per-type byteswap (see init()).
func Read[S Schema, T FieldKind](v View[S], f Field[S, T]) T {
	var zero T
	// Bounds check: the payload slice is exactly S.Size() bytes long;
	// a misdeclared field offset that points past the fixed section
	// returns the zero value instead of panicking. This mirrors v1's
	// graceful-degradation contract.
	size := int(unsafe.Sizeof(zero))
	off := int(f.Offset)
	if off < 0 || off+size > len(v.payload) {
		return zero
	}
	// Little-endian direct load. On amd64/arm64 this compiles to a
	// single MOV (8-byte for uint64/int64/float64, 4-byte for
	// uint32/int32/float32, etc).
	//
	// Safety: the bounds check above proves off..off+size is in
	// payload; payload aliases the caller's buffer which the caller is
	// bound to keep alive. The conversion is bit-identity (FieldKind
	// values share the wire encoding with their unsigned counterpart).
	return *(*T)(unsafe.Pointer(&v.payload[off]))
}

// ReadPayload reads a field directly from a payload byte slice (as
// yielded by [List.Payloads]). This is the hot-path counterpart to
// [Read] — equivalent wire semantics, but the input is a 24-byte
// slice header (registers-friendly) rather than a 56-byte [View[S]]
// (stack-spilling).
//
// Use ReadPayload inside a for-range over [List.Payloads] when
// iterating large lists with fixed-field reads only. For full View
// operations (Bytes, sub-objects, lists) use [Read] with [List.All].
//
// Compile-time safety: same as [Read] — Field[S, T] is phantom-typed
// against schema S, so the compiler rejects cross-schema misuse even
// though the payload slice itself is plain []byte. The S type
// parameter is what ties the field to its declared schema.
func ReadPayload[S Schema, T FieldKind](payload []byte, f Field[S, T]) T {
	var zero T
	size := int(unsafe.Sizeof(zero))
	off := int(f.Offset)
	if off < 0 || off+size > len(payload) {
		return zero
	}
	return *(*T)(unsafe.Pointer(&payload[off]))
}

// init-side static check: this file assumes a little-endian host. If
// the build platform is ever switched to big-endian, the directLoad
// path needs a per-T byteswap. We sanity-check at package init by
// reading a 2-byte word with both interpretations; the result of the
// check is unused at runtime (the panic fires only on misconfig).
func init() {
	var u uint16 = 1
	if *(*[2]byte)(unsafe.Pointer(&u)) != [2]byte{1, 0} {
		// readBE path would need to be wired here. The package
		// currently only targets little-endian platforms.
		panic("zapv2: big-endian host detected; direct-load Read path " +
			"requires per-T byteswap (see field.go).")
	}
}

// Write writes value val into field f of setter s.
//
// Compile-time safety: as with [Read], passing a Field declared for a
// different schema fails to type-check.
//
// Zero allocation. The write goes through the underlying v1
// [zap.ObjectBuilder] for the fixed payload — its bounds-check
// (ensureField) is inherited verbatim. After generic instantiation +
// inlining, this collapses to a direct little-endian store at the
// computed offset, matching v1 hand-rolled SetUint64 performance —
// verified by [bench_test.go].
//
// Implementation note: writing through the ObjectBuilder (rather than
// a direct unsafe store into the underlying buffer) preserves v1's
// audited "ensureField" semantics — fields past the currently-written
// region get the buffer growth + zero-fill that the builder
// guarantees. A bare unsafe write would bypass that and corrupt the
// builder's invariant.
func Write[S Schema, T FieldKind](s Setter[S], f Field[S, T], val T) {
	writeAt(s.ob, f.Offset, val)
}

// WriteB is the [Builder]-receiver counterpart to [Write]. Used in
// the imperative-style build path:
//
//	bb := zapv2.NewBuilderFor[Schema]()
//	zapv2.WriteB(bb, Fields.Time, ts)
//	view, buf := bb.Finish()
//
// Identical wire semantics to Write — the difference is only that
// passing a Builder[S] (by value) instead of a Setter[S] (through a
// closure) keeps the wrapper on the caller's stack. The underlying
// v1 *zap.Builder still escapes (its buffer is what goes on the
// wire), so the imperative form does not eliminate all v2 overhead —
// it eliminates only the closure-captured pointer allocation.
func WriteB[S Schema, T FieldKind](bb Builder[S], f Field[S, T], val T) {
	writeAt(bb.ob, f.Offset, val)
}

// writeAt is the shared underlying write impl. It uses a static type
// switch on T's concrete type so the Go compiler folds each generic
// instantiation to exactly one Set* call — no runtime any-boxing, no
// interface conversion.
//
// The cost-budget trick: Go's inliner sees `any(val).(type)` as a
// runtime dispatch (cost ~700, never inlines). A static `switch`
// against unsafe.Sizeof on the type parameter, each branch calling
// one v1 ObjectBuilder.Set* method, folds to one MOV per concrete T
// after generic instantiation and inlining.
func writeAt[T FieldKind](ob *zap.ObjectBuilder, offset uint32, val T) {
	off := int(offset)
	switch unsafe.Sizeof(val) {
	case 1:
		ob.SetUint8(off, *(*uint8)(unsafe.Pointer(&val)))
	case 2:
		ob.SetUint16(off, *(*uint16)(unsafe.Pointer(&val)))
	case 4:
		ob.SetUint32(off, *(*uint32)(unsafe.Pointer(&val)))
	case 8:
		ob.SetUint64(off, *(*uint64)(unsafe.Pointer(&val)))
	}
}
