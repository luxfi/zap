// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

import (
	"unsafe"

	"github.com/luxfi/zap"
)

// Layout invariant: [View[S]] and [Raw] share an identical memory
// layout (data, payload, rootOff). The unsafe cast in [AsView]
// depends on this. This compile-time assertion pins it — any future
// change to View[S]'s shape that breaks this invariant will fail to
// compile here, NOT silently produce undefined behaviour at runtime.
var _ = [1]struct{}{}[unsafe.Sizeof(View[stubSchema]{})-unsafe.Sizeof(Raw{})]

// stubSchema is a tiny zero-sized Schema used only to instantiate
// View at compile time for the layout assertion above.
type stubSchema struct{}

func (stubSchema) Kind() KindByte { return 0 }
func (stubSchema) Size() int      { return 0 }
func (stubSchema) Name() string   { return "stub" }

// View is a typed, zero-copy reference into a ZAP buffer. The type
// parameter S identifies the schema; a View[A] and a View[B] are
// distinct types and the compiler refuses to mix them. This is what
// makes [Field] accessors safe: the compiler will not let you pass a
// Field[A, uint64] to a View[B].Read.
//
// View carries no per-instance schema state — the schema's identity
// lives in the type parameter, and S{}'s methods (Kind/Size/Name) are
// queried only at boundaries (Wrap, Build, Registry). Inside the hot
// path the type parameter is purely a compile-time tag; no boxing, no
// interface dispatch.
//
// View is safe to copy. The underlying buffer must outlive every View
// that references it.
//
// Layout: a View holds two slice headers — `data` aliases the full ZAP
// buffer (used by variable-length tail accessors: list, bytes), and
// `payload` aliases the fixed section of the root object (used by
// Read/Write for direct unsafe-pointer indexing). Neither field is a
// pointer to a heap-allocated `*zap.Message` — that was the v1.0 design
// and forced a heap allocation per Wrap because the *Message escaped
// from the View's lifetime. The v1.1 redesign keeps everything in slice
// headers; View[S] is 56 bytes (3 slice headers + an int32 offset);
// stack-allocatable; escape-analysis-friendly.
type View[S Schema] struct {
	// data aliases the full ZAP buffer (header + data segment). Used
	// for variable-length tail accessors that need to resolve relative
	// offsets against an absolute anchor (list, bytes).
	data []byte
	// payload aliases the fixed-section bytes of the root object
	// (data[rootOff : rootOff+S{}.Size()] in practice). Fixed-size Read
	// operations index into this directly — no v1 Object accessor in
	// the hot path.
	payload []byte
	// rootOff is the absolute byte offset of the root object within
	// `data`. Kept so variable-length tail accessors (List, Bytes) can
	// re-synthesize a [zap.Object] without re-reading the header.
	rootOff int32
}

// Raw is the non-generic shape of [View]: same three fields, no
// schema type parameter. It exists as the value-shape that the per-
// schema Wrap shims construct in their hot path. Construction is via
// [WrapRaw] / [WrapRawUnchecked]; the public typed View[S] wraps a
// Raw with one struct cast.
//
// Treat Raw as an implementation detail of the per-schema shim
// constructors — application code uses [View[S]] / [Wrap].
type Raw struct {
	data    []byte
	payload []byte
	rootOff int32
}

// AsView converts a [Raw] to a typed [View[S]] without copying. The
// caller asserts that the Raw was produced by a constructor matching
// schema S (typically a per-schema [WrapX] shim that pinned S{}.Kind()
// and S{}.Size() at compile time).
//
// This is a zero-instruction cast: View[S] and Raw share an identical
// memory layout (data, payload, rootOff). The compiler folds it away
// via [unsafe.Pointer] reinterpretation — there is no struct copy.
// Verified by [bench_test.go].
//
// Layout invariant: View[S] MUST have the exact same fields in the
// same order as Raw. The compile-time assertion in [init] pins this.
func AsView[S Schema](r Raw) View[S] {
	return *(*View[S])(unsafe.Pointer(&r))
}

// WrapRaw parses a ZAP buffer and returns a [Raw] (non-generic) with
// the kind byte at the root validated against wantKind. The buffer's
// fixed-section size is validated against size. The schema name is
// used only when constructing a [*SchemaError] on kind mismatch.
//
// Used by per-schema [WrapX] shims: they pass S{}.Kind(), S{}.Size(),
// S{}.Name() as constants (because those methods on a zero-sized
// struct fold to literals at the call site), then convert the Raw to
// View[S] via [AsView]. Because none of the parse + bounds work is
// inside a generic shape function, the whole pipeline collapses to
// inlineable v1 primitives in the caller's frame — matching v1
// hand-rolled performance to within compiler noise.
//
// External callers should prefer [Wrap[S]] (which has the same wire
// semantics but goes through generic dispatch and is one function
// call slower per Wrap).
//
// Implementation: ParseHeader is delegated as the only non-inlined
// call site. The remainder lives inline (kind check + bounds + Raw
// compose). The result is ONE function call per Wrap (the
// parseHeaderImpl trampoline inside ParseHeader) — same depth as v1
// hand-rolled.
func WrapRaw(b []byte, wantKind uint8, size int, name string) (Raw, error) {
	data, rootOff, err := zap.ParseHeader(b)
	if err != nil {
		return Raw{}, err
	}
	end := rootOff + size
	if rootOff < 0 || end > len(data) {
		return Raw{}, zap.ErrOutOfBounds
	}
	got := data[rootOff]
	if got != wantKind {
		return Raw{}, newSchemaError(wantKind, got, name)
	}
	return Raw{
		data:    data,
		payload: data[rootOff:end:end],
		rootOff: int32(rootOff),
	}, nil
}

// newSchemaError allocates a [*SchemaError] for a kind mismatch.
// Pulled out of [WrapRaw] so the happy path stays inlineable. Only
// called on the error path — the *SchemaError allocation is part of
// the contract (callers want a typed error), so we don't worry about
// it.
func newSchemaError(want, got uint8, name string) *SchemaError {
	return &SchemaError{
		Want: KindByte(want),
		Got:  KindByte(got),
		Name: name,
	}
}

// NewSchemaError is the exported constructor used by per-schema
// [WrapX] shims (hand-written or codegen'd) on the kind-mismatch
// error path. Application code typically does not call this directly
// — it ships through the per-schema Wrap function's return value.
//
// Allocates one [*SchemaError]; only called on the error path so the
// alloc cost is outside the hot-path budget.
func NewSchemaError(want, got KindByte, name string) *SchemaError {
	return &SchemaError{Want: want, Got: got, Name: name}
}

// RawFromSlices composes a [Raw] directly from already-validated
// slices. Used by per-schema [WrapX] shims that did the parse + kind
// check inline — they pass the buffer, the root offset, and the end
// offset, and get back a Raw with the payload slice carved out (with
// the three-index slice form so accidental appends on the payload
// don't bleed into adjacent message bytes).
//
// SAFETY: the caller MUST have verified rootOff and end fall within
// data — this constructor performs no bounds checks. It is a struct-
// literal compose, intentionally so the inliner folds it into the
// per-schema shim.
func RawFromSlices(data []byte, rootOff, end int) Raw {
	return Raw{
		data:    data,
		payload: data[rootOff:end:end],
		rootOff: int32(rootOff),
	}
}

// WrapRawUnchecked is [WrapRaw] without the kind-byte check. The
// caller must have already dispatched on kind (typically via
// [Registry.Lookup] → [Entry.Wrap]).
func WrapRawUnchecked(b []byte, size int) (Raw, error) {
	data, rootOff, err := zap.ParseHeader(b)
	if err != nil {
		return Raw{}, err
	}
	if rootOff < 0 || rootOff >= len(data) {
		return Raw{}, zap.ErrOutOfBounds
	}
	end := rootOff + size
	if end > len(data) {
		return Raw{}, zap.ErrOutOfBounds
	}
	return Raw{
		data:    data,
		payload: data[rootOff:end:end],
		rootOff: int32(rootOff),
	}, nil
}

// Bytes returns the underlying ZAP buffer literally. Zero-copy,
// zero allocation. The buffer IS the wire format.
func (v View[S]) Bytes() []byte {
	return v.data
}

// RootOff returns the absolute byte offset of the root object within
// the underlying buffer. Exposed for codegen'd byte-array accessors
// that need to re-anchor a [zap.Object] at the root to call v1's
// out-of-line byte-slice readers ([zap.Object.BytesFixedSlice]).
// Application code typically does not need this — use the typed
// accessors emitted alongside each schema.
func RootOff[S Schema](v View[S]) int32 {
	return v.rootOff
}

// IsZero reports whether the view is uninitialized (the zero value
// of View[S]). A zero view does not alias any buffer.
func (v View[S]) IsZero() bool {
	return v.data == nil
}

// asObject re-synthesizes a [zap.Object] anchored at the root of this
// view. Used only by variable-length tail accessors (List, Bytes) that
// need v1's audited bounds-checked accessors. The hot-path Read does
// NOT touch this — it indexes into `payload` directly.
//
// The returned Object holds a transient *zap.Message — that's a v1 ABI
// constraint. Escape analysis stack-allocates it when the Object is
// used in the same frame (every list-iteration call site, every Bytes
// read).
func (v View[S]) asObject() zap.Object {
	msg := zap.WrapBuffer(v.data)
	return msg.RootObjectAt(int(v.rootOff))
}

// Wrap reads a ZAP buffer and returns a typed View[S].
//
// The kind byte at object offset 0 is checked against S{}.Kind(); a
// mismatch returns a [*SchemaError]. The underlying ZAP frame is
// validated by [zap.Parse] (magic, version, size, header-alias
// safety); any of those failures propagate as their original error.
//
// Zero copy: the returned View references b directly. The caller MUST
// keep b alive while the View is in use.
//
// Performance: View[S] is value-typed and contains no pointers. After
// generic instantiation + inlining, this collapses to a single Parse
// call (which the v1 layer inlines further), a 1-byte read for the
// kind check, and three slice-header writes. No heap allocation —
// verified by [bench_test.go].
func Wrap[S Schema](b []byte) (View[S], error) {
	var s S
	data, rootOff, end, err := parseAndCheck(b, uint8(s.Kind()), s.Size(), s.Name())
	if err != nil {
		return View[S]{}, err
	}
	return View[S]{
		data:    data,
		payload: data[rootOff:end:end],
		rootOff: int32(rootOff),
	}, nil
}

// parseAndCheck is the non-generic, shape-free portion of [Wrap]:
// validate the wire frame, bounds-check the root, compare the kind
// byte, bounds-check the payload. Returns (data, rootOff, end, nil)
// on success; the caller constructs the typed View[S] from those
// values via a single struct literal. Splitting this out keeps the
// per-Schema work down to three constant loads + one struct compose
// after inlining — verified by [bench_test.go].
//
// On kind mismatch returns a [*SchemaError] built from the supplied
// name. On any other validation failure returns the underlying
// [zap.ParseHeader]/bounds error verbatim.
func parseAndCheck(b []byte, wantKind uint8, size int, name string) ([]byte, int, int, error) {
	data, rootOff, err := zap.ParseHeader(b)
	if err != nil {
		return nil, 0, 0, err
	}
	if rootOff < 0 || rootOff >= len(data) {
		return nil, 0, 0, zap.ErrOutOfBounds
	}
	got := data[rootOff]
	if got != wantKind {
		return nil, 0, 0, &SchemaError{
			Want: KindByte(wantKind),
			Got:  KindByte(got),
			Name: name,
		}
	}
	end := rootOff + size
	if end > len(data) {
		return nil, 0, 0, zap.ErrOutOfBounds
	}
	return data, rootOff, end, nil
}

// WrapUnchecked is Wrap without the schema discriminator check. It
// still validates the ZAP frame. Intended only for callers that have
// already dispatched on kind (e.g. inside [Registry.Wrap]).
func WrapUnchecked[S Schema](b []byte) (View[S], error) {
	var s S
	data, rootOff, end, err := parseUnchecked(b, s.Size())
	if err != nil {
		return View[S]{}, err
	}
	return View[S]{
		data:    data,
		payload: data[rootOff:end:end],
		rootOff: int32(rootOff),
	}, nil
}

// parseUnchecked is the kind-byte-skipping counterpart of
// [parseAndCheck]: same parse + bounds, no schema match. Used by
// [Registry.Wrap] callers who have already dispatched on kind.
func parseUnchecked(b []byte, size int) ([]byte, int, int, error) {
	data, rootOff, err := zap.ParseHeader(b)
	if err != nil {
		return nil, 0, 0, err
	}
	if rootOff < 0 || rootOff >= len(data) {
		return nil, 0, 0, zap.ErrOutOfBounds
	}
	end := rootOff + size
	if end > len(data) {
		return nil, 0, 0, zap.ErrOutOfBounds
	}
	return data, rootOff, end, nil
}

// viewAt constructs a View[S] whose payload starts at absolute byte
// position `off` within data. Used by [List.At] and [List.All] for
// in-list elements whose offset is computed from the list header
// rather than the root pointer.
//
// Returns the zero View[S] if the requested slice is out of bounds —
// matches v1 graceful-degradation semantics.
func viewAt[S Schema](data []byte, off, size int) View[S] {
	end := off + size
	if off < 0 || end > len(data) {
		return View[S]{}
	}
	return View[S]{
		data:    data,
		payload: data[off:end:end],
		rootOff: int32(off),
	}
}

// Build writes a fresh ZAP buffer carrying a [View][S], populated by
// the provided init function. The init function receives a [Setter][S]
// — the only handle through which fields may be written — and is
// expected to set every field the schema requires before returning.
//
// The schema's kind byte is written at object offset 0 before init is
// called; init MUST NOT overwrite offset 0.
//
// Returns both the typed View and the underlying byte buffer. The two
// alias the same memory; the buffer is what goes on the wire.
//
// Performance: Build pays the closure-allocation cost (the init func
// captures its receiver and any callsite variables). For the per-tx
// hot path use the imperative [Builder][S] / [WriteB] pair instead —
// it matches the v1 hand-rolled 1-alloc profile.
func Build[S Schema](init func(Setter[S])) (View[S], []byte) {
	var s S
	cap := zap.HeaderSize + s.Size()
	b := zap.NewBuilder(cap)
	ob := b.StartObject(s.Size())
	ob.SetUint8(0, uint8(s.Kind()))
	init(Setter[S]{ob: ob, b: b})
	rootOff := ob.FinishAsRoot()
	buf := b.Finish()
	return viewAt[S](buf, rootOff, s.Size()), buf
}

// Setter is the write-side counterpart to [View]. A Setter[S] writes
// fields into the buffer for schema S. Like View, Setter is phantom-
// typed: a Field[S, uint64] cannot be written through Setter[T].
//
// Setter holds two pointers (ob, b) — both into the active builder.
// These pointers' targets always outlive the Setter (the builder owns
// them and is itself reachable from the caller's stack). Setter values
// are NOT safe to retain after the builder's Finish returns.
type Setter[S Schema] struct {
	ob zap.ObjectBuilder
	b  *zap.Builder
}

// raw exposes the underlying builder for advanced primitives that
// need to write variable-length tails (Text, Bytes, Lists). It is
// unexported; the variable-length writers in [list.go] use it.
func (s Setter[S]) raw() (zap.ObjectBuilder, *zap.Builder) {
	return s.ob, s.b
}
