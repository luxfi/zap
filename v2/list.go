// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2

import (
	"iter"

	"github.com/luxfi/zap"
)

// List is a typed, zero-copy view into a homogeneous list of objects
// of schema E. List[E] and List[F] are distinct types at compile time;
// you cannot accidentally iterate a list of Outputs as if it were a
// list of Inputs.
//
// The element type E identifies the schema for each entry. Each call
// to [List.At] returns a View[E] over the corresponding fixed-size
// slot, and [List.All] returns an [iter.Seq] for range-over-func.
//
// Layout: like [View], List is value-typed and contains no pointers
// other than the slice header for `data`. It carries the absolute byte
// offset of the first element and the wire-encoded length. Stride
// derives from E{}.Size() at call time.
type List[E Schema] struct {
	// data aliases the full ZAP buffer. Element slots are computed by
	// pointer arithmetic against data.
	data []byte
	// offset is the absolute byte position of element 0.
	offset int32
	// length is the wire-encoded element count.
	length int32
}

// Len returns the number of elements in the list.
//
// SAFETY: the value is wire-encoded; callers MUST NOT pre-allocate
// `make([]T, l.Len())` without an independent upper bound — see the
// v1 documentation of [zap.List.Len] for rationale. Iterate via [All]
// or index via [At] instead.
func (l List[E]) Len() int { return int(l.length) }

// IsZero reports whether the list view is uninitialized.
func (l List[E]) IsZero() bool { return l.data == nil }

// At returns the View[E] for element i. Out-of-range i returns the
// zero View[E] (matches v1 graceful degradation).
//
// Element stride is taken from E{}.Size() — every element in a
// homogeneous list occupies exactly that many bytes.
func (l List[E]) At(i int) View[E] {
	if l.data == nil || i < 0 || i >= int(l.length) {
		return View[E]{}
	}
	var s E
	stride := s.Size()
	off := int(l.offset) + i*stride
	return viewAt[E](l.data, off, stride)
}

// All returns an [iter.Seq] over every element. Use with the Go 1.23+
// range-over-func form:
//
//	for view := range list.All() {
//	    t := zapv2.Read(view, EFields.Time)
//	    // ...
//	}
//
// Constant memory: the iterator does not materialize a slice; each
// View[E] aliases the corresponding slot in the underlying buffer.
// Verified by [bench_test.go] over 1M elements.
//
// The yield function can return false to early-exit; semantics are
// identical to the stdlib iter.Seq contract.
//
// Performance: View[E] is 56 bytes (three slice headers + an int32),
// so the closure spills it to stack each iteration. For the hot path
// where you only need the payload (e.g. fixed-field reads), use
// [List.Payloads] which yields a 24-byte slice per element — that
// fits in registers and matches v1's per-element iteration cost.
func (l List[E]) All() iter.Seq[View[E]] {
	return func(yield func(View[E]) bool) {
		if l.data == nil {
			return
		}
		var s E
		stride := s.Size()
		n := int(l.length)
		startOff := int(l.offset)
		data := l.data
		for i := 0; i < n; i++ {
			off := startOff + i*stride
			end := off + stride
			if end > len(data) {
				return
			}
			v := View[E]{
				data:    data,
				payload: data[off:end:end],
				rootOff: int32(off),
			}
			if !yield(v) {
				return
			}
		}
	}
}

// Payloads returns an [iter.Seq] over the per-element payload slices
// — a hot-path variant of [List.All] that yields only the 24-byte
// payload slice rather than the full 56-byte [View[E]]. The element's
// fixed fields are accessible via [ReadPayload]; variable-length
// tails (sub-objects, lists, bytes) are NOT — for those, use [All].
//
// Why it exists: View[E] doesn't fit in registers, so iterating a
// large list via [All] spills to stack per element (~2 ns extra).
// Payloads yields a slice header (16 bytes data ptr + len), which
// the compiler keeps in registers. For 1000-element batches reading
// only fixed fields, this closes the gap to v1's hand-rolled list
// iteration. See [bench_test.go] for the side-by-side.
//
// Usage:
//
//	for payload := range list.Payloads() {
//	    v := zapv2.ReadPayload[ItemSchema, uint64](payload, ItemFields.Value)
//	    // ...
//	}
func (l List[E]) Payloads() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		if l.data == nil {
			return
		}
		var s E
		stride := s.Size()
		n := int(l.length)
		startOff := int(l.offset)
		data := l.data
		for i := 0; i < n; i++ {
			off := startOff + i*stride
			end := off + stride
			if end > len(data) {
				return
			}
			if !yield(data[off:end:end]) {
				return
			}
		}
	}
}

// Indexed returns an [iter.Seq2] with (i, View[E]) pairs. Useful when
// the index is part of the loop logic (e.g. paired with a sibling
// slice of expected values in a test).
func (l List[E]) Indexed() iter.Seq2[int, View[E]] {
	return func(yield func(int, View[E]) bool) {
		if l.data == nil {
			return
		}
		var s E
		stride := s.Size()
		n := int(l.length)
		startOff := int(l.offset)
		data := l.data
		for i := 0; i < n; i++ {
			off := startOff + i*stride
			end := off + stride
			if end > len(data) {
				return
			}
			v := View[E]{
				data:    data,
				payload: data[off:end:end],
				rootOff: int32(off),
			}
			if !yield(i, v) {
				return
			}
		}
	}
}

// ListAt reads a List[E] from the field at offset f in view v.
//
// Top-level function (not a method on View[S]) for the same reason as
// [Read]: Go 1.23 does not allow type parameters on methods of
// generic types.
//
// E's schema-Size() is used as the per-element stride hint, which
// activates the tighter wire-layer bounds check ([zap.Object.ListStride])
// — an attacker-set 0xFFFFFFFF length is rejected up front.
func ListAt[S, E Schema](v View[S], offset uint32) List[E] {
	if v.data == nil {
		return List[E]{}
	}
	// Re-synthesize a zap.Object at the View's root so we can use the
	// audited ListStride accessor (RED-HIGH-1 length clamp +
	// RED-HIGH-2 header-alias rejection inherited verbatim from v1).
	// The transient *zap.Message produced by WrapBuffer escape-
	// analyzes onto the stack — no heap alloc.
	obj := v.asObject()
	var e E
	stride := uint32(e.Size())
	raw := obj.ListStride(int(offset), stride)
	if raw.IsNull() {
		return List[E]{}
	}
	return List[E]{
		data:   v.data,
		offset: int32(rawListOffset(raw)),
		length: int32(raw.Len()),
	}
}

// rawListOffset extracts the absolute offset of a [zap.List]'s element
// zero. v1 doesn't expose this as a method, but the canonical way to
// compute it is via List.Object(0, stride).Offset() — which the wire
// layer just did internally during ListStride. We replicate the
// arithmetic here to avoid an extra Object construction.
//
// The wire layer's List type has `offset int` (absolute) and
// `length int`. Calling Object(0, stride) returns Object{offset:
// l.offset + 0*stride}. So `rawListOffset(l)` is exactly l.Object(0,
// stride).Offset().
func rawListOffset(l zap.List) int {
	// Stride doesn't matter for element 0; pass 1 so the wire layer's
	// bounds check is the loosest possible (the inner if-len check
	// would only reject if l.length == 0, in which case Object{} is
	// returned with offset 0).
	if l.Len() == 0 {
		return 0
	}
	return l.Object(0, 1).Offset()
}

// WriteList writes a homogeneous list of element-schema E into the
// list-pointer field at byteOffset within schema S. The `each` closure
// is called once with an [*ElemSetter[E]] handle that writes one
// element per call to [ElemSetter.Append]; the list pointer in S's
// fixed payload is patched with the final (relOffset, length) when
// each returns.
//
// Example (BatchTx.Items, see examples/batch_tx.go):
//
//	zapv2.Build[BatchSchema](func(s zapv2.Setter[BatchSchema]) {
//	    zapv2.Write(s, BatchFields.ID, batchID)
//	    zapv2.WriteList[BatchSchema, ItemSchema](s, OffsetBatchItems,
//	        func(items *zapv2.ElemSetter[ItemSchema]) {
//	            for _, it := range source {
//	                items.Append(func(e zapv2.Setter[ItemSchema]) {
//	                    zapv2.Write(e, ItemFields.ID, it.id)
//	                    zapv2.Write(e, ItemFields.Value, it.val)
//	                })
//	            }
//	        })
//	})
//
// Stride is taken from E{}.Size(). The list lives in the variable
// section of the parent message, after the fixed payload — the exact
// wire layout that v1 [zap.Builder.StartList]/SetList produces.
//
// Wire encoding: the list-pointer field at byteOffset holds (relOffset,
// length); length is the number of elements (NOT bytes), matching v1's
// [zap.List.Object] indexing convention.
func WriteList[S, E Schema](s Setter[S], byteOffset uint32, each func(*ElemSetter[E])) {
	ob, b := s.raw()
	var sParent S
	var e E
	stride := e.Size()

	// Reserve the parent's entire fixed payload BEFORE list elements
	// are written. Without this, the list-element StartObject calls
	// would align and start writing on top of the parent's still-
	// unwritten tail — the parent's list-pointer field at byteOffset
	// would overlap with element 0's bytes (a real subtle bug if the
	// list pointer happens to live near the end of the fixed payload).
	ob.ReserveFixed(sParent.Size())

	es := &ElemSetter[E]{b: b, stride: stride}
	each(es)
	if es.count == 0 {
		// Empty list — write a null pointer.
		ob.SetList(int(byteOffset), 0, 0)
		return
	}
	ob.SetList(int(byteOffset), es.startPos, es.count)
}

// ElemSetter writes one element at a time into a list of schema E.
// Always passed by pointer so [WriteList] observes the final count
// after [each] returns.
type ElemSetter[E Schema] struct {
	b        *zap.Builder
	stride   int
	count    int
	startPos int // position of the first appended element
}

// Append writes one element by calling init with a Setter[E] over the
// element's fixed slot. The slot is zero-filled before init runs.
//
// init MUST write exactly the fields the schema expects; any byte
// within the slot that init does not touch is left as zero.
func (es *ElemSetter[E]) Append(init func(Setter[E])) {
	// Each list element is a stride-byte slot. StartObject anchors a
	// fresh ObjectBuilder at the current builder position; init
	// populates the slot's fields via Write; ObjectBuilder.Finish
	// advances the builder past the slot and returns its startPos.
	ob := es.b.StartObject(es.stride)
	init(Setter[E]{ob: ob, b: es.b})
	pos := ob.Finish()
	if es.count == 0 {
		es.startPos = pos
	}
	es.count++
}
