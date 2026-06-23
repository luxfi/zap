// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

// Repeated nested objects — the "repeated message" wire shape. Where
// [List] holds fixed-stride INLINE elements (every element is exactly
// E.Size() bytes, no element-level tail), ListNested holds variable-size
// elements: each list slot is a 4-byte object POINTER into the parent's
// tail, and the pointed-to object is a full flat [View] with its own
// scalars, strings, bytes, lists, and further nesting.
//
// This is exactly [List] ∘ [NestedAt]: a stride-4 pointer array (the audited
// wire [zap.List]) whose every element is followed like a singular nested
// pointer. The two primitives compose — no new wire concept, just their
// product — which is why a repeated message of arbitrary internal shape
// needs no special case here: each element is read by the same
// pointer-follow [NestedAt] uses.
//
// Use this (not [List]) whenever the element schema carries a
// variable-length tail of its own. [List]'s fixed stride cannot place
// per-element tails; ListNested gives each element its own out-of-line
// object so the tails never collide.

import (
	"encoding/binary"
	"iter"

	"github.com/luxfi/zap"
)

// objPtrStride is the width of one object-pointer slot: a single 4-byte
// signed relative offset (the [zap.Object.Object] / [zap.ObjectBuilder.
// SetObject] encoding), with no length word (that's per-list, not
// per-element).
const objPtrStride = 4

// ListNested is a typed, zero-copy view into a repeated nested-object
// field. Each element is reached by following a 4-byte pointer slot to an
// out-of-line [View[N]]; elements may carry their own variable-length
// tails. Distinct compile-time type from [List[E]] so an inline-element
// list and a pointer-element list can never be confused.
type ListNested[N Schema] struct {
	// data aliases the full ZAP buffer.
	data []byte
	// offset is the absolute byte position of pointer-slot 0 (stride 4).
	offset int32
	// length is the wire-encoded element (pointer) count.
	length int32
}

// Len returns the number of elements. SAFETY: wire-encoded — do not
// preallocate against it without an independent bound (see [List.Len]).
func (l ListNested[N]) Len() int { return int(l.length) }

// IsZero reports whether the list view is uninitialized (null field).
func (l ListNested[N]) IsZero() bool { return l.data == nil }

// At returns the View[N] for element i by following its pointer slot. An
// out-of-range index, a null slot, or an out-of-bounds target yields the
// zero View[N] (v1 graceful degradation — test with [View.IsZero]).
func (l ListNested[N]) At(i int) View[N] {
	if l.data == nil || i < 0 || i >= int(l.length) {
		return View[N]{}
	}
	slotPos := int(l.offset) + i*objPtrStride
	if slotPos < 0 || slotPos+objPtrStride > len(l.data) {
		return View[N]{}
	}
	rel := int32(binary.LittleEndian.Uint32(l.data[slotPos:]))
	if rel == 0 {
		return View[N]{} // null element
	}
	target := slotPos + int(rel)
	var n N
	end := target + n.Size()
	// Same bounds discipline as [zap.Object.Object]: a pointer may not
	// target the wire header, and the flat payload must lie within the
	// buffer (end < target guards the int overflow on a hostile size).
	if target < zap.HeaderSize || end > len(l.data) || end < target {
		return View[N]{}
	}
	return View[N]{
		data:    l.data,
		payload: l.data[target:end:end],
		rootOff: int32(target),
	}
}

// All returns an [iter.Seq] over every element, following each pointer in
// turn. Range-over-func:
//
//	for it := range ListNestedAt[Parent, Child](v, off).All() {
//	    name := ChildName(it) // it is a full View[Child]
//	}
func (l ListNested[N]) All() iter.Seq[View[N]] {
	return func(yield func(View[N]) bool) {
		if l.data == nil {
			return
		}
		for i, n := 0, int(l.length); i < n; i++ {
			if !yield(l.At(i)) {
				return
			}
		}
	}
}

// ListNestedAt reads a repeated nested-object field from the list pointer
// at byteOffset in view v. The field holds an 8-byte {relOffset, length}
// list pointer (as any list does); the list elements are 4-byte object
// pointers. A null field yields the zero ListNested[N].
func ListNestedAt[S, N Schema](v View[S], offset uint32) ListNested[N] {
	if v.data == nil {
		return ListNested[N]{}
	}
	// Pointer slots are stride 4; the audited ListStride accessor bounds
	// the wire-encoded length by buffer/stride (RED-HIGH-1) and rejects a
	// header-aliasing list (RED-HIGH-2), inherited verbatim.
	raw := v.asObject().ListStride(int(offset), objPtrStride)
	if raw.IsNull() {
		return ListNested[N]{}
	}
	return ListNested[N]{
		data:   v.data,
		offset: int32(rawListOffset(raw)),
		length: int32(raw.Len()),
	}
}

// WriteListNested writes a repeated nested-object field: each element is
// built as a flat out-of-line object in the parent tail (with its own
// scalars/strings/lists), then a contiguous stride-4 pointer array is laid
// down and the list field patched to it. The pointer-array peer of
// [WriteList] (which inlines fixed-stride elements). An empty list writes a
// null pointer.
func WriteListNested[S, N Schema](s Setter[S], byteOffset uint32, each func(*NestedElemSetter[N])) {
	ob, b := s.raw()
	var sParent S

	// Reserve the parent fixed payload before any tail object is started —
	// identical invariant to [WriteList]/[WriteNested].
	ob.ReserveFixed(sParent.Size())

	es := &NestedElemSetter[N]{b: b}
	each(es)
	if len(es.positions) == 0 {
		ob.SetList(int(byteOffset), 0, 0)
		return
	}
	// The nested objects (and their tails) are already in the buffer; lay
	// the pointer array after them. Each slot's relative offset is computed
	// against the slot's own position by [zap.ListBuilder.AddObjectPtr].
	lb := b.StartList(objPtrStride)
	for _, p := range es.positions {
		lb.AddObjectPtr(p)
	}
	listOffset, length := lb.Finish()
	ob.SetList(int(byteOffset), listOffset, length)
}

// NestedElemSetter builds the elements of a repeated nested-object field,
// one out-of-line object per [Append]. It records each object's position
// so [WriteListNested] can emit the pointer array after the last element.
type NestedElemSetter[N Schema] struct {
	b         *zap.Builder
	positions []int
}

// Append builds one element by calling init with a Setter[N] over a fresh
// out-of-line object. init populates the element's fields via
// [Write]/[WriteString]/[WriteBytes]/[WriteList]/[WriteNested] — it composes
// exactly like a top-level build, so elements may carry their own tails.
func (es *NestedElemSetter[N]) Append(init func(Setter[N])) {
	var n N
	ob := es.b.StartObject(n.Size())
	init(Setter[N]{ob: ob, b: es.b})
	es.positions = append(es.positions, ob.Finish())
}
