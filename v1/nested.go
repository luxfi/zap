// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

// Singular nested objects — the out-of-line, single-object peer of the
// [List] machinery. A nested field holds a 4-byte object pointer
// {relOffset} in the parent's fixed payload (NOT the 8-byte {relOffset,
// length} a list holds); the nested object's flat payload lives in the
// parent's object tail, exactly where list elements live.
//
// The nested object is a flat ELEMENT schema (no kind discriminator byte
// at offset 0): the field type is known statically at both the build and
// the read call site (it is the N type parameter), so a runtime kind tag
// would be dead weight. This makes "singular nested" and "one list
// element" the same wire shape — a flat N-sized object reached by a
// relative pointer — differing only in arity (one pointer vs. a
// {pointer,count} pair). Codegen emits N as an Element schema for both.
//
// Composition is recursive and orthogonal: the init closure of
// [WriteNested] may itself call [Write], [WriteList], [WriteString],
// [WriteBytes], or [WriteNested] — so a nested object can carry its own
// scalars, strings, lists, and further-nested objects. On the read side,
// the [View] returned by [NestedAt] is a fully-formed View[N] (it aliases
// the same buffer with the nested object as its root), so every typed
// accessor — [Read], [ListAt], [NestedAt], the generated string/bytes
// readers — works against it unchanged.

// NestedAt reads a singular nested object from the out-of-line object
// pointer at byteOffset within view v, returning a typed View[N] anchored
// at the nested object. A null pointer (the proto3 "field unset" case, or
// any out-of-bounds pointer) yields the zero View[N] — test it with
// [View.IsZero].
//
// Top-level function (not a method on View[S]) for the same reason as
// [Read] and [ListAt]: Go 1.23 does not permit type parameters on methods
// of generic types.
//
// Zero copy: the returned View aliases v's underlying buffer; no bytes are
// moved. The nested View's lifetime is the parent buffer's lifetime.
func NestedAt[S, N Schema](v View[S], offset uint32) View[N] {
	if v.data == nil {
		return View[N]{}
	}
	// Re-synthesize the parent's zap.Object and follow the 4-byte
	// relative object pointer. Object() returns a Null object on a zero
	// relOffset (unset field) or an out-of-bounds target — both map to
	// the zero View[N] below.
	nested := v.asObject().Object(int(offset))
	if nested.IsNull() {
		return View[N]{}
	}
	off := nested.Offset()
	var n N
	end := off + n.Size()
	// Defence in depth: Object() already rejected off < HeaderSize and
	// off >= len(data), but it could not know N's fixed size. Reject a
	// pointer whose flat payload would run past the buffer end (a
	// truncated or hostile message) rather than alias out of bounds.
	if off < 0 || end > len(v.data) {
		return View[N]{}
	}
	return View[N]{
		data:    v.data,
		payload: v.data[off:end],
		rootOff: int32(off),
	}
}

// WriteNested builds a singular nested object of schema N into the parent
// object's tail and stores its 4-byte object pointer at byteOffset in the
// parent's fixed payload. The init closure populates the nested object's
// fields (via [Write]/[WriteString]/[WriteBytes]/[WriteList]/[WriteNested]
// — it composes recursively). The singular peer of [WriteList].
//
// Omitting the call entirely leaves the pointer field zero — a null
// pointer — which [NestedAt] reads back as the zero View[N]. This is how
// codegen encodes an unset proto3 message field: emit the WriteNested only
// inside an `if msg != nil` guard.
//
// Wire layout matches the singular case of [WriteList]: the parent's
// fixed payload is reserved first (so the nested object cannot overwrite
// the still-unwritten pointer field), then the nested object is appended
// to the tail and the pointer patched with its relative offset.
func WriteNested[S, N Schema](s Setter[S], byteOffset uint32, init func(Setter[N])) {
	ob, b := s.raw()
	var sParent S
	var n N

	// Reserve the parent's entire fixed payload BEFORE the nested object
	// is started — identical to [WriteList]'s ReserveFixed. Without it,
	// the nested StartObject would align and begin writing on top of the
	// parent's not-yet-written pointer field at byteOffset.
	ob.ReserveFixed(sParent.Size())

	nob := b.StartObject(n.Size())
	init(Setter[N]{ob: nob, b: b})
	pos := nob.Finish()
	ob.SetObject(int(byteOffset), pos)
}
