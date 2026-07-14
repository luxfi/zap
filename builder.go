// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/binary"
	"math"
	"sync"
)

// Builder constructs ZAP messages.
type Builder struct {
	buf        []byte
	pos        int
	rootOffset int
}

// NewBuilder creates a new builder with the given initial capacity. The
// resulting message is emitted with Version2 in the wire header (the
// current default). Use NewBuilderV1 only for legacy v1 emitters; new
// code should always use NewBuilder.
func NewBuilder(capacity int) *Builder {
	return newBuilder(capacity, Version2)
}

// NewBuilderV1 creates a new builder that emits Version1 messages. This is
// kept only for explicit-legacy-emitter call sites (none in tree as of
// LP-023 v3.1 round 2). New code should call NewBuilder.
func NewBuilderV1(capacity int) *Builder {
	return newBuilder(capacity, Version1)
}

func newBuilder(capacity int, version uint16) *Builder {
	if capacity < HeaderSize {
		capacity = 256
	}
	b := &Builder{
		buf: make([]byte, capacity),
		pos: HeaderSize, // Start after header
	}
	// Write magic and version
	copy(b.buf[0:4], Magic)
	binary.LittleEndian.PutUint16(b.buf[4:6], version)
	return b
}

// Reset resets the builder for reuse.
func (b *Builder) Reset() {
	b.pos = HeaderSize
	b.rootOffset = 0
}

// grow ensures capacity for n more bytes.
func (b *Builder) grow(n int) {
	if b.pos+n <= len(b.buf) {
		return
	}
	newCap := len(b.buf) * 2
	if newCap < b.pos+n {
		newCap = b.pos + n
	}
	newBuf := make([]byte, newCap)
	copy(newBuf, b.buf[:b.pos])
	b.buf = newBuf
}

// align aligns the current position to the given boundary.
func (b *Builder) align(alignment int) {
	padding := (alignment - (b.pos % alignment)) % alignment
	b.grow(padding)
	for i := 0; i < padding; i++ {
		b.buf[b.pos] = 0
		b.pos++
	}
}

// Finish finalizes the message and returns the bytes.
func (b *Builder) Finish() []byte {
	// Write root offset
	binary.LittleEndian.PutUint32(b.buf[8:12], uint32(b.rootOffset))
	// Write total size
	binary.LittleEndian.PutUint32(b.buf[12:16], uint32(b.pos))
	return b.buf[:b.pos]
}

// FinishWithFlags finalizes with specific flags.
func (b *Builder) FinishWithFlags(flags uint16) []byte {
	binary.LittleEndian.PutUint16(b.buf[6:8], flags)
	return b.Finish()
}

// ObjectBuilder builds a ZAP object (struct).
type ObjectBuilder struct {
	b        *Builder
	startPos int
	dataSize int
}

// StartObject starts building an object with the given data size, RESERVING the
// full fixed section up front (zero-filled). Reserving eagerly means a variable
// field (SetBytes/SetText) can append its tail data immediately after the fixed
// section and patch its own relative pointer on the spot — there is no deferred
// offset list to record intentions and replay in Finish. Callers already build
// child objects/lists BEFORE StartObject (the writeXxxList-then-StartObject
// pattern), so the object's own Set* calls are the only buffer writes between
// StartObject and Finish; appending tail bytes immediately is safe and produces
// byte-identical wire.
func (b *Builder) StartObject(dataSize int) ObjectBuilder {
	b.align(Alignment)
	ob := ObjectBuilder{
		b:        b,
		startPos: b.pos,
		dataSize: dataSize,
	}
	ob.ensureField(dataSize)
	return ob
}

// SetBool sets a bool field.
func (ob ObjectBuilder) SetBool(fieldOffset int, v bool) {
	if v {
		ob.SetUint8(fieldOffset, 1)
	} else {
		ob.SetUint8(fieldOffset, 0)
	}
}

// SetUint8 sets a uint8 field.
func (ob ObjectBuilder) SetUint8(fieldOffset int, v uint8) {
	ob.ensureField(fieldOffset + 1)
	ob.b.buf[ob.startPos+fieldOffset] = v
}

// SetUint16 sets a uint16 field.
func (ob ObjectBuilder) SetUint16(fieldOffset int, v uint16) {
	ob.ensureField(fieldOffset + 2)
	binary.LittleEndian.PutUint16(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetUint32 sets a uint32 field.
func (ob ObjectBuilder) SetUint32(fieldOffset int, v uint32) {
	ob.ensureField(fieldOffset + 4)
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetUint64 sets a uint64 field.
func (ob ObjectBuilder) SetUint64(fieldOffset int, v uint64) {
	ob.ensureField(fieldOffset + 8)
	binary.LittleEndian.PutUint64(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetInt8 sets an int8 field.
func (ob ObjectBuilder) SetInt8(fieldOffset int, v int8) {
	ob.SetUint8(fieldOffset, uint8(v))
}

// SetInt16 sets an int16 field.
func (ob ObjectBuilder) SetInt16(fieldOffset int, v int16) {
	ob.SetUint16(fieldOffset, uint16(v))
}

// SetInt32 sets an int32 field.
func (ob ObjectBuilder) SetInt32(fieldOffset int, v int32) {
	ob.SetUint32(fieldOffset, uint32(v))
}

// SetInt64 sets an int64 field.
func (ob ObjectBuilder) SetInt64(fieldOffset int, v int64) {
	ob.SetUint64(fieldOffset, uint64(v))
}

// SetFloat32 sets a float32 field.
func (ob ObjectBuilder) SetFloat32(fieldOffset int, v float32) {
	ob.SetUint32(fieldOffset, float32bits(v))
}

// SetFloat64 sets a float64 field.
func (ob ObjectBuilder) SetFloat64(fieldOffset int, v float64) {
	ob.SetUint64(fieldOffset, float64bits(v))
}

// SetBytesFixed copies len(v) bytes inline at fieldOffset within the
// object's fixed payload. This is the generic-width counterpart of
// SetHash (32 bytes) and SetAddress (20 bytes); it covers any N>0
// inline byte-array slot (e.g., LP-201 SessionID [16]byte, LP-208
// QuasarWitness [96]byte).
//
// Unlike SetBytes (which writes a variable-length tail pointer
// {relOffset uint32, length uint32}), SetBytesFixed writes the bytes
// IN PLACE in the fixed payload. Use this when the schema declares a
// fixed-width byte field; use SetBytes when the schema declares a
// variable-length tail.
//
// Panics on len(v) == 0 are avoided: a zero-length argument is a
// no-op (the slot is left as the zero value).
func (ob ObjectBuilder) SetBytesFixed(fieldOffset int, v []byte) {
	if len(v) == 0 {
		return
	}
	ob.ensureField(fieldOffset + len(v))
	copy(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetText sets a text (string) field.
func (ob ObjectBuilder) SetText(fieldOffset int, v string) {
	ob.SetBytes(fieldOffset, []byte(v))
}

// SetBytes sets a bytes field.
// The data is written after the object's fixed section during Finish().
func (ob ObjectBuilder) SetBytes(fieldOffset int, v []byte) {
	if len(v) == 0 {
		// Null pointer (offset 0, length 0).
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], 0)
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset+4:], 0)
		return
	}
	// The fixed section is fully reserved by StartObject, so b.pos is at the
	// tail: append the data now and patch this field's (relOffset, length) pair
	// immediately — no deferred offset list, no per-object slice allocation.
	dataPos := ob.b.pos
	ob.b.grow(len(v))
	copy(ob.b.buf[ob.b.pos:ob.b.pos+len(v)], v)
	ob.b.pos += len(v)

	fieldAbsPos := ob.startPos + fieldOffset
	relOffset := int32(dataPos - fieldAbsPos)
	binary.LittleEndian.PutUint32(ob.b.buf[fieldAbsPos:], uint32(relOffset))
	binary.LittleEndian.PutUint32(ob.b.buf[fieldAbsPos+4:], uint32(len(v)))
}

// SetObject sets a nested object field (by offset).
func (ob ObjectBuilder) SetObject(fieldOffset int, objOffset int) {
	ob.ensureField(fieldOffset + 4)

	if objOffset == 0 {
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], 0)
		return
	}

	// Calculate relative offset from field position
	relOffset := objOffset - (ob.startPos + fieldOffset)
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], uint32(relOffset))
}

// SetList sets a list field.
func (ob ObjectBuilder) SetList(fieldOffset int, listOffset int, length int) {
	ob.ensureField(fieldOffset + 8)

	if listOffset == 0 || length == 0 {
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], 0)
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset+4:], 0)
		return
	}

	relOffset := listOffset - (ob.startPos + fieldOffset)
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], uint32(relOffset))
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset+4:], uint32(length))
}

func (ob ObjectBuilder) ensureField(endOffset int) {
	needed := ob.startPos + endOffset
	if needed > ob.b.pos {
		ob.b.grow(needed - ob.b.pos)
		// Zero-fill
		for i := ob.b.pos; i < needed; i++ {
			ob.b.buf[i] = 0
		}
		ob.b.pos = needed
	}
}

// ReserveFixed extends the builder's write cursor so the object's
// entire fixed payload of dataSize bytes is materialized (zero-filled
// up to startPos+dataSize). Use this BEFORE writing any variable-
// length tail (list elements, deferred bytes) that should live AFTER
// the fixed section.
//
// Without this call, list elements or deferred-data writes interleave
// with the unreserved tail of the fixed section, producing incorrect
// wire bytes when later Set* calls patch fields that overlap with
// already-written variable data.
//
// Idempotent: a second call with the same dataSize is a no-op. A call
// with a smaller dataSize is also a no-op (the cursor never moves
// backwards).
//
// This is the exported counterpart to the internal ensureField helper.
// It is used by zapv1.WriteList to keep the parent's payload reserved
// before list elements are appended.
func (ob ObjectBuilder) ReserveFixed(dataSize int) {
	ob.ensureField(dataSize)
}

// Finish finalizes the object and returns its offset. Every field (fixed and
// variable) is written eagerly by its Set* call — the fixed section is reserved
// in StartObject and SetBytes/SetText append their tail immediately — so there
// is nothing to replay here.
func (ob ObjectBuilder) Finish() int {
	return ob.startPos
}

// FinishAsRoot finalizes and sets as the message root.
func (ob ObjectBuilder) FinishAsRoot() int {
	offset := ob.Finish()
	ob.b.rootOffset = offset
	return offset
}

// WriteBytes writes raw bytes and returns the offset.
func (b *Builder) WriteBytes(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	b.align(Alignment)
	offset := b.pos
	b.grow(len(data))
	copy(b.buf[b.pos:], data)
	b.pos += len(data)
	return offset
}

// WriteText writes a string and returns the offset.
func (b *Builder) WriteText(s string) int {
	return b.WriteBytes([]byte(s))
}

// ListBuilder builds a ZAP list.
type ListBuilder struct {
	b        *Builder
	startPos int
	count    int
}

// StartList starts building a list. Returns a VALUE (not a heap pointer): the
// Add*/Finish methods take pointer receivers, and every caller binds the result
// to an addressable local (`lb := b.StartList(...)`), so Go auto-addresses the
// local and count mutations accumulate on it — no per-list heap allocation.
// Mirrors the value-typed StartObject. elemSize is unused (the stride is
// implicit in which Add* the caller invokes) and kept only as a documenting
// param.
func (b *Builder) StartList(elemSize int) ListBuilder {
	_ = elemSize
	b.align(Alignment)
	return ListBuilder{
		b:        b,
		startPos: b.pos,
	}
}

// AddUint8 adds a uint8 element.
func (lb *ListBuilder) AddUint8(v uint8) {
	lb.b.grow(1)
	lb.b.buf[lb.b.pos] = v
	lb.b.pos++
	lb.count++
}

// AddUint32 adds a uint32 element.
func (lb *ListBuilder) AddUint32(v uint32) {
	lb.b.grow(4)
	binary.LittleEndian.PutUint32(lb.b.buf[lb.b.pos:], v)
	lb.b.pos += 4
	lb.count++
}

// AddUint64 adds a uint64 element.
func (lb *ListBuilder) AddUint64(v uint64) {
	lb.b.grow(8)
	binary.LittleEndian.PutUint64(lb.b.buf[lb.b.pos:], v)
	lb.b.pos += 8
	lb.count++
}

// AddBytes adds raw bytes (for byte lists).
func (lb *ListBuilder) AddBytes(data []byte) {
	lb.b.grow(len(data))
	copy(lb.b.buf[lb.b.pos:], data)
	lb.b.pos += len(data)
	lb.count += len(data)
}

// AddObjectPtr appends a 4-byte SIGNED relative pointer to an object at
// absolute position targetPos (pass 0 for a null element). This is the
// element kind for a list of out-of-line objects — the wire encoding of a
// "repeated message" field, where each fixed-stride slot points to a tailed
// object elsewhere in the buffer rather than inlining a fixed-size value.
//
// The relative offset is computed against THIS slot's position, so the
// reader resolves it the same way [Object.Object] does: absOffset = slotPos
// + int32(rel). Targets may precede the slot (negative rel) — the common
// case, since a builder writes the objects first and the pointer array
// after.
func (lb *ListBuilder) AddObjectPtr(targetPos int) {
	lb.b.grow(4)
	if targetPos == 0 {
		binary.LittleEndian.PutUint32(lb.b.buf[lb.b.pos:], 0)
	} else {
		rel := int32(targetPos - lb.b.pos)
		binary.LittleEndian.PutUint32(lb.b.buf[lb.b.pos:], uint32(rel))
	}
	lb.b.pos += 4
	lb.count++
}

// Finish returns the list offset and length.
func (lb *ListBuilder) Finish() (offset int, length int) {
	return lb.startPos, lb.count
}

// ---- Builder pool (write-side counterpart to the read bufpool) ----

// builderPool recycles Builders across messages. A pooled Builder keeps its
// grown backing array, so steady-state message construction allocates zero
// builder buffers. Byte-safety on reuse is unconditional: ensureField
// zero-fills every extended span and align zero-fills padding, so a reused
// (dirty) buffer emits bytes identical to a fresh one.
var builderPool = sync.Pool{
	New: func() any { return NewBuilder(512) },
}

// GetBuilder returns a pooled Builder, reset and ready to write a Version2
// message. Callers MUST copy out the bytes returned by Finish (which aliases
// the Builder's buffer) before calling PutBuilder.
func GetBuilder() *Builder {
	b := builderPool.Get().(*Builder)
	b.Reset()
	return b
}

// PutBuilder returns a Builder to the pool. The slice previously returned by
// b.Finish() must no longer be referenced (it aliases b's buffer).
func PutBuilder(b *Builder) {
	builderPool.Put(b)
}

// Helper functions

func float32bits(f float32) uint32 {
	return math.Float32bits(f)
}

func float64bits(f float64) uint64 {
	return math.Float64bits(f)
}
