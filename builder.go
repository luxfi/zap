// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/binary"
	"math"
)

// Builder constructs ZAP messages.
type Builder struct {
	buf        []byte
	pos        int
	rootOffset int
}

// NewBuilder creates a new builder with the given initial capacity.
func NewBuilder(capacity int) *Builder {
	if capacity < HeaderSize {
		capacity = 256
	}
	b := &Builder{
		buf: make([]byte, capacity),
		pos: HeaderSize, // Start after header
	}
	// Write magic and version
	copy(b.buf[0:4], Magic)
	binary.LittleEndian.PutUint16(b.buf[4:6], Version)
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
	b          *Builder
	startPos   int
	dataSize   int
	offsets    []offsetEntry
}

type offsetEntry struct {
	fieldOffset int
	targetPos   int    // positive = known position, negative = deferred write
	data        []byte // actual bytes to write (deferred text/bytes)
}

// StartObject starts building an object with the given data size.
func (b *Builder) StartObject(dataSize int) *ObjectBuilder {
	b.align(Alignment)
	return &ObjectBuilder{
		b:        b,
		startPos: b.pos,
		dataSize: dataSize,
	}
}

// SetBool sets a bool field.
func (ob *ObjectBuilder) SetBool(fieldOffset int, v bool) {
	if v {
		ob.SetUint8(fieldOffset, 1)
	} else {
		ob.SetUint8(fieldOffset, 0)
	}
}

// SetUint8 sets a uint8 field.
func (ob *ObjectBuilder) SetUint8(fieldOffset int, v uint8) {
	ob.ensureField(fieldOffset + 1)
	ob.b.buf[ob.startPos+fieldOffset] = v
}

// SetUint16 sets a uint16 field.
func (ob *ObjectBuilder) SetUint16(fieldOffset int, v uint16) {
	ob.ensureField(fieldOffset + 2)
	binary.LittleEndian.PutUint16(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetUint32 sets a uint32 field.
func (ob *ObjectBuilder) SetUint32(fieldOffset int, v uint32) {
	ob.ensureField(fieldOffset + 4)
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetUint64 sets a uint64 field.
func (ob *ObjectBuilder) SetUint64(fieldOffset int, v uint64) {
	ob.ensureField(fieldOffset + 8)
	binary.LittleEndian.PutUint64(ob.b.buf[ob.startPos+fieldOffset:], v)
}

// SetInt8 sets an int8 field.
func (ob *ObjectBuilder) SetInt8(fieldOffset int, v int8) {
	ob.SetUint8(fieldOffset, uint8(v))
}

// SetInt16 sets an int16 field.
func (ob *ObjectBuilder) SetInt16(fieldOffset int, v int16) {
	ob.SetUint16(fieldOffset, uint16(v))
}

// SetInt32 sets an int32 field.
func (ob *ObjectBuilder) SetInt32(fieldOffset int, v int32) {
	ob.SetUint32(fieldOffset, uint32(v))
}

// SetInt64 sets an int64 field.
func (ob *ObjectBuilder) SetInt64(fieldOffset int, v int64) {
	ob.SetUint64(fieldOffset, uint64(v))
}

// SetFloat32 sets a float32 field.
func (ob *ObjectBuilder) SetFloat32(fieldOffset int, v float32) {
	ob.SetUint32(fieldOffset, float32bits(v))
}

// SetFloat64 sets a float64 field.
func (ob *ObjectBuilder) SetFloat64(fieldOffset int, v float64) {
	ob.SetUint64(fieldOffset, float64bits(v))
}

// SetText sets a text (string) field.
func (ob *ObjectBuilder) SetText(fieldOffset int, v string) {
	ob.SetBytes(fieldOffset, []byte(v))
}

// SetBytes sets a bytes field.
// The data is written after the object's fixed section during Finish().
func (ob *ObjectBuilder) SetBytes(fieldOffset int, v []byte) {
	ob.ensureField(fieldOffset + 8) // offset + length

	if len(v) == 0 {
		// Null pointer
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset:], 0)
		binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset+4:], 0)
		return
	}

	// Store the data and length; the relative offset is patched in Finish()
	ob.offsets = append(ob.offsets, offsetEntry{
		fieldOffset: fieldOffset,
		data:        append([]byte(nil), v...), // copy the data
	})

	// Write the length now
	binary.LittleEndian.PutUint32(ob.b.buf[ob.startPos+fieldOffset+4:], uint32(len(v)))
}

// SetObject sets a nested object field (by offset).
func (ob *ObjectBuilder) SetObject(fieldOffset int, objOffset int) {
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
func (ob *ObjectBuilder) SetList(fieldOffset int, listOffset int, length int) {
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

func (ob *ObjectBuilder) ensureField(endOffset int) {
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

// Finish finalizes the object and returns its offset.
// Writes deferred text/bytes data after the object's fixed section
// and patches relative offsets.
func (ob *ObjectBuilder) Finish() int {
	// Ensure minimum size for fixed fields
	ob.ensureField(ob.dataSize)

	// Write deferred text/bytes data and patch relative offsets
	for _, entry := range ob.offsets {
		if entry.data == nil {
			continue
		}
		// Write the data at current position (after fixed section)
		dataPos := ob.b.pos
		ob.b.grow(len(entry.data))
		copy(ob.b.buf[ob.b.pos:ob.b.pos+len(entry.data)], entry.data)
		ob.b.pos += len(entry.data)

		// Patch the relative offset: relOffset = dataPos - fieldAbsPos
		fieldAbsPos := ob.startPos + entry.fieldOffset
		relOffset := int32(dataPos - fieldAbsPos)
		binary.LittleEndian.PutUint32(ob.b.buf[fieldAbsPos:], uint32(relOffset))
	}

	return ob.startPos
}

// FinishAsRoot finalizes and sets as the message root.
func (ob *ObjectBuilder) FinishAsRoot() int {
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
	elemSize int
	count    int
}

// StartList starts building a list.
func (b *Builder) StartList(elemSize int) *ListBuilder {
	b.align(Alignment)
	return &ListBuilder{
		b:        b,
		startPos: b.pos,
		elemSize: elemSize,
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

// Finish returns the list offset and length.
func (lb *ListBuilder) Finish() (offset int, length int) {
	return lb.startPos, lb.count
}

// Helper functions

func float32bits(f float32) uint32 {
	return math.Float32bits(f)
}

func float64bits(f float64) uint64 {
	return math.Float64bits(f)
}
