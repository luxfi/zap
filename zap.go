// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zap implements the Zero-copy Application Protocol (ZAP) for Lux.
//
// ZAP is a binary serialization format designed for high-performance
// inter-process and network communication. Like Cap'n Proto and FlatBuffers,
// ZAP enables zero-copy reads - data can be accessed directly from the
// underlying byte buffer without parsing or allocation.
//
// Wire Format:
//
//	┌─────────────────────────────────────────────────┐
//	│ Header (16 bytes)                               │
//	│  ├─ Magic (4 bytes): "ZAP\x00"                  │
//	│  ├─ Version (2 bytes): 1                        │
//	│  ├─ Flags (2 bytes): compression, etc.          │
//	│  ├─ Root Offset (4 bytes): offset to root       │
//	│  └─ Size (4 bytes): total message size          │
//	├─────────────────────────────────────────────────┤
//	│ Data Segment (variable)                         │
//	│  └─ Structs, lists, text, bytes...             │
//	└─────────────────────────────────────────────────┘
//
// All multi-byte integers are little-endian. Offsets are relative to
// the position of the offset field itself.
package zap

import (
	"encoding/binary"
	"errors"
	"math"
	"unsafe"
)

const (
	// HeaderSize is the size of the ZAP message header
	HeaderSize = 16

	// Magic bytes identifying a ZAP message
	Magic = "ZAP\x00"

	// Version of the ZAP format
	Version = 1

	// Alignment for data segments
	Alignment = 8
)

// Flags for message header
const (
	FlagNone       uint16 = 0
	FlagCompressed uint16 = 1 << 0
	FlagEncrypted  uint16 = 1 << 1
	FlagSigned     uint16 = 1 << 2
)

var (
	ErrInvalidMagic   = errors.New("zap: invalid magic bytes")
	ErrInvalidVersion = errors.New("zap: unsupported version")
	ErrBufferTooSmall = errors.New("zap: buffer too small")
	ErrOutOfBounds    = errors.New("zap: offset out of bounds")
	ErrInvalidOffset  = errors.New("zap: invalid offset")
)

// Message is a ZAP message that can be read zero-copy.
type Message struct {
	data []byte
}

// Parse parses a ZAP message from bytes without copying.
func Parse(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrBufferTooSmall
	}

	// Check magic
	if string(data[0:4]) != Magic {
		return nil, ErrInvalidMagic
	}

	// Check version
	version := binary.LittleEndian.Uint16(data[4:6])
	if version != Version {
		return nil, ErrInvalidVersion
	}

	// Validate size
	size := binary.LittleEndian.Uint32(data[12:16])
	if int(size) > len(data) {
		return nil, ErrBufferTooSmall
	}

	return &Message{data: data[:size]}, nil
}

// Bytes returns the underlying byte slice.
func (m *Message) Bytes() []byte {
	return m.data
}

// Size returns the total message size.
func (m *Message) Size() int {
	return len(m.data)
}

// Flags returns the message flags.
func (m *Message) Flags() uint16 {
	return binary.LittleEndian.Uint16(m.data[6:8])
}

// Root returns the root object of the message.
func (m *Message) Root() Object {
	offset := binary.LittleEndian.Uint32(m.data[8:12])
	return Object{msg: m, offset: int(offset)}
}

// Object is a zero-copy view into a ZAP struct.
type Object struct {
	msg    *Message
	offset int
}

// IsNull returns true if the object is null.
func (o Object) IsNull() bool {
	return o.offset == 0
}

// Bool reads a bool at the given field offset.
func (o Object) Bool(fieldOffset int) bool {
	return o.Uint8(fieldOffset) != 0
}

// Uint8 reads a uint8 at the given field offset.
func (o Object) Uint8(fieldOffset int) uint8 {
	pos := o.offset + fieldOffset
	if pos >= len(o.msg.data) {
		return 0
	}
	return o.msg.data[pos]
}

// Uint16 reads a uint16 at the given field offset.
func (o Object) Uint16(fieldOffset int) uint16 {
	pos := o.offset + fieldOffset
	if pos+2 > len(o.msg.data) {
		return 0
	}
	return binary.LittleEndian.Uint16(o.msg.data[pos:])
}

// Uint32 reads a uint32 at the given field offset.
func (o Object) Uint32(fieldOffset int) uint32 {
	pos := o.offset + fieldOffset
	if pos+4 > len(o.msg.data) {
		return 0
	}
	return binary.LittleEndian.Uint32(o.msg.data[pos:])
}

// Uint64 reads a uint64 at the given field offset.
func (o Object) Uint64(fieldOffset int) uint64 {
	pos := o.offset + fieldOffset
	if pos+8 > len(o.msg.data) {
		return 0
	}
	return binary.LittleEndian.Uint64(o.msg.data[pos:])
}

// Int8 reads an int8 at the given field offset.
func (o Object) Int8(fieldOffset int) int8 {
	return int8(o.Uint8(fieldOffset))
}

// Int16 reads an int16 at the given field offset.
func (o Object) Int16(fieldOffset int) int16 {
	return int16(o.Uint16(fieldOffset))
}

// Int32 reads an int32 at the given field offset.
func (o Object) Int32(fieldOffset int) int32 {
	return int32(o.Uint32(fieldOffset))
}

// Int64 reads an int64 at the given field offset.
func (o Object) Int64(fieldOffset int) int64 {
	return int64(o.Uint64(fieldOffset))
}

// Float32 reads a float32 at the given field offset.
func (o Object) Float32(fieldOffset int) float32 {
	return math.Float32frombits(o.Uint32(fieldOffset))
}

// Float64 reads a float64 at the given field offset.
func (o Object) Float64(fieldOffset int) float64 {
	return math.Float64frombits(o.Uint64(fieldOffset))
}

// Text reads a string at the given field offset (zero-copy).
func (o Object) Text(fieldOffset int) string {
	b := o.Bytes(fieldOffset)
	if len(b) == 0 {
		return ""
	}
	// Zero-copy string conversion
	return unsafe.String(&b[0], len(b))
}

// Bytes reads a byte slice at the given field offset (zero-copy).
func (o Object) Bytes(fieldOffset int) []byte {
	pos := o.offset + fieldOffset
	if pos+4 > len(o.msg.data) {
		return nil
	}

	// Read offset (relative) and length
	relOffset := int32(binary.LittleEndian.Uint32(o.msg.data[pos:]))
	if relOffset == 0 {
		return nil // Null
	}

	lenPos := pos + 4
	if lenPos+4 > len(o.msg.data) {
		return nil
	}
	length := binary.LittleEndian.Uint32(o.msg.data[lenPos:])

	// Calculate absolute position
	absPos := pos + int(relOffset)
	if absPos < 0 || absPos+int(length) > len(o.msg.data) {
		return nil
	}

	return o.msg.data[absPos : absPos+int(length)]
}

// Object reads a nested object at the given field offset.
func (o Object) Object(fieldOffset int) Object {
	pos := o.offset + fieldOffset
	if pos+4 > len(o.msg.data) {
		return Object{}
	}

	relOffset := int32(binary.LittleEndian.Uint32(o.msg.data[pos:]))
	if relOffset == 0 {
		return Object{} // Null
	}

	absOffset := pos + int(relOffset)
	if absOffset < 0 || absOffset >= len(o.msg.data) {
		return Object{}
	}

	return Object{msg: o.msg, offset: absOffset}
}

// List reads a list at the given field offset.
func (o Object) List(fieldOffset int) List {
	pos := o.offset + fieldOffset
	if pos+8 > len(o.msg.data) {
		return List{}
	}

	relOffset := int32(binary.LittleEndian.Uint32(o.msg.data[pos:]))
	if relOffset == 0 {
		return List{} // Null
	}

	length := binary.LittleEndian.Uint32(o.msg.data[pos+4:])
	absOffset := pos + int(relOffset)

	if absOffset < 0 || absOffset >= len(o.msg.data) {
		return List{}
	}

	return List{msg: o.msg, offset: absOffset, length: int(length)}
}

// List is a zero-copy view into a ZAP list.
type List struct {
	msg    *Message
	offset int
	length int
}

// Len returns the number of elements.
func (l List) Len() int {
	return l.length
}

// IsNull returns true if the list is null.
func (l List) IsNull() bool {
	return l.msg == nil
}

// Uint8 returns a uint8 list element.
func (l List) Uint8(i int) uint8 {
	if i < 0 || i >= l.length {
		return 0
	}
	pos := l.offset + i
	if pos >= len(l.msg.data) {
		return 0
	}
	return l.msg.data[pos]
}

// Uint32 returns a uint32 list element.
func (l List) Uint32(i int) uint32 {
	if i < 0 || i >= l.length {
		return 0
	}
	pos := l.offset + i*4
	if pos+4 > len(l.msg.data) {
		return 0
	}
	return binary.LittleEndian.Uint32(l.msg.data[pos:])
}

// Uint64 returns a uint64 list element.
func (l List) Uint64(i int) uint64 {
	if i < 0 || i >= l.length {
		return 0
	}
	pos := l.offset + i*8
	if pos+8 > len(l.msg.data) {
		return 0
	}
	return binary.LittleEndian.Uint64(l.msg.data[pos:])
}

// Object returns an object list element.
func (l List) Object(i int, elemSize int) Object {
	if i < 0 || i >= l.length {
		return Object{}
	}
	return Object{msg: l.msg, offset: l.offset + i*elemSize}
}

// Bytes returns the raw bytes of the list (for byte lists).
func (l List) Bytes() []byte {
	if l.msg == nil || l.offset+l.length > len(l.msg.data) {
		return nil
	}
	return l.msg.data[l.offset : l.offset+l.length]
}
