// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zap implements the Zero-copy Application Protocol (ZAP) for Lux.
//
// ZAP is a binary serialization format designed for high-performance
// inter-process and network communication. Like Cap'n Proto and FlatBuffers,
// ZAP enables zero-copy reads - data can be accessed directly from the
// underlying byte buffer without parsing or allocation.
//
// Transport security: set NodeConfig.TLS to a *tls.Config to wrap all
// TCP connections with TLS. This supports PQ-TLS 1.3 when the Go runtime
// and configured cipher suites provide post-quantum key exchange (e.g.
// X25519Kyber768). When TLS is nil (the default), connections are plaintext.
//
// Wire Format:
//
//	┌─────────────────────────────────────────────────┐
//	│ Header (16 bytes)                               │
//	│  ├─ Magic (4 bytes): "ZAP\x00"                  │
//	│  ├─ Version (2 bytes): 1 (legacy) or 2 (current)│
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

	// Version of the ZAP wire format. Two schemas are defined:
	//
	//   Version1 — legacy v2 platformvm schema (NetworkID at byte 0, no TxKind
	//              discriminator). Accepted at Parse for backward compatibility,
	//              but new builders emit Version2 by default.
	//
	//   Version2 — v3 platformvm schema (TxKind discriminator at byte 0, all
	//              other fields shifted by +1). This is what every Wrap*Tx in
	//              luxfi/node/vms/platformvm/txs/zap_native expects.
	//
	// Version (the bare constant) is the CURRENT wire version emitted by
	// NewBuilder. It tracks Version2; Version1 is preserved only for legacy
	// parse and explicit-opt-in builds via NewBuilderV1.
	//
	// RED-MEDIUM-1 (LP-023 v3.1 round 2): a v2-shaped BaseTx with NetworkID=11
	// has byte 0 == 0x0B == TxKindBaseFull. Wrap*Tx on a v1-header v2-schema
	// buffer with this collision would PASS the discriminator check and
	// misinterpret the rest of the buffer. Reject at the schema-version gate
	// in every Wrap*Tx (callers should require Version2).
	Version1 uint16 = 1
	Version2 uint16 = 2
	Version  uint16 = Version2

	// DefaultPort is the canonical TCP port for ZAP transport across the
	// Lux ecosystem. Like 80 means HTTP and 443 means HTTPS, 9999 means
	// ZAP — every ZAP-hosting service binds this port; the DNS name (e.g.
	// zap.kms.svc, zap.mpc.svc) disambiguates which service is on the
	// other end.
	DefaultPort = 9999

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
//
// Accepts both Version1 and Version2 wire headers (forward-compatible read).
// Callers that require Version2 semantics (e.g. v3 platformvm schema) must
// gate on Message.Version() after Parse.
//
// RED-V18 (LP-023 v3.1 round 2): the declared size field must be at least
// HeaderSize. A buffer with size=0 used to pass Parse and then panic on
// subsequent Root()/Flags() reads against an empty slice. Now rejected at
// the wire boundary.
func Parse(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrBufferTooSmall
	}

	// Check magic
	if string(data[0:4]) != Magic {
		return nil, ErrInvalidMagic
	}

	// Check version (accept legacy v1 + current v2; reject anything else).
	version := binary.LittleEndian.Uint16(data[4:6])
	if version != Version1 && version != Version2 {
		return nil, ErrInvalidVersion
	}

	// Validate size: must be at least the header (else Root()/Flags() would
	// panic on data[:size]) and at most the input length.
	size := binary.LittleEndian.Uint32(data[12:16])
	if int(size) < HeaderSize || int(size) > len(data) {
		return nil, ErrBufferTooSmall
	}

	return &Message{data: data[:size]}, nil
}

// Version returns the wire version of the message (Version1 or Version2).
// Wrap*Tx accessors in luxfi/node/vms/platformvm/txs/zap_native gate on
// Version2 to reject v1-vs-v2 cross-schema confusion (RED-MEDIUM-1).
func (m *Message) Version() uint16 {
	return binary.LittleEndian.Uint16(m.data[4:6])
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
//
// Wire-format rule: relOffset is an UNSIGNED forward pointer from the field
// position into the variable-section. Negative bit-patterns (high bit set)
// flow through uint32→int conversion as large positive values and are
// rejected by the absPos+length > len(data) bounds check. This closes the
// memo-pointer-escape malleability surface where a signed cast would let a
// crafted relOffset alias bytes back inside the fixed section.
func (o Object) Bytes(fieldOffset int) []byte {
	pos := o.offset + fieldOffset
	if pos+4 > len(o.msg.data) {
		return nil
	}

	// Read offset (relative, unsigned forward pointer) and length.
	relOffset := binary.LittleEndian.Uint32(o.msg.data[pos:])
	if relOffset == 0 {
		return nil // Null
	}

	lenPos := pos + 4
	if lenPos+4 > len(o.msg.data) {
		return nil
	}
	length := binary.LittleEndian.Uint32(o.msg.data[lenPos:])

	// Calculate absolute position. uint32 + int may not overflow on 64-bit
	// (Lux is 64-bit only); the bounds check below catches values past EOF.
	// RED-HIGH-2 (mirror): reject any payload that lands inside the wire
	// header — Bytes targets cannot live in offsets 0..HeaderSize-1.
	absPos := pos + int(relOffset)
	if absPos < HeaderSize {
		return nil
	}
	if absPos+int(length) > len(o.msg.data) {
		return nil
	}

	return o.msg.data[absPos : absPos+int(length)]
}

// Object reads a nested object at the given field offset.
//
// Wire-format rule: relOffset is SIGNED. The builder may finalize a nested
// object BEFORE its parent (in which case the nested payload lives EARLIER
// in the variable section than the parent's pointer cell, and the
// relOffset is negative). The bounds check below rejects any absOffset
// outside the message; for the Bytes-malleability fix see Bytes().
//
// RED-HIGH-2 (LP-023 v3.1 round 2): an attacker can use a backward
// relOffset to alias the WIRE HEADER (offsets 0..HeaderSize-1). The
// header carries Magic/Version/Flags/RootOffset/Size — none of which is a
// legitimate object payload. We reject any absOffset < HeaderSize. The
// signed-cast still lets honest builders point backward to nested objects
// they finalized first (which live at offset >= HeaderSize).
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
	if absOffset < HeaderSize || absOffset >= len(o.msg.data) {
		return Object{}
	}

	return Object{msg: o.msg, offset: absOffset}
}

// List reads a list at the given field offset.
//
// Wire-format rule: relOffset is SIGNED (see Object()). RED-HIGH-2: any
// absOffset < HeaderSize is rejected (lists cannot start inside the wire
// header). RED-HIGH-1: the length field is bounded by the total message
// size — an attacker-set length=0xFFFFFFFF would otherwise let downstream
// `for i := 0; i < l.Len()` loops iterate 4G times even though every
// per-element accessor would silently return 0.
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

	// RED-HIGH-1: clamp length to the message size. The tightest bound is
	// `length * minElementSize <= msgSize - absOffset`, but element size is
	// per-list-accessor (Uint8 is 1B, Uint32 is 4B, struct lists carry their
	// own stride). The wire layer cannot know the stride, so we use the
	// permissive `length <= len(data)` baseline — any per-element access
	// re-checks bounds in List.Uint{8,16,32,64}/Object/Bytes. This rejects
	// the 0xFFFFFFFF DoS without false-rejecting honest 1-byte-stride lists
	// that span the entire message.
	if int(length) > len(o.msg.data) {
		return List{}
	}

	absOffset := pos + int(relOffset)
	if absOffset < HeaderSize || absOffset >= len(o.msg.data) {
		return List{}
	}

	return List{msg: o.msg, offset: absOffset, length: int(length)}
}

// ListStride is List() with a caller-supplied per-element stride hint. It
// applies the tighter clamp `length * minStride <= len(buffer) - absOffset`
// up front, rejecting attacker-set length=0xFFFFFFFF on multi-byte-stride
// accessors instead of pushing the bounds check to every per-element
// accessor.
//
// Use case: an Uint32 list with stride 4, a struct list with stride 96 — pass
// the stride; the wire layer rejects length values that exceed what the
// remaining buffer can possibly carry. This is a NEW-V1 follow-up (LP-023
// Red round 3) — the bare List() accessor cannot know the stride and uses
// the permissive `length <= len(data)` baseline.
//
// minStride MUST be the BYTE width of one element (1 for uint8, 4 for
// uint32, 8 for uint64, SizeTransferableOutput for OutputList, etc.). When
// minStride <= 0 the call falls back to bare List() semantics.
//
// Wire format is unchanged — same {relOffset, length} pair as List(). The
// clamp is purely a tightened acceptance test; any List() that would
// succeed with minStride=0 succeeds with the correct stride too.
func (o Object) ListStride(fieldOffset int, minStride uint32) List {
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
	if absOffset < HeaderSize || absOffset >= len(o.msg.data) {
		return List{}
	}

	// Tighter clamp using per-element stride: `length * minStride` must fit
	// in the remaining buffer after absOffset. This rejects 0xFFFFFFFF DoS
	// on any stride > 1 immediately, instead of waiting for per-element
	// access bounds checks. Length<=msgsize baseline (RED-HIGH-1) is also
	// applied for stride=0 (or unspecified caller).
	bufRem := uint64(len(o.msg.data) - absOffset)
	if minStride > 0 {
		// uint64 product cannot overflow because both operands are uint32.
		if uint64(length)*uint64(minStride) > bufRem {
			return List{}
		}
	} else if uint64(length) > uint64(len(o.msg.data)) {
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

// Len returns the list element count as encoded on the wire.
//
// SAFETY: callers MUST NOT pre-allocate via make([]T, l.Len()) without an
// independent bound. The wire encoding only constrains length to len(buffer),
// so a 64KB mempool tx can carry Len()=65535 — large enough to OOM if a
// consumer naively pre-allocates. Always iterate List.At(i) with i < Len()
// AND validate each element's invariants before trusting the count.
//
// For tighter per-stride bounds at the wire layer, use Object.ListStride
// (introduced in v0.7.2): it rejects length*minStride > len(buffer) up
// front. This Len() value is the wire-encoded count irrespective of which
// accessor produced the List — Object.List or Object.ListStride.
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
