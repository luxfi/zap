// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapcodec

import (
	"encoding/binary"
	"errors"
	"math"
)

// Packing constants (mirror wrappers.ByteLen et al., kept local so this
// package has no runtime dependency on wrappers — the codec.Manager that
// owns this codec passes raw byte slices in and out).
const (
	byteLen  = 1
	shortLen = 2
	intLen   = 4
	longLen  = 8
	boolLen  = 1

	// maxStringLen is the upper bound for a single string value. Mirrors
	// the linearcodec MaxStringLen so cross-codec data carrying strings
	// keeps the same envelope.
	maxStringLen = math.MaxUint16
)

var (
	// ErrInsufficientLength indicates the packer ran out of room (either
	// growing past MaxSize on write, or reading past the buffer on read).
	ErrInsufficientLength = errors.New("zapcodec: packer has insufficient length")

	// errNegativeOffset indicates the caller drove the packer offset
	// negative — defensive guard, should never fire on honest input.
	errNegativeOffset = errors.New("zapcodec: negative offset")

	// errInvalidInput indicates a structurally malformed input (e.g. a
	// boolean byte that's neither 0 nor 1).
	errInvalidInput = errors.New("zapcodec: input does not match expected format")

	// errBadBool indicates a malformed bool tag byte.
	errBadBool = errors.New("zapcodec: unexpected value when unpacking bool")

	// errOversized indicates a length-prefixed value exceeded the
	// caller-supplied limit.
	errOversized = errors.New("zapcodec: size is larger than limit")
)

// packer is the zapcodec little-endian byte packer. Same surface as
// wrappers.Packer but emits/parses LE instead of BE. The point of going
// LE is that x86_64 and arm64 are little-endian by hardware, so the LE
// path emits raw MOV instructions where the BE path emits MOV+BSWAP.
// On the marshal hot path this is the dominant per-field cost.
//
// packer is intentionally NOT exported. Callers that want to marshal a
// type at the zapcodec wire format go through Codec.Marshal /
// Codec.Unmarshal on a codec.Manager registered via NewDefault().
type packer struct {
	err error

	maxSize int
	bytes   []byte
	offset  int
}

func (p *packer) addErr(e error) {
	if p.err == nil {
		p.err = e
	}
}

func (p *packer) errored() bool { return p.err != nil }

// PackByte appends a byte.
func (p *packer) PackByte(v byte) {
	p.expand(byteLen)
	if p.errored() {
		return
	}
	p.bytes[p.offset] = v
	p.offset++
}

// UnpackByte reads a byte.
func (p *packer) UnpackByte() byte {
	p.checkSpace(byteLen)
	if p.errored() {
		return 0
	}
	v := p.bytes[p.offset]
	p.offset++
	return v
}

// PackShort appends a uint16 in little-endian.
func (p *packer) PackShort(v uint16) {
	p.expand(shortLen)
	if p.errored() {
		return
	}
	binary.LittleEndian.PutUint16(p.bytes[p.offset:], v)
	p.offset += shortLen
}

// UnpackShort reads a uint16 in little-endian.
func (p *packer) UnpackShort() uint16 {
	p.checkSpace(shortLen)
	if p.errored() {
		return 0
	}
	v := binary.LittleEndian.Uint16(p.bytes[p.offset:])
	p.offset += shortLen
	return v
}

// PackInt appends a uint32 in little-endian.
func (p *packer) PackInt(v uint32) {
	p.expand(intLen)
	if p.errored() {
		return
	}
	binary.LittleEndian.PutUint32(p.bytes[p.offset:], v)
	p.offset += intLen
}

// UnpackInt reads a uint32 in little-endian.
func (p *packer) UnpackInt() uint32 {
	p.checkSpace(intLen)
	if p.errored() {
		return 0
	}
	v := binary.LittleEndian.Uint32(p.bytes[p.offset:])
	p.offset += intLen
	return v
}

// PackLong appends a uint64 in little-endian.
func (p *packer) PackLong(v uint64) {
	p.expand(longLen)
	if p.errored() {
		return
	}
	binary.LittleEndian.PutUint64(p.bytes[p.offset:], v)
	p.offset += longLen
}

// UnpackLong reads a uint64 in little-endian.
func (p *packer) UnpackLong() uint64 {
	p.checkSpace(longLen)
	if p.errored() {
		return 0
	}
	v := binary.LittleEndian.Uint64(p.bytes[p.offset:])
	p.offset += longLen
	return v
}

// PackBool appends a bool as a single byte.
func (p *packer) PackBool(b bool) {
	if b {
		p.PackByte(1)
	} else {
		p.PackByte(0)
	}
}

// UnpackBool reads a bool. Rejects any tag byte not in {0,1}.
func (p *packer) UnpackBool() bool {
	b := p.UnpackByte()
	switch b {
	case 0:
		return false
	case 1:
		return true
	default:
		p.addErr(errBadBool)
		return false
	}
}

// PackFixedBytes appends raw bytes (no length prefix).
func (p *packer) PackFixedBytes(b []byte) {
	p.expand(len(b))
	if p.errored() {
		return
	}
	copy(p.bytes[p.offset:], b)
	p.offset += len(b)
}

// UnpackFixedBytes reads n raw bytes (no length prefix).
func (p *packer) UnpackFixedBytes(n int) []byte {
	p.checkSpace(n)
	if p.errored() {
		return nil
	}
	b := p.bytes[p.offset : p.offset+n]
	p.offset += n
	return b
}

// PackBytes appends a uint32-length-prefixed byte slice.
func (p *packer) PackBytes(b []byte) {
	p.PackInt(uint32(len(b)))
	p.PackFixedBytes(b)
}

// UnpackBytes reads a uint32-length-prefixed byte slice.
func (p *packer) UnpackBytes() []byte {
	n := p.UnpackInt()
	return p.UnpackFixedBytes(int(n))
}

// PackStr appends a string with a uint16 length prefix (mirrors
// wrappers.PackStr — same envelope shape, just LE).
func (p *packer) PackStr(s string) {
	if len(s) > maxStringLen {
		p.addErr(errInvalidInput)
		return
	}
	p.PackShort(uint16(len(s)))
	p.PackFixedBytes([]byte(s))
}

// UnpackStr reads a uint16-length-prefixed string.
func (p *packer) UnpackStr() string {
	n := p.UnpackShort()
	return string(p.UnpackFixedBytes(int(n)))
}

// checkSpace asserts that at least n bytes remain to read.
func (p *packer) checkSpace(n int) {
	switch {
	case p.offset < 0:
		p.addErr(errNegativeOffset)
	case n < 0:
		p.addErr(errInvalidInput)
	case len(p.bytes)-p.offset < n:
		p.addErr(ErrInsufficientLength)
	}
}

// expand grows the underlying buffer to accommodate n more write bytes.
// Refuses to grow past maxSize.
func (p *packer) expand(n int) {
	needed := p.offset + n
	switch {
	case needed <= len(p.bytes):
		return
	case needed > p.maxSize:
		p.err = ErrInsufficientLength
		return
	case needed <= cap(p.bytes):
		p.bytes = p.bytes[:needed]
		return
	default:
		p.bytes = append(p.bytes[:cap(p.bytes)], make([]byte, needed-cap(p.bytes))...)
	}
}
