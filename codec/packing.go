// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codec

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/luxfi/ids"
)

// Common errors
var (
	ErrInsufficientLength = errors.New("packing: insufficient length")
	ErrNegativeLength     = errors.New("packing: negative length")
	ErrBadLength          = errors.New("packing: bad length")
	ErrOverflow           = errors.New("packing: overflow")
)

// MaxStringLen is the maximum string length that can be packed
const MaxStringLen = math.MaxUint16

// Packer provides methods to pack data into bytes
type Packer struct {
	Bytes  []byte
	Offset int
	Err    error
}

// NewPacker returns a new Packer with the given max size
func NewPacker(maxSize int) *Packer {
	if maxSize < 0 {
		maxSize = 0
	}
	// Avoid huge upfront allocations; capacity will grow as needed.
	if maxSize > DefaultMaxSize {
		maxSize = DefaultMaxSize
	}
	return &Packer{
		Bytes:  make([]byte, 0, maxSize),
		Offset: 0,
	}
}

// PackerFromBytes returns a Packer initialized with the given bytes
func PackerFromBytes(b []byte) *Packer {
	return &Packer{
		Bytes:  b,
		Offset: 0,
	}
}

// Remaining returns the number of bytes remaining to read
func (p *Packer) Remaining() int {
	return len(p.Bytes) - p.Offset
}

// Errored returns true if there's been an error
func (p *Packer) Errored() bool {
	return p.Err != nil
}

// expand ensures capacity for n more bytes
func (p *Packer) expand(n int) {
	if p.Err != nil {
		return
	}
	needed := p.Offset + n
	if needed > cap(p.Bytes) {
		newCap := max(cap(p.Bytes)*2, needed)
		newBytes := make([]byte, len(p.Bytes), newCap)
		copy(newBytes, p.Bytes)
		p.Bytes = newBytes
	}
	if needed > len(p.Bytes) {
		p.Bytes = p.Bytes[:needed]
	}
}

// PackByte packs a byte
func (p *Packer) PackByte(val byte) {
	p.expand(1)
	if p.Err != nil {
		return
	}
	p.Bytes[p.Offset] = val
	p.Offset++
}

// UnpackByte unpacks a byte
func (p *Packer) UnpackByte() byte {
	if p.Err != nil {
		return 0
	}
	if p.Offset >= len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return 0
	}
	val := p.Bytes[p.Offset]
	p.Offset++
	return val
}

// PackShort packs a uint16
func (p *Packer) PackShort(val uint16) {
	p.expand(2)
	if p.Err != nil {
		return
	}
	binary.BigEndian.PutUint16(p.Bytes[p.Offset:], val)
	p.Offset += 2
}

// UnpackShort unpacks a uint16
func (p *Packer) UnpackShort() uint16 {
	if p.Err != nil {
		return 0
	}
	if p.Offset+2 > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return 0
	}
	val := binary.BigEndian.Uint16(p.Bytes[p.Offset:])
	p.Offset += 2
	return val
}

// PackInt packs a uint32
func (p *Packer) PackInt(val uint32) {
	p.expand(4)
	if p.Err != nil {
		return
	}
	binary.BigEndian.PutUint32(p.Bytes[p.Offset:], val)
	p.Offset += 4
}

// UnpackInt unpacks a uint32
func (p *Packer) UnpackInt() uint32 {
	if p.Err != nil {
		return 0
	}
	if p.Offset+4 > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return 0
	}
	val := binary.BigEndian.Uint32(p.Bytes[p.Offset:])
	p.Offset += 4
	return val
}

// PackLong packs a uint64
func (p *Packer) PackLong(val uint64) {
	p.expand(8)
	if p.Err != nil {
		return
	}
	binary.BigEndian.PutUint64(p.Bytes[p.Offset:], val)
	p.Offset += 8
}

// UnpackLong unpacks a uint64
func (p *Packer) UnpackLong() uint64 {
	if p.Err != nil {
		return 0
	}
	if p.Offset+8 > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return 0
	}
	val := binary.BigEndian.Uint64(p.Bytes[p.Offset:])
	p.Offset += 8
	return val
}

// PackBool packs a bool
func (p *Packer) PackBool(val bool) {
	if val {
		p.PackByte(1)
	} else {
		p.PackByte(0)
	}
}

// UnpackBool unpacks a bool
func (p *Packer) UnpackBool() bool {
	return p.UnpackByte() != 0
}

// PackBytes packs a byte slice with length prefix
func (p *Packer) PackBytes(val []byte) {
	if len(val) > math.MaxInt32 {
		p.Err = ErrOverflow
		return
	}
	p.PackInt(uint32(len(val)))
	p.PackFixedBytes(val)
}

// UnpackBytes unpacks a byte slice with length prefix
func (p *Packer) UnpackBytes() []byte {
	length := p.UnpackInt()
	return p.UnpackFixedBytes(int(length))
}

// PackFixedBytes packs a fixed-length byte slice
func (p *Packer) PackFixedBytes(val []byte) {
	p.expand(len(val))
	if p.Err != nil {
		return
	}
	copy(p.Bytes[p.Offset:], val)
	p.Offset += len(val)
}

// UnpackFixedBytes unpacks a fixed-length byte slice
func (p *Packer) UnpackFixedBytes(n int) []byte {
	if p.Err != nil {
		return nil
	}
	if n < 0 {
		p.Err = ErrNegativeLength
		return nil
	}
	if p.Offset+n > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return nil
	}
	val := make([]byte, n)
	copy(val, p.Bytes[p.Offset:p.Offset+n])
	p.Offset += n
	return val
}

// PackStr packs a string with length prefix
func (p *Packer) PackStr(val string) {
	strLen := len(val)
	if strLen > MaxStringLen {
		p.Err = ErrBadLength
		return
	}
	p.PackShort(uint16(strLen))
	p.PackFixedBytes([]byte(val))
}

// UnpackStr unpacks a string with length prefix
func (p *Packer) UnpackStr() string {
	strLen := p.UnpackShort()
	return string(p.UnpackFixedBytes(int(strLen)))
}

// PackID packs an ID
func (p *Packer) PackID(id ids.ID) {
	p.PackFixedBytes(id[:])
}

// UnpackID unpacks an ID
func (p *Packer) UnpackID() ids.ID {
	bytes := p.UnpackFixedBytes(ids.IDLen)
	if p.Err != nil {
		return ids.Empty
	}
	id, err := ids.ToID(bytes)
	if err != nil {
		p.Err = err
		return ids.Empty
	}
	return id
}
