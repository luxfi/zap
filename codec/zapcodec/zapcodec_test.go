// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapcodec

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/utils/wrappers"
)

// ---------------------------------------------------------------------
// Test fixtures
//
// Each fixture covers one structural shape. Together they exercise every
// code path in reflectiveCodec.{size,marshal,unmarshal}: integers of all
// widths, bool, string, slice (byte and non-byte), array, struct,
// nested struct, interface dispatch, and map.
// ---------------------------------------------------------------------

type prims struct {
	U8  uint8  `serialize:"true"`
	U16 uint16 `serialize:"true"`
	U32 uint32 `serialize:"true"`
	U64 uint64 `serialize:"true"`
	I8  int8   `serialize:"true"`
	I16 int16  `serialize:"true"`
	I32 int32  `serialize:"true"`
	I64 int64  `serialize:"true"`
	B   bool   `serialize:"true"`
	S   string `serialize:"true"`
}

type bytesBag struct {
	Fixed [4]byte `serialize:"true"`
	Slice []byte  `serialize:"true"`
}

type sliceOfStructs struct {
	Items []prims `serialize:"true"`
}

type mapWrapper struct {
	M map[uint32]uint32 `serialize:"true"`
}

// shape is the test interface used for interface-prefix dispatch.
type shape interface {
	tag() string
}

type circle struct {
	R uint32 `serialize:"true"`
}

func (*circle) tag() string { return "circle" }

type square struct {
	Side uint32 `serialize:"true"`
}

func (*square) tag() string { return "square" }

type shapeHolder struct {
	S shape `serialize:"true"`
}

// ---------------------------------------------------------------------
// Test-local Manager
//
// The historical luxfi/codec.Manager prepended a 2-byte BE version
// prefix before calling Codec.MarshalInto. This test file embeds a
// tiny equivalent so the zapcodec module is independently testable
// without depending on the legacy codec module.
//
// The version prefix is BE on purpose — that mirrors the historical
// codec.Manager.PackShort behaviour the original tests asserted on
// (bytes 0-1 are the version, BE-encoded). Production callers using
// proto/zap_codec.Manager get an LE version prefix — see that package
// for the canonical wiring.
// ---------------------------------------------------------------------

type testManager struct {
	codec   Codec
	version uint16
}

func newTestManager(c Codec, version uint16) *testManager {
	return &testManager{codec: c, version: version}
}

func (m *testManager) Marshal(version uint16, src interface{}) ([]byte, error) {
	if version != m.version {
		return nil, errors.New("unknown codec version")
	}
	p := &wrappers.Packer{MaxSize: 1 << 20}
	p.PackShort(version) // BE per codec.Manager historical contract
	if p.Errored() {
		return nil, p.Err
	}
	if err := m.codec.MarshalInto(src, p); err != nil {
		return nil, err
	}
	if p.Err != nil {
		return nil, p.Err
	}
	return p.Bytes[:p.Offset], nil
}

func (m *testManager) Unmarshal(buf []byte, dst interface{}) (uint16, error) {
	if len(buf) < 2 {
		return 0, errors.New("can't unpack version")
	}
	p := &wrappers.Packer{Bytes: buf, MaxSize: 1 << 20}
	v := p.UnpackShort()
	if p.Errored() {
		return 0, p.Err
	}
	if v != m.version {
		return v, errors.New("unknown codec version")
	}
	if err := m.codec.UnmarshalFrom(p, dst); err != nil {
		return v, err
	}
	if p.Offset != len(buf) {
		return v, errors.New("trailing buffer space")
	}
	return v, nil
}

func (m *testManager) Size(version uint16, value interface{}) (int, error) {
	if version != m.version {
		return 0, errors.New("unknown codec version")
	}
	sz, err := m.codec.Size(value)
	if err != nil {
		return 0, err
	}
	return 2 + sz, nil // 2-byte version prefix
}

// ---------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------

func newManager(t *testing.T) *testManager {
	t.Helper()
	c := NewDefault()
	require.NoError(t, c.RegisterType(&circle{}))
	require.NoError(t, c.RegisterType(&square{}))
	return newTestManager(c, 0)
}

// ---------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------

func TestRoundTripPrims(t *testing.T) {
	m := newManager(t)
	in := &prims{
		U8: 0xAA, U16: 0xBEEF, U32: 0xDEADBEEF, U64: 0xCAFEBABEDEADBEEF,
		I8: -1, I16: -2, I32: -3, I64: -4,
		B: true, S: "ZAP rules",
	}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)

	var out prims
	v, err := m.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, uint16(0), v)
	require.Equal(t, *in, out)
}

func TestRoundTripBytes(t *testing.T) {
	m := newManager(t)
	in := &bytesBag{Fixed: [4]byte{1, 2, 3, 4}, Slice: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)
	var out bytesBag
	_, err = m.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestRoundTripSliceOfStructs(t *testing.T) {
	m := newManager(t)
	in := &sliceOfStructs{
		Items: []prims{
			{U8: 1, U32: 100, S: "first"},
			{U8: 2, U32: 200, S: "second"},
			{U8: 3, U32: 300, S: "third"},
		},
	}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)
	var out sliceOfStructs
	_, err = m.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestRoundTripMap(t *testing.T) {
	m := newManager(t)
	in := &mapWrapper{M: map[uint32]uint32{1: 100, 2: 200, 3: 300}}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)
	var out mapWrapper
	_, err = m.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, *in, out)
}

func TestRoundTripInterface(t *testing.T) {
	m := newManager(t)

	in1 := &shapeHolder{S: &circle{R: 42}}
	b, err := m.Marshal(0, in1)
	require.NoError(t, err)
	var out1 shapeHolder
	_, err = m.Unmarshal(b, &out1)
	require.NoError(t, err)
	require.Equal(t, uint32(42), out1.S.(*circle).R)

	in2 := &shapeHolder{S: &square{Side: 7}}
	b, err = m.Marshal(0, in2)
	require.NoError(t, err)
	var out2 shapeHolder
	_, err = m.Unmarshal(b, &out2)
	require.NoError(t, err)
	require.Equal(t, uint32(7), out2.S.(*square).Side)
}

// ---------------------------------------------------------------------
// Wire-format assertions
// ---------------------------------------------------------------------

// TestWireIsLittleEndian asserts the codec emits little-endian
// multi-byte integers. The testManager's 2-byte version prefix is
// BigEndian (matching the historical codec.Manager contract);
// everything past byte 2 is the codec's output and must be LE.
func TestWireIsLittleEndian(t *testing.T) {
	m := newManager(t)
	// Pick a value whose LE and BE encodings are byte-distinct:
	// 0xDEADBEEF → LE: EF BE AD DE, BE: DE AD BE EF.
	in := &struct {
		X uint32 `serialize:"true"`
	}{X: 0xDEADBEEF}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)

	// Bytes 0-1: codec version (BE 0x0000).
	require.Equal(t, byte(0x00), b[0])
	require.Equal(t, byte(0x00), b[1])

	// Bytes 2-5: the uint32 payload in LE.
	require.Equal(t, byte(0xEF), b[2])
	require.Equal(t, byte(0xBE), b[3])
	require.Equal(t, byte(0xAD), b[4])
	require.Equal(t, byte(0xDE), b[5])

	// Cross-check via binary.LittleEndian:
	require.Equal(t, uint32(0xDEADBEEF), binary.LittleEndian.Uint32(b[2:]))
}

// TestWireSliceLenIsLE asserts that slice length prefixes are also LE.
func TestWireSliceLenIsLE(t *testing.T) {
	m := newManager(t)
	in := &struct {
		B []byte `serialize:"true"`
	}{B: []byte{1, 2, 3}}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)
	// Bytes 0-1: version. Bytes 2-5: LE uint32 length = 3.
	require.Equal(t, uint32(3), binary.LittleEndian.Uint32(b[2:]))
	require.Equal(t, byte(1), b[6])
	require.Equal(t, byte(2), b[7])
	require.Equal(t, byte(3), b[8])
}

// ---------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------

func TestMarshalNil(t *testing.T) {
	m := newManager(t)
	_, err := m.Marshal(0, nil)
	require.ErrorIs(t, err, ErrMarshalNil)
}

func TestUnmarshalNeedsPointer(t *testing.T) {
	m := newManager(t)
	in := &prims{U32: 99}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)

	// Pass a non-pointer destination; the codec layer should reject.
	var out prims
	_, err = m.Unmarshal(b, out)
	require.Error(t, err)
	// Specific sentinel: errNeedPointer is internal; the manager
	// wraps it. errors.Is on the public sentinel ErrUnmarshalNil is
	// NOT what fires here — this is "not a pointer", a distinct
	// error. Just assert the error contains the expected phrase.
	require.Contains(t, err.Error(), "must be a pointer")
}

func TestUnmarshalShortBuffer(t *testing.T) {
	m := newManager(t)
	// Buffer carries only the codec version (2 bytes). A prims has
	// 8 + 2 + 4 + 8 + ... bytes of fixed-size content; reading any
	// integer should produce ErrInsufficientLength wrapped into the
	// codec error chain.
	short := []byte{0x00, 0x00}
	var out prims
	_, err := m.Unmarshal(short, &out)
	require.Error(t, err)
	// Underlying cause is our ErrInsufficientLength.
	require.True(t, errors.Is(err, ErrInsufficientLength),
		"expected ErrInsufficientLength chain, got %v", err)
}

// TestSizeMatchesMarshalLen is a structural invariant: Size(v) MUST
// equal len(Marshal(v)) - len(version prefix). If they diverge, either
// the size calculation is wrong or the marshal emits extra bytes — both
// are wire-format bugs.
func TestSizeMatchesMarshalLen(t *testing.T) {
	m := newManager(t)
	cases := []interface{}{
		&prims{U64: 99, S: "abc"},
		&bytesBag{Slice: []byte{1, 2, 3, 4, 5, 6, 7}},
		&sliceOfStructs{Items: []prims{{U8: 1}, {U8: 2}}},
		&mapWrapper{M: map[uint32]uint32{1: 10, 2: 20}},
		&shapeHolder{S: &circle{R: 7}},
	}
	for _, c := range cases {
		b, err := m.Marshal(0, c)
		require.NoError(t, err)
		sz, err := m.Size(0, c)
		require.NoError(t, err)
		require.Equal(t, len(b), sz, "Size and Marshal disagree for %T", c)
	}
}

// TestDuplicateRegistration asserts the Registry contract — the
// same type registered twice returns ErrDuplicateType.
func TestDuplicateRegistration(t *testing.T) {
	c := NewDefault()
	require.NoError(t, c.RegisterType(&circle{}))
	err := c.RegisterType(&circle{})
	require.ErrorIs(t, err, ErrDuplicateType)
}

// TestSkipRegistrationsKeepsSlotIDs asserts that SkipRegistrations
// does what its name says: bumps the next-type-id counter without
// registering, so subsequent registrations land at the expected ID.
// The slot-ID effect is observed externally: after Skip(5), a
// registered type unmarshalled from a wire with id=5 must decode.
func TestSkipRegistrationsKeepsSlotIDs(t *testing.T) {
	c := NewDefault()
	c.SkipRegistrations(5)
	require.NoError(t, c.RegisterType(&circle{}))
	m := newTestManager(c, 0)

	in := &shapeHolder{S: &circle{R: 99}}
	b, err := m.Marshal(0, in)
	require.NoError(t, err)

	// The interface-type-id is at byte offset (2 version + struct
	// prelude). For shapeHolder the only field is the interface, so
	// the type-id is the first 4 bytes after the version prefix.
	require.Equal(t, uint32(5), binary.LittleEndian.Uint32(b[2:6]))

	var out shapeHolder
	_, err = m.Unmarshal(b, &out)
	require.NoError(t, err)
	require.Equal(t, uint32(99), out.S.(*circle).R)
}
