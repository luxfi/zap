// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zapcodec is the ZAP-native little-endian reflection codec.
//
// Module history: this package originated inside github.com/luxfi/codec
// as codec/zapcodec, a drop-in replacement for codec/linearcodec that
// emits little-endian bytes. After the Wave 2G codec rip moved every
// production caller off github.com/luxfi/codec, zapcodec was extracted
// into its own top-level module so consumers (proto/zap_codec, the
// canonical wallet codec construction site) can depend on it without
// pulling in the archived codec module.
//
// Wire-format delta vs the historical linearcodec:
//
//   - All multi-byte integers are little-endian. x86_64 and arm64
//     hardware is LE-native; LE writes map to single MOV instructions
//     where BE writes need BSWAP.
//   - Interface type-id prefixes are uint32 LE (linearcodec used uint32
//     BE).
//   - String length prefix is uint16 LE (linearcodec used uint16 BE).
//   - Slice/map length prefixes are uint32 (same width as linearcodec,
//     LE byte order).
//   - Bool is a single byte, struct fields are emitted in
//     serialize-tag order — same as linearcodec.
//
// Self-contained design (Hickey decomplection):
//
//   - VALUE: the wire codec choice. Today: little-endian reflection
//     codec. The value lives here, in its own module, qualified by
//     namespace.
//   - COMPOSITION: the public Codec interface (MarshalInto /
//     UnmarshalFrom / Size) is satisfied by *codecImpl. Callers compose
//     this with their own version-prefix outer layer (see
//     proto/zap_codec.Manager for the canonical wiring).
//   - ORTHOGONAL: this package has no knowledge of any specific wire
//     payload type (PVM/XVM/warp/...) — it's a generic reflection-
//     driven (un)marshaller. Per-type registration happens at the
//     caller via Codec.RegisterType.
//
// Dependencies: the only external dependency is luxfi/utils/wrappers
// for the Packer type that crosses module boundaries on
// MarshalInto/UnmarshalFrom. The reflection-driven encoder body uses
// a local little-endian packer (zapcodec/packer.go) that aliases the
// wrappers.Packer's underlying buffer — no per-Marshal copy.
package zapcodec

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/luxfi/container/bimap"
	"github.com/luxfi/utils/wrappers"
)

// Codec is the zapcodec public surface — the reflection-driven
// (un)marshaller plus a sequential-type-id registry.
//
// Implementations are concurrency-safe: RegisterType / SkipRegistrations
// take an internal write lock; Marshal/Unmarshal/Size take a read lock
// only when inspecting the registry.
type Codec interface {
	// RegisterType assigns val the next sequential type-id so it can be
	// (un)marshalled into an interface field at the same codec
	// instance.
	RegisterType(val interface{}) error

	// SkipRegistrations bumps the next-type-id counter by n. Lets
	// callers preserve historical type-id slot layouts during a
	// migration window.
	SkipRegistrations(n int)

	// MarshalInto serialises value into p. value MAY be a pointer-to-
	// interface (in which case the interface type-id prefix is written
	// before the underlying value).
	MarshalInto(value interface{}, p *wrappers.Packer) error

	// UnmarshalFrom deserialises p into dest. dest MUST be a pointer.
	UnmarshalFrom(p *wrappers.Packer, dest interface{}) error

	// Size returns the on-wire size of value before any outer
	// version-prefix layer the manager applies.
	Size(value interface{}) (int, error)
}

// Registry is the type-registration sub-surface of Codec. Useful for
// callers that only need to register types onto a codec they hold by
// the narrower contract.
type Registry interface {
	RegisterType(val interface{}) error
}

// GeneralCodec is the union of Codec and Registry — provided for
// structural symmetry with the historical luxfi/codec.GeneralCodec.
type GeneralCodec interface {
	Codec
	Registry
}

// codecImpl is the concrete implementation behind New / NewDefault.
type codecImpl struct {
	reflective *reflectiveCodec

	lock            sync.RWMutex
	nextTypeID      uint32
	registeredTypes *bimap.BiMap[uint32, reflect.Type]
}

// New returns a fresh zapcodec instance that honours the supplied
// struct-tag names. Concurrency-safe.
func New(tagNames []string) Codec {
	c := &codecImpl{
		nextTypeID:      0,
		registeredTypes: bimap.New[uint32, reflect.Type](),
	}
	c.reflective = newReflective(c, tagNames)
	return c
}

// NewDefault returns a zapcodec instance honouring the "serialize"
// struct tag — the canonical configuration.
func NewDefault() Codec {
	return New([]string{DefaultTagName})
}

// SkipRegistrations bumps the next-type-id counter by n.
func (c *codecImpl) SkipRegistrations(n int) {
	c.lock.Lock()
	c.nextTypeID += uint32(n)
	c.lock.Unlock()
}

// RegisterType registers val under the next sequential type-id.
func (c *codecImpl) RegisterType(val interface{}) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	t := reflect.TypeOf(val)
	if c.registeredTypes.HasValue(t) {
		return fmt.Errorf("%w: %v", ErrDuplicateType, t)
	}
	c.registeredTypes.Put(c.nextTypeID, t)
	c.nextTypeID++
	return nil
}

// PrefixSize is the size of an interface type-id prefix — uint32, 4
// bytes. The reflective codec calls this when computing Size for
// values that contain interface fields.
func (*codecImpl) PrefixSize(reflect.Type) int { return intLen }

// PackPrefix writes the type-id prefix for valueType into p.
func (c *codecImpl) PackPrefix(p *packer, valueType reflect.Type) error {
	c.lock.RLock()
	defer c.lock.RUnlock()

	id, ok := c.registeredTypes.GetKey(valueType)
	if !ok {
		return fmt.Errorf("can't marshal unregistered type %q", valueType)
	}
	p.PackInt(id)
	return p.err
}

// UnpackPrefix reads a type-id prefix and returns a new zero value of
// the registered concrete type implementing valueType.
func (c *codecImpl) UnpackPrefix(p *packer, valueType reflect.Type) (reflect.Value, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	id := p.UnpackInt()
	if p.err != nil {
		return reflect.Value{}, fmt.Errorf("couldn't unmarshal interface: %w", p.err)
	}
	implT, ok := c.registeredTypes.GetValue(id)
	if !ok {
		return reflect.Value{}, fmt.Errorf("couldn't unmarshal interface: unknown type ID %d", id)
	}
	if !implT.Implements(valueType) {
		return reflect.Value{}, fmt.Errorf("couldn't unmarshal interface: %s %w %s",
			implT, ErrDoesNotImplementInterface, valueType)
	}
	return reflect.New(implT).Elem(), nil
}

// MarshalInto serialises value into the supplied wrappers.Packer. The
// local zapcodec packer aliases p's underlying buffer directly — no
// per-Marshal heap alloc for the packer itself.
func (c *codecImpl) MarshalInto(value interface{}, p *wrappers.Packer) error {
	if value == nil {
		return ErrMarshalNil
	}
	zp := packer{
		err:     p.Err,
		maxSize: p.MaxSize,
		bytes:   p.Bytes,
		offset:  p.Offset,
	}
	err := c.reflective.Marshal(value, &zp)
	p.Bytes = zp.bytes
	p.Offset = zp.offset
	if p.Err == nil {
		p.Err = chainWrappersErr(zp.err)
	}
	if err != nil {
		return chainWrappersErr(err)
	}
	return p.Err
}

// UnmarshalFrom deserialises dest from p.
func (c *codecImpl) UnmarshalFrom(p *wrappers.Packer, dest interface{}) error {
	zp := packer{
		err:     p.Err,
		maxSize: p.MaxSize,
		bytes:   p.Bytes,
		offset:  p.Offset,
	}
	err := c.reflective.Unmarshal(&zp, dest)
	p.Bytes = zp.bytes
	p.Offset = zp.offset
	if p.Err == nil {
		p.Err = chainWrappersErr(zp.err)
	}
	if err != nil {
		return chainWrappersErr(err)
	}
	return p.Err
}

// chainWrappersErr wraps zapcodec sentinel errors so they chain into
// their luxfi/utils/wrappers equivalents for errors.Is compatibility.
//
// Callers that historically asserted on wrappers.ErrInsufficientLength
// (e.g. proto/p/state's TestGetFeeStateErrors,
// vms/proposervm/block's TestParseBytes, vms/platformvm/state's
// TestParseValidator/DelegatorMetadata) continue to match without
// edit. Callers asserting on zapcodec.ErrInsufficientLength directly
// also match — both names are in the chain.
//
// Wrapping is an O(1) errors.Join — no allocation when err is nil.
func chainWrappersErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrInsufficientLength):
		return errors.Join(wrappers.ErrInsufficientLength, err)
	}
	return err
}

// Size returns the on-wire size of value, excluding any outer
// version-prefix layer the manager applies.
func (c *codecImpl) Size(value interface{}) (int, error) {
	return c.reflective.Size(value)
}
