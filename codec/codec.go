// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codec

import (
	"errors"

	"github.com/luxfi/zap/codec/wrappers"
)

// Common codec errors
var (
	ErrUnsupportedType           = errors.New("unsupported type")
	ErrMaxSliceLenExceeded       = errors.New("max slice length exceeded")
	ErrDoesNotImplementInterface = errors.New("does not implement interface")
	ErrUnexportedField           = errors.New("unexported field")
	ErrMarshalNil                = errors.New("can't marshal nil pointer")
	ErrMarshalZeroLength         = errors.New("can't marshal zero length value")
	ErrUnmarshalNil              = errors.New("can't unmarshal into nil")
	ErrUnmarshalZeroLength       = errors.New("can't unmarshal zero length value")
	ErrCantPackVersion           = errors.New("couldn't pack codec version")
	ErrCantUnpackVersion         = errors.New("couldn't unpack codec version")
	ErrUnknownVersion            = errors.New("unknown codec version")
	ErrDuplicateType             = errors.New("duplicate type registration")
	ErrExtraSpace                = errors.New("trailing buffer space")
)

// Codec marshals and unmarshals
type Codec interface {
	MarshalInto(interface{}, *wrappers.Packer) error
	UnmarshalFrom(*wrappers.Packer, interface{}) error
	Size(value interface{}) (int, error)
}

// Registry handles type registration for codec
type Registry interface {
	RegisterType(interface{}) error
}

// GeneralCodec combines Codec and Registry interfaces
type GeneralCodec interface {
	Codec
	Registry
}

// Manager manages multiple codec versions
type Manager interface {
	RegisterCodec(version uint16, codec Codec) error
	Marshal(version uint16, source interface{}) ([]byte, error)
	Unmarshal(bytes []byte, dest interface{}) (uint16, error)
	Size(version uint16, value interface{}) (int, error)
}

// DefaultMaxSize is the default maximum size for codec manager (1MB)
const DefaultMaxSize = 1024 * 1024

// NewManager returns a new codec manager
func NewManager(maxSize uint64) Manager {
	return &manager{
		maxSize: int(maxSize),
		codecs:  make(map[uint16]Codec),
	}
}

// NewDefaultManager returns a codec manager with default max size
func NewDefaultManager() Manager {
	return NewManager(DefaultMaxSize)
}

type manager struct {
	maxSize int
	codecs  map[uint16]Codec
}

func (m *manager) RegisterCodec(version uint16, codec Codec) error {
	if _, exists := m.codecs[version]; exists {
		return ErrDuplicateType
	}
	m.codecs[version] = codec
	return nil
}

func (m *manager) Marshal(version uint16, source interface{}) ([]byte, error) {
	codec, exists := m.codecs[version]
	if !exists {
		return nil, ErrUnknownVersion
	}

	p := &wrappers.Packer{MaxSize: m.maxSize}
	p.PackShort(version)
	if p.Err != nil {
		return nil, ErrCantPackVersion
	}

	if err := codec.MarshalInto(source, p); err != nil {
		return nil, err
	}

	return p.Bytes[:p.Offset], p.Err
}

func (m *manager) Unmarshal(bytes []byte, dest interface{}) (uint16, error) {
	if len(bytes) < 2 {
		return 0, ErrCantUnpackVersion
	}

	// Enforce maxSize during unmarshalling - reject oversized inputs
	if len(bytes) > m.maxSize {
		return 0, ErrMaxSliceLenExceeded
	}

	p := &wrappers.Packer{Bytes: bytes, MaxSize: m.maxSize}
	version := p.UnpackShort()
	if p.Err != nil {
		return 0, ErrCantUnpackVersion
	}

	codec, exists := m.codecs[version]
	if !exists {
		return version, ErrUnknownVersion
	}

	if err := codec.UnmarshalFrom(p, dest); err != nil {
		return version, err
	}

	// Check for trailing bytes
	if p.Offset != len(bytes) {
		return version, ErrExtraSpace
	}

	return version, nil
}

func (m *manager) Size(version uint16, value interface{}) (int, error) {
	codec, exists := m.codecs[version]
	if !exists {
		return 0, ErrUnknownVersion
	}
	size, err := codec.Size(value)
	if err != nil {
		return 0, err
	}
	return 2 + size, nil // +2 for version
}
