// Copyright (C) 2025-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapcodec

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"

	"github.com/luxfi/math/set"
)

const initialSliceLen = 16

var (
	errNeedPointer             = errors.New("zapcodec: argument to unmarshal must be a pointer")
	errRecursiveInterfaceTypes = errors.New("zapcodec: recursive interface types")
)

// reflectiveCodec is the reflection-driven (un)marshaller. It walks
// struct fields via the embedded structFielder and emits/parses
// little-endian bytes via the local packer.
//
// The reflective walker is intentionally separate from the typeCoder
// (the registry-driven interface prefix codec): the codecImpl on
// zapcodec.go satisfies typeCoder, this walker calls into it through
// the typer field.
type reflectiveCodec struct {
	typer   typeCoder
	fielder *structFielder
}

// typeCoder is the interface/registry-driven prefix codec. codecImpl
// satisfies this — UnpackPrefix reads a uint32 type-id and returns a
// fresh zero value of the registered type; PackPrefix writes the
// type-id; PrefixSize returns the constant 4-byte prefix width.
type typeCoder interface {
	UnpackPrefix(*packer, reflect.Type) (reflect.Value, error)
	PackPrefix(*packer, reflect.Type) error
	PrefixSize(reflect.Type) int
}

func newReflective(t typeCoder, tagNames []string) *reflectiveCodec {
	return &reflectiveCodec{
		typer:   t,
		fielder: newStructFielder(tagNames),
	}
}

// Size returns the byte size of marshalling value, before any version
// prefix the manager adds.
func (c *reflectiveCodec) Size(value interface{}) (int, error) {
	if value == nil {
		return 0, ErrMarshalNil
	}
	stack := make(set.Set[reflect.Type])
	size, _, err := c.size(reflect.ValueOf(value), stack)
	return size, err
}

func (c *reflectiveCodec) size(value reflect.Value, stack set.Set[reflect.Type]) (int, bool, error) {
	switch kind := value.Kind(); kind {
	case reflect.Uint8, reflect.Int8, reflect.Bool:
		return byteLen, true, nil
	case reflect.Uint16, reflect.Int16:
		return shortLen, true, nil
	case reflect.Uint32, reflect.Int32:
		return intLen, true, nil
	case reflect.Uint64, reflect.Int64:
		return longLen, true, nil
	case reflect.String:
		// uint16 length prefix + body
		return shortLen + len(value.String()), false, nil
	case reflect.Ptr:
		if value.IsNil() {
			return 0, false, ErrMarshalNil
		}
		return c.size(value.Elem(), stack)
	case reflect.Interface:
		if value.IsNil() {
			return 0, false, ErrMarshalNil
		}
		under := value.Interface()
		underT := reflect.TypeOf(under)
		if stack.Contains(underT) {
			return 0, false, fmt.Errorf("%w: %s", errRecursiveInterfaceTypes, underT)
		}
		stack.Add(underT)
		prefix := c.typer.PrefixSize(underT)
		body, _, err := c.size(value.Elem(), stack)
		stack.Remove(underT)
		return prefix + body, false, err
	case reflect.Slice:
		n := value.Len()
		if n == 0 {
			return intLen, false, nil
		}
		elemSize, constSize, err := c.size(value.Index(0), stack)
		if err != nil {
			return 0, false, err
		}
		if elemSize == 0 {
			return 0, false, fmt.Errorf("can't marshal slice of zero length values: %w", ErrMarshalZeroLength)
		}
		if constSize {
			return intLen + n*elemSize, false, nil
		}
		total := elemSize
		for i := 1; i < n; i++ {
			inner, _, err := c.size(value.Index(i), stack)
			if err != nil {
				return 0, false, err
			}
			total += inner
		}
		return intLen + total, false, nil
	case reflect.Array:
		n := value.Len()
		if n == 0 {
			return 0, true, nil
		}
		elemSize, constSize, err := c.size(value.Index(0), stack)
		if err != nil {
			return 0, false, err
		}
		if constSize {
			return n * elemSize, true, nil
		}
		total := elemSize
		for i := 1; i < n; i++ {
			inner, _, err := c.size(value.Index(i), stack)
			if err != nil {
				return 0, false, err
			}
			total += inner
		}
		return total, false, nil
	case reflect.Struct:
		fields, err := c.fielder.GetSerializedFields(value.Type())
		if err != nil {
			return 0, false, err
		}
		var (
			total     int
			constSize = true
		)
		for _, fi := range fields {
			inner, innerConst, err := c.size(value.Field(fi), stack)
			if err != nil {
				return 0, false, err
			}
			total += inner
			constSize = constSize && innerConst
		}
		return total, constSize, nil
	case reflect.Map:
		iter := value.MapRange()
		if !iter.Next() {
			return intLen, false, nil
		}
		keySize, keyConst, err := c.size(iter.Key(), stack)
		if err != nil {
			return 0, false, err
		}
		valSize, valConst, err := c.size(iter.Value(), stack)
		if err != nil {
			return 0, false, err
		}
		if keySize == 0 && valSize == 0 {
			return 0, false, fmt.Errorf("can't marshal map with zero length entries: %w", ErrMarshalZeroLength)
		}
		switch {
		case keyConst && valConst:
			n := value.Len()
			return intLen + n*(keySize+valSize), false, nil
		case keyConst:
			n := 1
			tot := valSize
			for iter.Next() {
				vs, _, err := c.size(iter.Value(), stack)
				if err != nil {
					return 0, false, err
				}
				tot += vs
				n++
			}
			return intLen + n*keySize + tot, false, nil
		case valConst:
			n := 1
			tot := keySize
			for iter.Next() {
				ks, _, err := c.size(iter.Key(), stack)
				if err != nil {
					return 0, false, err
				}
				tot += ks
				n++
			}
			return intLen + tot + n*valSize, false, nil
		default:
			tot := intLen + keySize + valSize
			for iter.Next() {
				ks, _, err := c.size(iter.Key(), stack)
				if err != nil {
					return 0, false, err
				}
				vs, _, err := c.size(iter.Value(), stack)
				if err != nil {
					return 0, false, err
				}
				tot += ks + vs
			}
			return tot, false, nil
		}
	default:
		return 0, false, fmt.Errorf("can't size unknown kind %s", kind)
	}
}

// Marshal writes value into p. value MAY be a pointer-to-interface (in
// which case the interface prefix is written before the underlying).
func (c *reflectiveCodec) Marshal(value interface{}, p *packer) error {
	if value == nil {
		return ErrMarshalNil
	}
	stack := make(set.Set[reflect.Type])
	return c.marshal(reflect.ValueOf(value), p, stack)
}

func (c *reflectiveCodec) marshal(value reflect.Value, p *packer, stack set.Set[reflect.Type]) error {
	switch kind := value.Kind(); kind {
	case reflect.Uint8:
		p.PackByte(uint8(value.Uint()))
		return p.err
	case reflect.Int8:
		p.PackByte(uint8(value.Int()))
		return p.err
	case reflect.Uint16:
		p.PackShort(uint16(value.Uint()))
		return p.err
	case reflect.Int16:
		p.PackShort(uint16(value.Int()))
		return p.err
	case reflect.Uint32:
		p.PackInt(uint32(value.Uint()))
		return p.err
	case reflect.Int32:
		p.PackInt(uint32(value.Int()))
		return p.err
	case reflect.Uint64:
		p.PackLong(value.Uint())
		return p.err
	case reflect.Int64:
		p.PackLong(uint64(value.Int()))
		return p.err
	case reflect.String:
		p.PackStr(value.String())
		return p.err
	case reflect.Bool:
		p.PackBool(value.Bool())
		return p.err
	case reflect.Ptr:
		if value.IsNil() {
			return ErrMarshalNil
		}
		return c.marshal(value.Elem(), p, stack)
	case reflect.Interface:
		if value.IsNil() {
			return ErrMarshalNil
		}
		under := value.Interface()
		underT := reflect.TypeOf(under)
		if stack.Contains(underT) {
			return fmt.Errorf("%w: %s", errRecursiveInterfaceTypes, underT)
		}
		stack.Add(underT)
		if err := c.typer.PackPrefix(p, underT); err != nil {
			return err
		}
		if err := c.marshal(value.Elem(), p, stack); err != nil {
			return err
		}
		stack.Remove(underT)
		return p.err
	case reflect.Slice:
		n := value.Len()
		if n > math.MaxInt32 {
			return fmt.Errorf("%w; slice length %d exceeds %d",
				ErrMaxSliceLenExceeded, n, math.MaxInt32)
		}
		p.PackInt(uint32(n))
		if p.err != nil {
			return p.err
		}
		if n == 0 {
			return nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			p.PackFixedBytes(value.Bytes())
			return p.err
		}
		for i := 0; i < n; i++ {
			start := p.offset
			if err := c.marshal(value.Index(i), p, stack); err != nil {
				return err
			}
			if start == p.offset {
				return fmt.Errorf("couldn't marshal slice of zero length values: %w", ErrMarshalZeroLength)
			}
		}
		return nil
	case reflect.Array:
		if value.CanAddr() && value.Type().Elem().Kind() == reflect.Uint8 {
			p.PackFixedBytes(value.Bytes())
			return p.err
		}
		n := value.Len()
		for i := 0; i < n; i++ {
			if err := c.marshal(value.Index(i), p, stack); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		fields, err := c.fielder.GetSerializedFields(value.Type())
		if err != nil {
			return err
		}
		for _, fi := range fields {
			if err := c.marshal(value.Field(fi), p, stack); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		keys := value.MapKeys()
		n := len(keys)
		if n > math.MaxInt32 {
			return fmt.Errorf("%w; map length %d exceeds %d",
				ErrMaxSliceLenExceeded, n, math.MaxInt32)
		}
		p.PackInt(uint32(n))
		if p.err != nil {
			return p.err
		}
		type keyTuple struct {
			key             reflect.Value
			startIdx, endIdx int
		}
		sortedKeys := make([]keyTuple, len(keys))
		startOff := p.offset
		endOff := p.offset
		for i, k := range keys {
			if err := c.marshal(k, p, stack); err != nil {
				return err
			}
			if p.err != nil {
				return fmt.Errorf("couldn't marshal map key %+v: %w", k, p.err)
			}
			sortedKeys[i] = keyTuple{key: k, startIdx: endOff, endIdx: p.offset}
			endOff = p.offset
		}
		slices.SortFunc(sortedKeys, func(a, b keyTuple) int {
			return bytes.Compare(p.bytes[a.startIdx:a.endIdx], p.bytes[b.startIdx:b.endIdx])
		})
		allKeys := slices.Clone(p.bytes[startOff:p.offset])
		p.offset = startOff
		for _, k := range sortedKeys {
			keyStart := p.offset
			si := k.startIdx - startOff
			ei := k.endIdx - startOff
			p.PackFixedBytes(allKeys[si:ei])
			if p.err != nil {
				return p.err
			}
			if err := c.marshal(value.MapIndex(k.key), p, stack); err != nil {
				return err
			}
			if keyStart == p.offset {
				return fmt.Errorf("couldn't marshal map with zero length entries: %w", ErrMarshalZeroLength)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, kind)
	}
}

// Unmarshal reads dest (pointer-typed) from p.
func (c *reflectiveCodec) Unmarshal(p *packer, dest interface{}) error {
	if dest == nil {
		return ErrUnmarshalNil
	}
	dv := reflect.ValueOf(dest)
	if dv.Kind() != reflect.Ptr {
		return errNeedPointer
	}
	stack := make(set.Set[reflect.Type])
	return c.unmarshal(p, dv.Elem(), stack)
}

func (c *reflectiveCodec) unmarshal(p *packer, value reflect.Value, stack set.Set[reflect.Type]) error {
	switch value.Kind() {
	case reflect.Uint8:
		value.SetUint(uint64(p.UnpackByte()))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal uint8: %w", p.err)
		}
		return nil
	case reflect.Int8:
		value.SetInt(int64(int8(p.UnpackByte())))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal int8: %w", p.err)
		}
		return nil
	case reflect.Uint16:
		value.SetUint(uint64(p.UnpackShort()))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal uint16: %w", p.err)
		}
		return nil
	case reflect.Int16:
		value.SetInt(int64(int16(p.UnpackShort())))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal int16: %w", p.err)
		}
		return nil
	case reflect.Uint32:
		value.SetUint(uint64(p.UnpackInt()))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal uint32: %w", p.err)
		}
		return nil
	case reflect.Int32:
		value.SetInt(int64(int32(p.UnpackInt())))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal int32: %w", p.err)
		}
		return nil
	case reflect.Uint64:
		value.SetUint(p.UnpackLong())
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal uint64: %w", p.err)
		}
		return nil
	case reflect.Int64:
		value.SetInt(int64(p.UnpackLong()))
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal int64: %w", p.err)
		}
		return nil
	case reflect.Bool:
		value.SetBool(p.UnpackBool())
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal bool: %w", p.err)
		}
		return nil
	case reflect.Slice:
		n32 := p.UnpackInt()
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal slice: %w", p.err)
		}
		if n32 > math.MaxInt32 {
			return fmt.Errorf("%w; array length %d exceeds %d",
				ErrMaxSliceLenExceeded, n32, math.MaxInt32)
		}
		n := int(n32)
		sliceT := value.Type()
		innerT := sliceT.Elem()
		if innerT.Kind() == reflect.Uint8 {
			value.SetBytes(p.UnpackFixedBytes(n))
			return p.err
		}
		value.Set(reflect.MakeSlice(sliceT, 0, initialSliceLen))
		zero := reflect.Zero(innerT)
		for i := 0; i < n; i++ {
			value.Set(reflect.Append(value, zero))
			start := p.offset
			if err := c.unmarshal(p, value.Index(i), stack); err != nil {
				return err
			}
			if start == p.offset {
				return fmt.Errorf("couldn't unmarshal slice of zero length values: %w", ErrUnmarshalZeroLength)
			}
		}
		return nil
	case reflect.Array:
		n := value.Len()
		if value.Type().Elem().Kind() == reflect.Uint8 {
			unpacked := p.UnpackFixedBytes(n)
			if p.errored() {
				return p.err
			}
			under := value.Slice(0, n).Interface().([]byte)
			copy(under, unpacked)
			return nil
		}
		for i := 0; i < n; i++ {
			if err := c.unmarshal(p, value.Index(i), stack); err != nil {
				return err
			}
		}
		return nil
	case reflect.String:
		value.SetString(p.UnpackStr())
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal string: %w", p.err)
		}
		return nil
	case reflect.Interface:
		impl, err := c.typer.UnpackPrefix(p, value.Type())
		if err != nil {
			return err
		}
		implT := impl.Type()
		if stack.Contains(implT) {
			return fmt.Errorf("%w: %s", errRecursiveInterfaceTypes, implT)
		}
		stack.Add(implT)
		if err := c.unmarshal(p, impl, stack); err != nil {
			return err
		}
		stack.Remove(implT)
		value.Set(impl)
		return nil
	case reflect.Struct:
		fields, err := c.fielder.GetSerializedFields(value.Type())
		if err != nil {
			return fmt.Errorf("couldn't unmarshal struct: %w", err)
		}
		for _, fi := range fields {
			if err := c.unmarshal(p, value.Field(fi), stack); err != nil {
				return err
			}
		}
		return nil
	case reflect.Ptr:
		t := value.Type().Elem()
		v := reflect.New(t)
		if err := c.unmarshal(p, v.Elem(), stack); err != nil {
			return err
		}
		value.Set(v)
		return nil
	case reflect.Map:
		n32 := p.UnpackInt()
		if p.err != nil {
			return fmt.Errorf("couldn't unmarshal map: %w", p.err)
		}
		if n32 > math.MaxInt32 {
			return fmt.Errorf("%w; map length %d exceeds %d",
				ErrMaxSliceLenExceeded, n32, math.MaxInt32)
		}
		var (
			n      = int(n32)
			mapT   = value.Type()
			keyT   = mapT.Key()
			valT   = mapT.Elem()
			prevKey []byte
		)
		value.Set(reflect.MakeMap(mapT))
		for i := 0; i < n; i++ {
			k := reflect.New(keyT).Elem()
			keyStart := p.offset
			if err := c.unmarshal(p, k, stack); err != nil {
				return err
			}
			keyBytes := p.bytes[keyStart:p.offset]
			if i != 0 && bytes.Compare(keyBytes, prevKey) <= 0 {
				return fmt.Errorf("keys aren't sorted: (%s, %s)", prevKey, k)
			}
			prevKey = keyBytes
			v := reflect.New(valT).Elem()
			if err := c.unmarshal(p, v, stack); err != nil {
				return err
			}
			if keyStart == p.offset {
				return fmt.Errorf("couldn't unmarshal map with zero length entries: %w", ErrUnmarshalZeroLength)
			}
			value.SetMapIndex(k, v)
		}
		return nil
	default:
		return fmt.Errorf("can't unmarshal unknown type %s", value.Kind())
	}
}
