// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

// Schema types for ZAP messages.
// These can be used to generate code or for runtime reflection.

// Type represents a ZAP type.
type Type uint8

const (
	TypeVoid Type = iota
	TypeBool
	TypeInt8
	TypeInt16
	TypeInt32
	TypeInt64
	TypeUint8
	TypeUint16
	TypeUint32
	TypeUint64
	TypeFloat32
	TypeFloat64
	TypeText
	TypeBytes
	TypeList
	TypeStruct
	TypeEnum
	TypeUnion
)

// Field describes a struct field.
type Field struct {
	Name       string
	Type       Type
	Offset     int    // Byte offset within struct
	ListElem   Type   // Element type if Type == TypeList
	StructName string // Struct name if Type == TypeStruct
	Default    any    // Default value
}

// Struct describes a ZAP struct.
type Struct struct {
	Name   string
	Size   int // Total size in bytes
	Fields []Field
}

// Enum describes a ZAP enum.
type Enum struct {
	Name    string
	Type    Type // Underlying type (Uint8, Uint16, etc.)
	Values  map[string]uint64
}

// Schema describes a complete ZAP schema.
type Schema struct {
	Name    string
	Structs map[string]*Struct
	Enums   map[string]*Enum
}

// NewSchema creates a new empty schema.
func NewSchema(name string) *Schema {
	return &Schema{
		Name:    name,
		Structs: make(map[string]*Struct),
		Enums:   make(map[string]*Enum),
	}
}

// AddStruct adds a struct to the schema.
func (s *Schema) AddStruct(st *Struct) {
	s.Structs[st.Name] = st
}

// AddEnum adds an enum to the schema.
func (s *Schema) AddEnum(e *Enum) {
	s.Enums[e.Name] = e
}

// TypeSize returns the size of a type in bytes.
func TypeSize(t Type) int {
	switch t {
	case TypeBool, TypeInt8, TypeUint8:
		return 1
	case TypeInt16, TypeUint16:
		return 2
	case TypeInt32, TypeUint32, TypeFloat32:
		return 4
	case TypeInt64, TypeUint64, TypeFloat64:
		return 8
	case TypeText, TypeBytes:
		return 8 // offset (4) + length (4)
	case TypeList:
		return 8 // offset (4) + length (4)
	case TypeStruct:
		return 4 // offset (4)
	default:
		return 0
	}
}

// Example schema definition helpers

// StructBuilder helps build struct definitions.
type StructBuilder struct {
	s      *Struct
	offset int
}

// NewStructBuilder creates a struct builder.
func NewStructBuilder(name string) *StructBuilder {
	return &StructBuilder{
		s: &Struct{Name: name},
	}
}

// Bool adds a bool field.
func (sb *StructBuilder) Bool(name string) *StructBuilder {
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeBool, Offset: sb.offset})
	sb.offset += 1
	return sb
}

// Int32 adds an int32 field.
func (sb *StructBuilder) Int32(name string) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeInt32, Offset: sb.offset})
	sb.offset += 4
	return sb
}

// Int64 adds an int64 field.
func (sb *StructBuilder) Int64(name string) *StructBuilder {
	sb.align(8)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeInt64, Offset: sb.offset})
	sb.offset += 8
	return sb
}

// Uint32 adds a uint32 field.
func (sb *StructBuilder) Uint32(name string) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeUint32, Offset: sb.offset})
	sb.offset += 4
	return sb
}

// Uint64 adds a uint64 field.
func (sb *StructBuilder) Uint64(name string) *StructBuilder {
	sb.align(8)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeUint64, Offset: sb.offset})
	sb.offset += 8
	return sb
}

// Float64 adds a float64 field.
func (sb *StructBuilder) Float64(name string) *StructBuilder {
	sb.align(8)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeFloat64, Offset: sb.offset})
	sb.offset += 8
	return sb
}

// Text adds a text field.
func (sb *StructBuilder) Text(name string) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeText, Offset: sb.offset})
	sb.offset += 8 // offset + length
	return sb
}

// Bytes adds a bytes field.
func (sb *StructBuilder) Bytes(name string) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeBytes, Offset: sb.offset})
	sb.offset += 8
	return sb
}

// List adds a list field.
func (sb *StructBuilder) List(name string, elemType Type) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeList, Offset: sb.offset, ListElem: elemType})
	sb.offset += 8
	return sb
}

// Struct adds a nested struct field.
func (sb *StructBuilder) Struct(name string, structName string) *StructBuilder {
	sb.align(4)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeStruct, Offset: sb.offset, StructName: structName})
	sb.offset += 4
	return sb
}

// Build finalizes and returns the struct.
func (sb *StructBuilder) Build() *Struct {
	sb.align(8) // Final alignment
	sb.s.Size = sb.offset
	return sb.s
}

func (sb *StructBuilder) align(n int) {
	sb.offset = (sb.offset + n - 1) &^ (n - 1)
}
