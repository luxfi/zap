// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codegen

// Schema is the declarative description of a ZAP v1 schema. The
// codegen tool consumes a [Schema] and emits a per-schema *.go file
// with the Wrap/Build/Read/Write functions hand-rolled to inline.
//
// One schema description, one emitted file, one and only one way to
// access the wire format from Go code — Hickey-style.
type Schema struct {
	// GoName is the Go type name for the schema marker struct (e.g.
	// "AdvanceTimeSchema"). Used as the View[S] type parameter.
	GoName string
	// WireName is the human-readable name of the schema (e.g.
	// "AdvanceTimeTx"). Used in error messages and Registry lookup.
	// Stable across versions — part of the schema's identity.
	WireName string
	// Kind is the discriminator byte at object offset 0.
	Kind uint8
	// Size is the fixed object payload in bytes (excluding header).
	Size int
	// Package is the Go package the emitted file should live in.
	Package string
	// Fields is the ordered list of fields: scalars, fixed byte arrays
	// ("bytes<N>"), and variable-length tails ("string"/"bytes"). Each
	// occupies a slot in the fixed payload (variable-length fields hold
	// an 8-byte tail pointer there). List and nested-object tails are
	// not declared here; they use the generic [zapv1.ListAt] machinery.
	Fields []Field
	// SkipRegistry suppresses the emit of `init() { zapv1.Register[S]
	// (zapv1.DefaultRegistry) }`. Use for schema families that have a
	// PRIVATE Kind namespace (the discriminator byte is unique only
	// within a per-package registry, not globally). Examples:
	//
	//  - LP-186 chains-VM wire: each <vm>wire package has its own
	//    KindBlock=0x01 / KindTx=0x02 / etc. Registering all twelve
	//    KindBlock=0x01 implementations into a single global registry
	//    would panic on duplicate kind byte at init time.
	//  - LP-182 consensus wire: the 0x01..0x0D kind bytes are local to
	//    the consensus-wire registry (`pkg/wire/zap/schemas.go`), not
	//    the global zapv1.DefaultRegistry shared with P2P/light-client
	//    schemas at 0xD0+/0xF0+.
	//
	// Default is false — schemas with globally-unique Kind bytes
	// (LP-201, LP-208, LP-211, LP-214, LP-218) DO register at init.
	SkipRegistry bool
	// Element marks this schema as a LIST ELEMENT: a flat, fixed-size
	// value slot with NO kind discriminator byte at offset 0 (fields may
	// start at offset 0), built inline by a parent's [zapv1.WriteList] and
	// read via [zapv1.List][E].At — never wrapped as a top-level message.
	// The Kind()/Size()/Name() methods are still emitted (List[E] and the
	// registry need the Schema interface), but Kind is NOT stored in the
	// slot and Wrap does not validate it. Default false (top-level kinded
	// message: offset 0 reserved for the discriminator).
	Element bool
}

// Field describes one fixed-size field in a schema.
//
// Two field kinds are supported:
//
//  1. Scalar fields. Type is one of the [zapv1.FieldKind] members
//     (bool, int8/16/32/64, uint8/16/32/64, float32/64). The emitted
//     code uses a [zapv1.Field][S, T] handle and the standard
//     zapv1.Read/Write generic functions.
//
//  2. Fixed-width byte-array fields. Type is "bytes<N>" where N is a
//     positive integer (e.g., "bytes20" for NodeID, "bytes32" for
//     hashes, "bytes16" for session IDs). The emitted code uses the
//     v1 ObjectBuilder.SetBytesFixed / Object.BytesFixedSlice
//     accessors and returns the value as a [N]byte. Byte-array fields
//     do NOT use the zapv1.Field generic handle because [N]byte is
//     not a [zapv1.FieldKind] member; instead they get a typed
//     accessor function emitted alongside the schema.
//
//  3. Variable-length tail fields. Type is "string" or "bytes" (no
//     <N> suffix). These occupy an 8-byte tail pointer {relOffset
//     uint32, length uint32} in the fixed payload; the data lives in
//     the object tail after the fixed section. The constructor uses v1
//     ObjectBuilder.SetText / SetBytes; reads go through a standalone
//     accessor over v1's Object.Text / Object.Bytes (zero-copy
//     sub-slice of the buffer). Like byte-array fields, they do NOT use
//     the zapv1.Field generic handle (string/[]byte are not FieldKind
//     members).
//
// List and nested-object tail fields are still hand-written (the
// generic [zapv1.ListAt] / out-of-line pointer machinery).
type Field struct {
	// Name is the Go-visible field name (e.g. "Time"). Emitted into
	// the schema's Fields struct as `<SchemaGoName>Fields.Name`.
	Name string
	// Type is the Go type as a string. Supported: scalar FieldKind
	// types, "bytes<N>" for fixed byte arrays, or "string"/"bytes" for
	// variable-length tails.
	Type string
	// Offset is the byte position within the fixed-size payload. For
	// variable-length fields this is where the 8-byte tail pointer sits.
	Offset uint32
	// Elem, when non-nil, marks this field as a variable-length LIST of a
	// fixed-size element schema (Type is ignored for list fields). The
	// field occupies an 8-byte list pointer {relOffset, length} at Offset;
	// the elements live in the object tail and are read via [zapv1.ListAt].
	Elem *ListElem
	// Nested, when non-nil, marks this field as a SINGULAR nested object
	// (Type is ignored). The field occupies a 4-byte object pointer
	// {relOffset} at Offset; the nested object lives in the object tail and
	// is read via [zapv1.NestedAt]. The proto3 "message field" case — the
	// singular peer of Elem. An unset value (nil) encodes as a null pointer.
	Nested *NestedMsg
}

// ListElem describes the element type of a list field. The element must
// be a FIXED-SIZE schema (scalars + fixed byte arrays only — no
// variable-length tails of its own), so every element is a flat
// Stride-byte slot the list machinery can index in O(1).
type ListElem struct {
	// Schema is the element schema's marker GoName, e.g. "ItemSchema".
	// Emitted as the List[E] / WriteList[S,E] / ListAt[S,E] type param.
	Schema string
	// Wire is the element schema's WireName, e.g. "BatchItem". Needed to
	// reference the element's variable-length Offset<Wire>_<Field>
	// constants when an element carries string/bytes sub-fields. May be
	// empty for scalar-only elements (which use only <Schema>Fields).
	Wire string
	// Value is the Go value-struct the constructor accepts per element,
	// e.g. "Item". Emitted as `type Value struct { ...Fields... }` and the
	// list parameter is `[]Value`.
	Value string
	// Stride is the element's fixed payload size in bytes (its Size()).
	Stride int
	// Fields are the element's fields, in order (scalar, string, bytes).
	// Used to emit the Value struct and the per-element WriteList body
	// (one write per field, from the value struct into the element Setter).
	Fields []Field
}

// NestedMsg describes a singular nested-object field — the proto3 message
// field. The nested object must be a FIXED-SIZE (flat, no-kind) Element
// schema, reached through a 4-byte object pointer; its flat payload lives
// in the parent's object tail. The singular peer of [ListElem].
type NestedMsg struct {
	// Schema is the nested schema's marker GoName, e.g. "InnerSchema".
	// Emitted as the View[N] / WriteNested[S,N] / NestedAt[S,N] type param.
	Schema string
	// Wire is the nested schema's WireName, e.g. "Inner". Referenced for
	// the nested's Offset<Wire>_<Field> constants when it carries
	// string/bytes sub-fields.
	Wire string
	// Value is the Go value-struct the constructor accepts (by POINTER, so
	// nil encodes the unset/null case), e.g. "Inner". Emitted as
	// `type Value struct { ...Fields... }`; the parameter is `*Value`.
	Value string
	// Fields are the nested object's fields, in order. Used to emit the
	// Value struct and the WriteNested body (one write per field).
	Fields []Field
}

// IsList reports whether the field is a variable-length list of a
// fixed-size element schema, returning the element descriptor.
func (f Field) IsList() (*ListElem, bool) {
	if f.Elem != nil {
		return f.Elem, true
	}
	return nil, false
}

// IsNested reports whether the field is a singular nested object,
// returning the nested-message descriptor.
func (f Field) IsNested() (*NestedMsg, bool) {
	if f.Nested != nil {
		return f.Nested, true
	}
	return nil, false
}

// IsBytes reports whether the field is a fixed-width byte-array field
// (type "bytes<N>"). Returns (n, true) on a match; (0, false) for
// scalar fields.
func (f Field) IsBytes() (int, bool) {
	const prefix = "bytes"
	if len(f.Type) <= len(prefix) || f.Type[:len(prefix)] != prefix {
		return 0, false
	}
	n := 0
	for i := len(prefix); i < len(f.Type); i++ {
		c := f.Type[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// IsVarString reports whether the field is a variable-length string
// (Type == "string"). A variable-length field occupies an 8-byte tail
// pointer {relOffset uint32, length uint32} in the fixed payload; the
// string bytes live in the object tail after the fixed section. Read
// access is a standalone accessor over v1's Object.Text (a zero-copy
// sub-slice of the buffer).
func (f Field) IsVarString() bool { return f.Type == "string" }

// IsVarBytes reports whether the field is a variable-length byte slice
// (Type == "bytes", no <N> suffix). Same 8-byte tail-pointer layout as
// IsVarString; read access is over v1's Object.Bytes.
func (f Field) IsVarBytes() bool { return f.Type == "bytes" }

// IsVariable reports whether the field is any variable-length tail field
// (string or bytes). Variable fields are emitted as standalone accessor
// functions (like fixed byte arrays) rather than in the Fields struct,
// because string/[]byte are not zapv1.FieldKind members.
func (f Field) IsVariable() bool { return f.IsVarString() || f.IsVarBytes() }
