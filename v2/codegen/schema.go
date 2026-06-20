// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package codegen

// Schema is the declarative description of a ZAP v2 schema. The
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
	// Fields is the ordered list of fixed-size fields. Variable-length
	// tails (lists, bytes) are not declared here; they use the
	// generic [zapv2.ListAt] / [zapv2.WriteList] machinery.
	Fields []Field
	// SkipRegistry suppresses the emit of `init() { zapv2.Register[S]
	// (zapv2.DefaultRegistry) }`. Use for schema families that have a
	// PRIVATE Kind namespace (the discriminator byte is unique only
	// within a per-package registry, not globally). Examples:
	//
	//  - LP-186 chains-VM wire: each <vm>wire package has its own
	//    KindBlock=0x01 / KindTx=0x02 / etc. Registering all twelve
	//    KindBlock=0x01 implementations into a single global registry
	//    would panic on duplicate kind byte at init time.
	//  - LP-182 consensus wire: the 0x01..0x0D kind bytes are local to
	//    the consensus-wire registry (`pkg/wire/zap/schemas.go`), not
	//    the global zapv2.DefaultRegistry shared with P2P/light-client
	//    schemas at 0xD0+/0xF0+.
	//
	// Default is false — schemas with globally-unique Kind bytes
	// (LP-201, LP-208, LP-211, LP-214, LP-218) DO register at init.
	SkipRegistry bool
}

// Field describes one fixed-size field in a schema.
//
// Two field kinds are supported:
//
//  1. Scalar fields. Type is one of the [zapv2.FieldKind] members
//     (bool, int8/16/32/64, uint8/16/32/64, float32/64). The emitted
//     code uses a [zapv2.Field][S, T] handle and the standard
//     zapv2.Read/Write generic functions.
//
//  2. Fixed-width byte-array fields. Type is "bytes<N>" where N is a
//     positive integer (e.g., "bytes20" for NodeID, "bytes32" for
//     hashes, "bytes16" for session IDs). The emitted code uses the
//     v1 ObjectBuilder.SetBytesFixed / Object.BytesFixedSlice
//     accessors and returns the value as a [N]byte. Byte-array fields
//     do NOT use the zapv2.Field generic handle because [N]byte is
//     not a [zapv2.FieldKind] member; instead they get a typed
//     accessor function emitted alongside the schema.
//
// Variable-length tail fields (lists, bytes, sub-objects) are NOT
// declared here. They use the generic [zapv2.ListAt] / out-of-line
// pointer machinery and require a hand-written accessor.
type Field struct {
	// Name is the Go-visible field name (e.g. "Time"). Emitted into
	// the schema's Fields struct as `<SchemaGoName>Fields.Name`.
	Name string
	// Type is the Go type as a string. See Field doc for the supported
	// set: scalar FieldKind types or "bytes<N>" for fixed byte arrays.
	Type string
	// Offset is the byte position within the fixed-size payload.
	Offset uint32
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
