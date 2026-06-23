// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv1

// KindByte is the one-byte discriminator at offset 0 of every v2
// object payload. It identifies the schema concretely.
//
// In v1 this lived as `TxKind uint8` per-package; v2 lifts it into
// the ZAP layer so the generic [View], [Wrap] and [Registry] code can
// reason about kind without importing every consumer.
type KindByte uint8

// Schema describes a v2 message shape. A type implements Schema by
// declaring its kind byte, its fixed object size (in bytes within the
// data segment), and a human-readable name.
//
// A schema is a value, not a place. Implementations are typically
// zero-sized marker structs whose name documents the wire shape:
//
//	type AdvanceTimeSchema struct{}
//	func (AdvanceTimeSchema) Kind() KindByte { return 0x14 }
//	func (AdvanceTimeSchema) Size() int      { return 9 }
//	func (AdvanceTimeSchema) Name() string   { return "AdvanceTimeTx" }
//
// Implementations MUST be safe to use as the zero value of their type
// — the methods consult only the receiver type, never any state.
// This invariant is what lets Registry.Register and reflect-free
// generic dispatch work.
type Schema interface {
	// Kind returns the discriminator byte at object offset 0.
	Kind() KindByte

	// Size returns the fixed-size object payload in bytes (the value
	// passed to v1's StartObject). Variable-length tails (text, bytes,
	// lists) are appended after this fixed section and do not count.
	Size() int

	// Name returns a human-readable schema name. Used for error
	// messages and for [Registry] introspection. MUST be stable across
	// versions — it is part of the schema's identity, not its display.
	Name() string
}

// FieldKind is the type-level constraint a [Field]'s value type must
// satisfy: any Go value type that can be stored in a fixed-size slot.
// The exhaustive set is the integer + float + Address + Hash + bool
// family; variable-length values (bytes, text, lists, sub-objects)
// have their own accessors because their wire representation is a
// pointer pair, not a primitive.
//
// We use a comparable union so the generic [Field] type is constrained
// at compile time. Users who add new fixed-size element types extend
// this constraint; no other API surface changes.
type FieldKind interface {
	~bool |
		~int8 | ~int16 | ~int32 | ~int64 |
		~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

// SchemaError is returned when a buffer does not match the expected
// schema (wrong kind byte, undersized object payload, etc).
type SchemaError struct {
	Want KindByte
	Got  KindByte
	Name string // schema name (Want side)
}

func (e *SchemaError) Error() string {
	// Keep the message terse and machine-grep-friendly: the kind bytes
	// are the load-bearing identity, the name is human help.
	return "zapv1: schema mismatch: want " + e.Name +
		" (kind=" + hexByte(byte(e.Want)) +
		"), got kind=" + hexByte(byte(e.Got))
}

// hexByte returns a lowercase 0x.. byte string without depending on
// fmt (keeps this hot path allocation-free; cf. b.ReportAllocs in
// the benchmark suite).
func hexByte(b byte) string {
	const hex = "0123456789abcdef"
	return "0x" + string([]byte{hex[b>>4], hex[b&0x0f]})
}
