// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zapv2 is the elegant, generic, idiomatic Go reference
// implementation of the ZAP wire format.
//
// Where the v1 [github.com/luxfi/zap] package exposes a C-shaped API
// (one hand-rolled Wrap/Build/accessor block per schema, runtime offset
// constants, runtime kind-byte switch), v2 expresses the same wire
// format through Go 1.23+ generics so that every schema gets:
//
//   - One typed [View] over the buffer.
//   - One typed [Field] per offset, with the field's value type
//     enforced at compile time. A [Field][SchemaA, uint64] cannot be
//     read from a [View][SchemaB]; the compiler rejects it.
//   - One generic [List] with [iter.Seq] range-over-func iteration.
//   - One generic [Pool] for reuse.
//   - One generic [Registry] for kind-byte dispatch (reflection at
//     boot, none in the hot path).
//
// # Wire compatibility
//
// v2 reads and writes the exact same bytes as v1. Both APIs ship
// side-by-side and may share buffers freely; nothing about the on-wire
// encoding has changed. v2 is purely an ergonomic upgrade.
//
// # Threat model
//
// All wire-level safety properties of v1 are inherited verbatim by v2
// (Magic check, version check, bounds-checked offsets, signed-but-
// non-header-aliasing Object/List pointers, RED-HIGH-1 length clamp,
// RED-HIGH-2 header-alias rejection). v2 adds compile-time type safety
// on top — it does not loosen any runtime check.
//
// # Hickey-style decomposition
//
//   - A schema is a value (something implementing [Schema]), not a
//     place. It carries a kind byte, a fixed size, and a name. Schemas
//     are qualified by package, not by prefix.
//   - A view is a value ([View]) — a typed reference into a buffer.
//     View[S] and View[T] are distinct at compile time.
//   - A field is a value ([Field]) — a phantom-typed offset, qualified
//     by the schema it belongs to and the wire type it reads/writes.
//   - A list is a value ([List]) — its element type is the schema for
//     that element; iteration is generic via [iter.Seq].
//
// One and only one way to express any of these. No braiding of policy
// with primitive, no inheritance, no duplication.
package zapv2
