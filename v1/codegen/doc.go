// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package codegen emits per-schema ZAP v2 accessors that match v1's
// hand-rolled inline-everything performance.
//
// # Why codegen
//
// Go's generic dispatch and inlining cost budget combine to put a
// hard ceiling on how fast a generic API can be: any function whose
// body is larger than the inliner's 80-cost budget cannot inline
// into its caller, so the call site pays a function-call cost (~5-7
// ns on modern hardware). The work performed by a "Wrap" function
// (parse the ZAP wire frame, validate the kind discriminator, build
// a typed view) exceeds that budget. The generic [zapv1.Wrap[S]]
// function therefore costs one function call per Wrap, even when
// every other primitive in its body would inline.
//
// Hand-written per-schema [WrapX] shims (e.g. [examples.WrapAdvanceTime])
// have the same problem — even though they pin S{}.Kind() and
// S{}.Size() as constants, the body is still too large to inline.
//
// Codegen solves this by emitting Wrap/Build/Read/Write functions
// that DON'T live inside a function at all — they expand inline at
// the call site through Go templates instantiated at build time.
// The user writes a single schema declaration; the codegen tool
// produces a *_zap.go file whose functions match v1's hand-rolled
// pattern byte-for-byte.
//
// # Output shape
//
// For a schema declared as:
//
//	type AdvanceTimeSchema struct{}
//	func (AdvanceTimeSchema) Kind() zapv1.KindByte { return 1 }
//	func (AdvanceTimeSchema) Size() int            { return 9 }
//	func (AdvanceTimeSchema) Name() string         { return "AdvanceTimeTx" }
//
//	//zap:field Time uint64 @1
//
// the codegen tool emits a sibling file (advance_time_zap.go) with:
//
//	const sizeAdvanceTimeTx = 9
//	const kindAdvanceTimeTx uint8 = 1
//	const offsetAdvanceTimeTx_Time = 1
//
//	func WrapAdvanceTime(b []byte) (zapv1.View[AdvanceTimeSchema], error) {
//	    msg, err := zap.Parse(b)
//	    ...
//	}
//
// The emitted code uses v1 primitives directly (zap.Parse, msg.Root,
// root.Uint8) so that the inliner folds them into the caller's frame,
// matching v1 hand-rolled performance.
//
// # When to use codegen
//
// - Hot-path schemas where the function-call overhead matters
//   (per-tx assembly, per-block validation).
// - When you have a schema description in a declarative form (a YAML
//   file, a Cap'n-Proto-style schema file, struct tags) and want
//   ZAP v2 accessors emitted automatically.
//
// For cold paths and ad-hoc schemas, the generic [zapv1.Wrap[S]] /
// [zapv1.Build[S]] are equally correct and one extra function call
// slower — which is rarely the bottleneck.
//
// # Status
//
// This package is the entry point. The current implementation emits
// the canonical AdvanceTimeTx fast-path file (used as the canary in
// the bench suite); adding new schemas means feeding the codegen
// tool a schema declaration in one of the supported forms.
package codegen
