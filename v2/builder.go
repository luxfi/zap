// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2

import (
	"github.com/luxfi/zap"
)

// Builder is the imperative-style construction API for schema S.
// Where [Build] takes a closure (more readable, more allocations
// because the closure escapes), Builder gives the caller direct
// control over the build sequence — at the cost of three lines
// instead of one. Use it on hot paths that match the v1 hand-rolled
// allocation profile (1 alloc per Finish: the buffer itself).
//
// Usage:
//
//	bb := zapv2.NewBuilderFor[AdvanceTimeSchema]()
//	zapv2.WriteB(bb, examples.AdvanceTimeFields.Time, ts)
//	view, buf := bb.Finish()
//
// WriteB is the explicit-receiver counterpart to [Write] — both take
// a (Field, value) pair, but WriteB writes through a [Builder][S]
// instead of a [Setter][S], allowing escape analysis to keep the
// builder on the stack.
//
// Builder is NOT safe for concurrent use; each goroutine should
// allocate its own.
//
// Layout: Builder holds two pointers (b, ob) into the v1 builder
// state. Both pointers' targets are heap-allocated by v1, but the
// Builder[S] struct itself stays on the caller's stack because it's
// passed by value.
type Builder[S Schema] struct {
	b  *zap.Builder
	ob *zap.ObjectBuilder
}

// NewBuilderFor returns a fresh Builder[S] sized for S's fixed
// payload + the ZAP frame header. Variable-length tails (lists,
// bytes) grow on demand via the underlying [zap.Builder].
//
// The discriminator byte at object offset 0 is written automatically;
// the caller MUST NOT overwrite offset 0.
//
// Returned by value so the wrapping Builder[S] struct can stay on the
// caller's stack — only the underlying v1 *zap.Builder and []byte buf
// escape to the heap.
func NewBuilderFor[S Schema]() Builder[S] {
	var s S
	b, ob := startBuild(s.Size(), uint8(s.Kind()))
	return Builder[S]{b: b, ob: ob}
}

// startBuild is the non-generic, shape-free counterpart of
// [NewBuilderFor]: allocate a v1 [*zap.Builder] sized for the fixed
// payload, anchor an [*zap.ObjectBuilder] at the root, and write the
// kind discriminator. The caller (per-schema shim, codegen, or
// generic [NewBuilderFor]) supplies size and kind as constants — the
// Go compiler folds them at compile time when called from a concrete
// instantiation.
//
// Centralizing the allocation here keeps the generic [NewBuilderFor]
// body tiny and lets the inliner fold it into the caller — same
// trick as [WrapRaw] / [parseHeaderImpl].
func startBuild(size int, kind uint8) (*zap.Builder, *zap.ObjectBuilder) {
	b := zap.NewBuilder(zap.HeaderSize + size)
	ob := b.StartObject(size)
	ob.SetUint8(0, kind)
	return b, ob
}

// Finish finalizes the message and returns both the typed View and
// the underlying buffer (aliasing the same memory). After Finish, the
// Builder MUST NOT be reused.
//
// Performance: returns a value-typed View[S] holding only slice
// headers and an int32 offset. No *zap.Message is allocated — the
// View references buf directly. Combined with NewBuilderFor + WriteB,
// this collapses to v1's hand-rolled 1-alloc profile (just the buf).
func (bb Builder[S]) Finish() (View[S], []byte) {
	var s S
	r, buf := finishBuild(bb.b, bb.ob, s.Size())
	return AsView[S](r), buf
}

// finishBuild is the non-generic finalization step: finalize the
// object as the root, finalize the builder, and produce a Raw + the
// buffer. Pulled out of [Builder.Finish] for the same inlining reason
// as [startBuild] / [WrapRaw].
//
// The Raw's payload is the fixed-section slice; the caller wraps it
// as [View[S]] via [AsView]. The buffer is returned for callers that
// need the on-wire bytes.
func finishBuild(b *zap.Builder, ob *zap.ObjectBuilder, size int) (Raw, []byte) {
	rootOff := ob.FinishAsRoot()
	buf := b.Finish()
	end := rootOff + size
	return Raw{
		data:    buf,
		payload: buf[rootOff:end:end],
		rootOff: int32(rootOff),
	}, buf
}

// AsSetter returns a [Setter][S] for advanced variable-length
// helpers (WriteList, WriteBytes) that need both the ObjectBuilder
// and the underlying Builder.
func (bb Builder[S]) AsSetter() Setter[S] {
	return Setter[S]{ob: bb.ob, b: bb.b}
}
