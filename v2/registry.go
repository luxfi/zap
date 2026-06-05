// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2

import (
	"sync"

	"github.com/luxfi/zap"
)

// Registry is a kind-byte → schema-typed wrapper dispatcher. Each
// registered schema produces an [Entry] that knows, at runtime, how
// to wrap a buffer as the right typed View. The Entry itself was
// generated at compile time when [Register] was called, so dispatch
// requires no reflection and no per-call allocation — only a map
// lookup.
//
// Registry is safe for concurrent reads; Register is intended for use
// at package init and is guarded by a mutex against concurrent
// init-time races.
//
// Hickey decomposition: Registry is a value (map of values). The
// "what kind is this?" question is answered by looking at a byte;
// the "how do I parse it?" question is answered by an Entry value;
// there is no inheritance, no interface tower, no "TxFactory".
type Registry struct {
	mu      sync.RWMutex
	entries map[KindByte]Entry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[KindByte]Entry)}
}

// Entry describes how to handle one schema. The Wrap closure parses
// a buffer and returns the validated data slice + root offset,
// reflection-free.
//
// Name and Kind are duplicated from the Schema for convenient
// inspection without instantiating the Schema receiver.
type Entry struct {
	Kind KindByte
	Name string

	// Wrap validates b and returns (validated data, root offset) if
	// the kind byte matches; otherwise returns a SchemaError.
	//
	// Returns NO *zap.Message — the v1.1 generic API is value-typed
	// and constructs its own View[S] from (data, rootOff). Callers
	// that need v1 Object accessors can call zap.WrapBuffer on the
	// returned data slice.
	Wrap func(b []byte) (data []byte, rootOff int, err error)
}

// Register registers schema S in r. It is safe to call from multiple
// goroutines, but the typical pattern is init():
//
//	func init() {
//	    zapv2.Register[AdvanceTimeSchema](DefaultRegistry)
//	}
//
// Register panics if two schemas declare the same kind byte — that
// would be a wire-protocol bug, not a runtime condition.
func Register[S Schema](r *Registry) {
	var s S
	kind := s.Kind()
	name := s.Name()
	size := s.Size()

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.entries[kind]; ok && existing.Name != name {
		panic("zapv2: duplicate kind byte " + hexByte(byte(kind)) +
			" for schemas " + existing.Name + " and " + name)
	}
	r.entries[kind] = Entry{
		Kind: kind,
		Name: name,
		Wrap: func(b []byte) ([]byte, int, error) {
			data, rootOff, err := zap.ParseHeader(b)
			if err != nil {
				return nil, 0, err
			}
			// Kind byte at rootOff: 1-byte bounds is sufficient for the
			// discriminator check; the full S.Size() bounds is gated by
			// a passing kind match.
			if rootOff < 0 || rootOff >= len(data) {
				return nil, 0, zap.ErrOutOfBounds
			}
			got := KindByte(data[rootOff])
			if got != kind {
				return nil, 0, &SchemaError{
					Want: kind, Got: got, Name: name,
				}
			}
			if rootOff+size > len(data) {
				return nil, 0, zap.ErrOutOfBounds
			}
			return data, rootOff, nil
		},
	}
}

// Lookup returns the Entry for kind, or false.
//
// O(1) map read; safe for concurrent use.
func (r *Registry) Lookup(kind KindByte) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[kind]
	return e, ok
}

// Entries returns a snapshot of all registered entries. Useful for
// debugging / pretty-printing the schema table; not used in the hot
// path. The returned slice is freshly allocated.
func (r *Registry) Entries() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

// PeekKind returns the kind byte of a ZAP buffer without doing a full
// schema match. Useful when you do not know which schema you have and
// want to dispatch by kind before calling [WrapAs].
//
// Returns 0 and an error if b is not a valid ZAP frame.
func PeekKind(b []byte) (KindByte, error) {
	data, rootOff, err := zap.ParseHeader(b)
	if err != nil {
		return 0, err
	}
	if rootOff < 0 || rootOff >= len(data) {
		return 0, zap.ErrOutOfBounds
	}
	return KindByte(data[rootOff]), nil
}

// WrapAs is the typed-dispatch form: given a buffer of unknown kind
// and a target schema S, wrap if-and-only-if the buffer's kind matches
// S{}.Kind(). Equivalent to [Wrap] for callers who already have S.
//
// Existence note: kept alongside [Wrap] for symmetry with the
// Registry-driven flow (PeekKind → branch → WrapAs).
func WrapAs[S Schema](b []byte) (View[S], error) {
	return Wrap[S](b)
}

// DefaultRegistry is the package-level registry. Schemas typically
// register here at init.
var DefaultRegistry = NewRegistry()
