// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2

import "sync"

// Pool is a generic, type-safe sync.Pool wrapper. Instead of writing a
// dedicated sync.Pool + Get + Put per type as v1 did, register a
// constructor once:
//
//	var ViewPool = zapv2.NewPool(func() *View[AdvanceTimeSchema] {
//	    return &View[AdvanceTimeSchema]{}
//	})
//
//	v := ViewPool.Get()
//	defer ViewPool.Put(v)
//
// Get returns a *T; Put returns it to the pool. The generic guarantees
// that a value pulled from Pool[A] cannot be returned to Pool[B]
// (would not type-check).
//
// Pool itself is safe for concurrent use (delegated to [sync.Pool]).
type Pool[T any] struct {
	p sync.Pool
}

// NewPool returns a Pool[T] whose New func is `new`. The constructor
// is called whenever the pool is exhausted. Always return a fresh,
// zero-state *T from new — never a stale value.
func NewPool[T any](new func() *T) *Pool[T] {
	return &Pool[T]{
		p: sync.Pool{
			New: func() any { return new() },
		},
	}
}

// Get returns a *T from the pool (allocating one via the New func if
// the pool is empty).
//
// The returned pointer's state is whatever the previous owner left.
// Callers MUST reset/initialize before use.
func (p *Pool[T]) Get() *T {
	return p.p.Get().(*T)
}

// Put returns t to the pool. Callers MUST NOT use t after Put.
//
// Nil pointers are silently ignored — this matches the [sync.Pool]
// "best effort" semantics.
func (p *Pool[T]) Put(t *T) {
	if t == nil {
		return
	}
	p.p.Put(t)
}
