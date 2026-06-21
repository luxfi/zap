// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"sync"
)

// promise.go is Cap'n-Proto-style promise pipelining over the ZAP Node.Call
// primitive. Two complementary mechanisms:
//
//  1. Promise[T] — a CLIENT future. A call returns immediately with a Promise;
//     dependent calls take the Promise and dispatch the instant it resolves, so
//     network latencies OVERLAP. The user writes the chain declaratively:
//
//	   quote  := dex.Quote(ctx, req)
//	   intent := dex.PrepareSwapIntent(ctx, req, quote)   // waits on quote internally
//	   watch  := dex.NotifyIntent(ctx, intent)            // waits on intent internally
//	   settle := dex.ImportSettlement(ctx, watch.OnCommitted())
//	   res, err := settle.Await(ctx)
//
//  2. Pipeline batch (see pipeline.go) — a SERVER-side mechanism: a single frame
//     carries an ordered list of dependent calls with placeholder refs the server
//     substitutes from prior results, collapsing a whole chain into ONE round trip.
//
// Neither mechanism touches value: a Promise resolves to a quote estimate, a
// PreparedIntent (calldata), an IntentWatch, or a SettlementSubmitResult (calldata
// / tx hash). The consensus path stays native atomic; pipelining only hides
// latency.

// Promise is a future for an async DexSession call result of type T. It is safe
// for one producer (the dispatching goroutine) and many consumers (Await is
// idempotent and concurrent-safe).
type Promise[T any] struct {
	mu    sync.Mutex
	done  chan struct{}
	val   T
	err   error
	ready bool
}

// newPromise creates an unresolved Promise.
func newPromise[T any]() *Promise[T] {
	return &Promise[T]{done: make(chan struct{})}
}

// resolved returns an already-resolved Promise (used to lift a concrete value
// into the pipeline, e.g. a request the caller already holds).
func resolved[T any](v T, err error) *Promise[T] {
	p := newPromise[T]()
	p.fulfil(v, err)
	return p
}

// fulfil resolves the promise exactly once. Subsequent calls are no-ops (the first
// result wins), so a racing double-resolve cannot corrupt the value.
func (p *Promise[T]) fulfil(v T, err error) {
	p.mu.Lock()
	if p.ready {
		p.mu.Unlock()
		return
	}
	p.val, p.err, p.ready = v, err, true
	close(p.done)
	p.mu.Unlock()
}

// Await blocks until the promise resolves or ctx is cancelled. On cancellation it
// returns the context error WITHOUT resolving the promise (a later resolution
// still delivers to other awaiters).
func (p *Promise[T]) Await(ctx context.Context) (T, error) {
	select {
	case <-p.done:
		p.mu.Lock()
		v, err := p.val, p.err
		p.mu.Unlock()
		return v, err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// thenAsync chains a dependent call: it spawns a goroutine that awaits this
// promise, then runs fn (which issues the next Call) and resolves the returned
// promise. This is the client-side pipelining primitive — the dependent call's
// goroutine is queued immediately and fires the moment the dependency resolves, so
// the caller never blocks between stages and the network round trips overlap.
//
// fn receives the resolved value of THIS promise and the context. An error in this
// promise short-circuits: fn is not called and the error propagates.
func thenAsync[T, U any](ctx context.Context, p *Promise[T], fn func(context.Context, T) (U, error)) *Promise[U] {
	out := newPromise[U]()
	go func() {
		v, err := p.Await(ctx)
		if err != nil {
			var zero U
			out.fulfil(zero, err)
			return
		}
		u, ferr := fn(ctx, v)
		out.fulfil(u, ferr)
	}()
	return out
}
