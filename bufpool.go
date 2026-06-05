// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"sync"
	"sync/atomic"
)

// Pooled read-buffer slabs.
//
// readMessageRaw used to do `make([]byte, length)` on every frame, which
// allocates GC-tracked memory each read. The buffer's lifetime extends
// from one Read call to wherever the caller releases the *Message —
// typically the end of a handler invocation, or the moment a Call
// goroutine consumes its response from the response channel.
//
// We quantize buffer sizes into six classes (64B, 256B, 1 KiB, 4 KiB,
// 16 KiB, 64 KiB) so each `sync.Pool` holds slabs of one shape only
// — that avoids the variable-size pool defeat where a 1 KiB Get
// returns a 64 KiB slab that's never reused at its real shape.
//
// A `bufRef` is a refcount wrapper around the slab. dispatchLoop
// increments the count when a *Message escapes to a channel (so the
// awaiting Call goroutine can Release) and decrements once after the
// handler/parse path is done. When refs hits zero the slab returns
// to its pool.
//
// Anything larger than the largest class (> 64 KiB) falls through to
// a one-off heap allocation with a nil pool — Release on those is a
// no-op so the GC reclaims them naturally. Three reasons we don't pool
// >64 KiB:
//   - Large frames are rare on the steady-state hot path (most
//     dispatchLoop frames are control + correlated RPCs).
//   - sync.Pool fairness under contention degrades with slab size:
//     keeping >64 KiB slabs hot can pin tens of MiB per process.
//   - The 10 MiB MaxFrameSize ceiling already caps the worst case
//     to a single heap allocation per giant frame.

// bufSizes lists the quantization in ascending order. Anything between
// classes rounds UP to the next class — that's the only way to keep
// a class invariant ("a 256B slab is exactly 256 bytes of cap").
var bufSizes = [...]int{64, 256, 1024, 4 * 1024, 16 * 1024, 64 * 1024}

// bufPools[i] holds slabs of bufSizes[i] capacity.
//
// Declared as a pointer-to-array so the package-level initializer
// doesn't copy a `sync.Pool` value (which contains sync.noCopy). The
// pools themselves never move after init.
var bufPools = func() *[len(bufSizes)]sync.Pool {
	pools := new([len(bufSizes)]sync.Pool)
	for i, sz := range bufSizes {
		size := sz // capture before closure binding
		pools[i].New = func() any {
			b := make([]byte, size)
			return &b
		}
	}
	return pools
}()

// pickBufClass returns the pool index for a buffer of length n,
// or -1 if n exceeds the largest class.
//
// Branchless ladder beats binary search at this scale (6 classes) —
// the predicted compare-and-jump is one pipeline-friendly cycle on
// modern superscalars. We tested both; the ladder won by 3-4 ns.
func pickBufClass(n int) int {
	switch {
	case n <= bufSizes[0]:
		return 0
	case n <= bufSizes[1]:
		return 1
	case n <= bufSizes[2]:
		return 2
	case n <= bufSizes[3]:
		return 3
	case n <= bufSizes[4]:
		return 4
	case n <= bufSizes[5]:
		return 5
	default:
		return -1
	}
}

// bufRef is a refcounted slab. The refcount is set to 1 by getBuf
// and decremented by release. When it hits zero the underlying slab
// is returned to its pool (if any).
//
// One bufRef tracks one slab; we pool the bufRef struct itself via a
// dedicated pool so the refcount header doesn't churn the heap either.
//
// We hold the slab as *[]byte (not []byte) so release can Put the
// same pointer that Get returned — sync.Pool deduplicates on pointer
// identity. Putting a fresh-stack &buf forces a new heap alloc for
// the slice header on every release, which was a 24-byte/op overhead
// on the first iteration.
type bufRef struct {
	// bufp is the pooled slice header. nil for over-class one-offs.
	bufp *[]byte

	// fallback holds the slab when bufp is nil (over-class). Sized
	// exactly to n; reclaimed by GC.
	fallback []byte

	// n is the frame length the caller asked for (≤ len(buf)).
	n int

	// class is the index into bufPools, or -1 if buf was a one-off
	// heap allocation (frame > largest pool class).
	class int

	// refs counts live references to buf. Starts at 1, +1 on retain,
	// -1 on release. When it reaches 0 the slab returns to its pool.
	refs atomic.Int32
}

// refPool pools the bufRef header itself. bufRefs are tiny (40 bytes
// on 64-bit) but they appear on every frame — pooling them takes them
// off the GC's plate the same way the slab pool removes the buffer.
var refPool = sync.Pool{
	New: func() any { return new(bufRef) },
}

// getBuf returns a refcounted slab of at least n bytes, with refs=1.
//
// Caller must call release() (or attach the ref to a *Message which
// will release on its own teardown). Failure to release leaks the
// slab — sync.Pool will eventually reclaim it via its own GC hook,
// but the steady-state allocation savings depend on prompt release.
func getBuf(n int) *bufRef {
	r := refPool.Get().(*bufRef)
	r.n = n
	r.refs.Store(1)

	class := pickBufClass(n)
	r.class = class
	if class < 0 {
		// Anything larger than the largest class: one-off heap alloc.
		// Release returns the bufRef header to refPool but lets GC
		// reclaim the buffer itself.
		r.bufp = nil
		r.fallback = make([]byte, n)
		return r
	}
	r.bufp = bufPools[class].Get().(*[]byte)
	r.fallback = nil
	return r
}

// rawBuf returns the underlying slab as a slice of class capacity
// (or n bytes for over-class fallbacks). io.ReadFull writes into the
// first n bytes.
func (r *bufRef) rawBuf() []byte {
	if r.bufp != nil {
		return (*r.bufp)[:bufSizes[r.class]]
	}
	return r.fallback
}

// Bytes returns the slab sub-slice the caller asked for. The capacity
// is the pool class size; the length is the requested n. Treat as
// read-only after the underlying frame has been parsed.
func (r *bufRef) Bytes() []byte {
	if r.bufp != nil {
		return (*r.bufp)[:r.n]
	}
	return r.fallback[:r.n]
}

// retain increments the refcount. Called when a *Message constructed
// over this slab escapes from the dispatch loop to a goroutine that
// will release it later (e.g. a Call response delivered via channel).
func (r *bufRef) retain() {
	r.refs.Add(1)
}

// release decrements the refcount. When it hits zero the slab is
// returned to its pool (or simply dropped to GC if it was an
// over-class one-off allocation).
//
// release on a nil bufRef is a no-op — Message's release field is
// nil when the message wasn't built over a pooled buffer, and we
// don't want callers to have to branch on that.
func (r *bufRef) release() {
	if r == nil {
		return
	}
	if r.refs.Add(-1) != 0 {
		return
	}
	if r.bufp != nil {
		bufPools[r.class].Put(r.bufp)
		r.bufp = nil
	}
	r.fallback = nil
	r.n = 0
	r.class = 0
	refPool.Put(r)
}
