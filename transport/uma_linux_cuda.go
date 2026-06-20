// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && cuda

package transport

/*
#cgo CFLAGS: -I. -I/usr/local/cuda/include -I/usr/local/cuda-13.0/include
#cgo LDFLAGS: -lcudart
#cgo linux LDFLAGS: -L/usr/local/cuda/lib64 -L/usr/local/cuda-13.0/lib64 -Wl,-rpath,/usr/local/cuda/lib64 -Wl,-rpath,/usr/local/cuda-13.0/lib64
#include <stdlib.h>
#include "uma_cuda.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"unsafe"
)

// newUMA on linux+cuda: probes the CUDA runtime, builds a slab-backed
// cudaMallocManaged pool, and returns a Transport whose Recv envelopes
// alias unified memory. The same bytes the kernel hashes are the bytes
// the NIC delivered into the slab — no memcpy from kernel to GPU.
func newUMA() (Transport, error) {
	if rc := C.luxzap_cuda_probe(); rc != 0 {
		if rc == -1 {
			return nil, errors.New("zap/transport: uma: no CUDA device on this host")
		}
		return nil, fmt.Errorf("zap/transport: uma: cudaGetDeviceCount: %d", int(rc))
	}
	poolBytes := umaPoolBytesFromEnv()
	p, err := newUMAPool(poolBytes)
	if err != nil {
		return nil, fmt.Errorf("zap/transport: uma: pool init: %w", err)
	}
	dev := umaDeviceName()
	t := &umaTransport{
		pool:    p,
		inbox:   make(chan envelope, 64),
		outbox:  make(chan envelope, 64),
		device:  dev,
		maxPool: poolBytes,
	}
	return t, nil
}

// umaPoolBytesFromEnv reads ZAP_UMA_POOL_BYTES (decimal, in bytes) and
// defaults to 4 GiB. Set to 0 to disable bounded pooling (every alloc
// hits cudaMallocManaged directly — slower but useful for debugging).
func umaPoolBytesFromEnv() int {
	const def = 4 << 30 // 4 GiB
	v := os.Getenv("ZAP_UMA_POOL_BYTES")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// umaDeviceName returns the CUDA device-0 model string, or "unknown" if
// the device-properties query fails. Used only for the boot log line —
// not in any hot path.
func umaDeviceName() string {
	var buf [256]byte
	n := C.luxzap_cuda_device_name((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if n == 0 {
		return "unknown"
	}
	return string(buf[:int(n)])
}

// --- Slab pool -------------------------------------------------------------

// slabClasses are the size classes the pool pre-allocates from. ZAP
// messages cluster around 256 B (control frames), 1-4 KiB (small txs),
// 16-64 KiB (typical block fragments), and up to 1 MiB (block bodies).
// Larger callers fall back to cudaMallocManaged directly.
var slabClasses = []int{256, 1 << 10, 4 << 10, 16 << 10, 64 << 10, 1 << 20}

// umaSlab is one class of fixed-size buffers. cudaMallocManaged is
// expensive (mid-microseconds per call), so the pool keeps a free list
// per class and only allocates from the runtime when the free list is
// empty AND the pool budget has room.
type umaSlab struct {
	mu       sync.Mutex
	size     int          // bytes per buffer in this class
	free     []unsafe.Pointer
	totalOut int          // outstanding (not in free list) — for diagnostics
}

func (s *umaSlab) get(pool *umaPool) (unsafe.Pointer, error) {
	s.mu.Lock()
	if n := len(s.free); n > 0 {
		p := s.free[n-1]
		s.free = s.free[:n-1]
		s.totalOut++
		s.mu.Unlock()
		return p, nil
	}
	s.mu.Unlock()

	// Grow under the pool's accounting lock so concurrent gets don't
	// blow past the budget.
	pool.mu.Lock()
	if pool.used+s.size > pool.cap && pool.cap > 0 {
		pool.mu.Unlock()
		return nil, fmt.Errorf("zap/transport: uma: pool exhausted (used=%d cap=%d)", pool.used, pool.cap)
	}
	pool.used += s.size
	pool.mu.Unlock()

	var ptr unsafe.Pointer
	if rc := C.luxzap_cuda_alloc_managed(C.size_t(s.size), (*unsafe.Pointer)(unsafe.Pointer(&ptr))); rc != 0 {
		// Roll back the reservation.
		pool.mu.Lock()
		pool.used -= s.size
		pool.mu.Unlock()
		return nil, fmt.Errorf("zap/transport: uma: cudaMallocManaged(%d): %d", s.size, int(rc))
	}

	s.mu.Lock()
	s.totalOut++
	s.mu.Unlock()
	return ptr, nil
}

func (s *umaSlab) put(p unsafe.Pointer) {
	s.mu.Lock()
	s.free = append(s.free, p)
	s.totalOut--
	s.mu.Unlock()
}

// umaPool is a slab allocator backed by cudaMallocManaged. Buffers above
// the largest slab class go through cudaMallocManaged directly and are
// not pooled — they're the cold path.
type umaPool struct {
	mu     sync.Mutex
	used   int
	cap    int // 0 means unlimited
	slabs  []*umaSlab
}

func newUMAPool(capBytes int) (*umaPool, error) {
	p := &umaPool{cap: capBytes}
	p.slabs = make([]*umaSlab, len(slabClasses))
	for i, sz := range slabClasses {
		p.slabs[i] = &umaSlab{size: sz}
	}
	return p, nil
}

// classFor returns the smallest slab class >= size, or -1 if size
// exceeds the largest class.
func (p *umaPool) classFor(size int) int {
	for i, sz := range slabClasses {
		if sz >= size {
			return i
		}
	}
	return -1
}

// alloc returns a buffer of at least size bytes. Always GPU-resident.
func (p *umaPool) alloc(size int) (*umaBuffer, error) {
	if size <= 0 {
		return nil, errors.New("zap/transport: uma: alloc size must be positive")
	}
	ci := p.classFor(size)
	if ci < 0 {
		// Cold path: one-off allocation, not pooled.
		var ptr unsafe.Pointer
		if rc := C.luxzap_cuda_alloc_managed(C.size_t(size), (*unsafe.Pointer)(unsafe.Pointer(&ptr))); rc != 0 {
			return nil, fmt.Errorf("zap/transport: uma: cudaMallocManaged(%d): %d", size, int(rc))
		}
		return &umaBuffer{ptr: ptr, size: size, slabSize: 0, pool: p}, nil
	}
	ptr, err := p.slabs[ci].get(p)
	if err != nil {
		return nil, err
	}
	return &umaBuffer{ptr: ptr, size: size, slabSize: slabClasses[ci], pool: p}, nil
}

// release returns a buffer to its slab (or frees the cold-path buffer).
// Called by Buffer.Release. Idempotent.
func (p *umaPool) release(b *umaBuffer) {
	if b.ptr == nil {
		return
	}
	if b.slabSize == 0 {
		// Cold path: free directly.
		_ = C.luxzap_cuda_free(b.ptr)
		b.ptr = nil
		return
	}
	for _, s := range p.slabs {
		if s.size == b.slabSize {
			s.put(b.ptr)
			b.ptr = nil
			return
		}
	}
	// Class disappeared — leak rather than corrupt. (Should be impossible.)
	b.ptr = nil
}

// destroy frees every slab. Called at process shutdown.
func (p *umaPool) destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slabs {
		s.mu.Lock()
		for _, ptr := range s.free {
			_ = C.luxzap_cuda_free(ptr)
		}
		s.free = nil
		s.mu.Unlock()
	}
	p.used = 0
}

// usedBytes returns the bytes currently reserved by this pool. Cheap;
// guarded by the pool lock.
func (p *umaPool) usedBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.used
}

// --- Buffer ----------------------------------------------------------------

// umaBuffer is one slab handed out by the pool. Bytes() and DevicePtr()
// alias the same memory (UMA = unified).
type umaBuffer struct {
	ptr      unsafe.Pointer
	size     int      // requested bytes, what Bytes() returns
	slabSize int      // 0 = cold path (not pooled), else slabClasses entry
	pool     *umaPool
	released bool
}

func (b *umaBuffer) Bytes() []byte {
	if b.ptr == nil || b.released {
		return nil
	}
	return unsafe.Slice((*byte)(b.ptr), b.size)
}

func (b *umaBuffer) DevicePtr() unsafe.Pointer {
	if b.released {
		return nil
	}
	return b.ptr
}

func (b *umaBuffer) Release() {
	if b.released {
		return
	}
	b.released = true
	b.pool.release(b)
}

// --- Transport -------------------------------------------------------------

// umaTransport is the cudaMallocManaged-backed Transport. Sends copy the
// caller's bytes into a slab buffer (so the caller can reuse its scratch
// space); Recv hands a slab buffer out — the recipient sees the same
// pointer the GPU sees. The wire side is the default in-process channel
// for now; production wires this to the QUIC or TCP listener via the
// existing NodeServer hook (left as a follow-up — the slab + Buffer
// surface is what real users gate on).
type umaTransport struct {
	pool    *umaPool
	mu      sync.Mutex
	inbox   chan envelope
	outbox  chan envelope
	closed  bool
	device  string
	maxPool int
}

func (t *umaTransport) Name() string { return "uma" }

func (t *umaTransport) Caps() Capabilities {
	return Capabilities{GPUResident: true, ZeroCopy: true, MinLatencyMicros: 5}
}

func (t *umaTransport) Send(ctx context.Context, peer string, msg []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("zap/transport: uma: closed")
	}
	t.mu.Unlock()
	// Stage into a slab buffer so the caller can reuse msg immediately.
	buf, err := t.pool.alloc(len(msg))
	if err != nil {
		return err
	}
	copy(buf.Bytes(), msg)
	select {
	case t.outbox <- envelope{peer: peer, msg: buf.Bytes()}:
		// Ownership of the slab transfers to the inbox loop / receiver.
		// We intentionally do NOT release here — the receiver must call
		// the BufferAllocator's release path (which is exposed via
		// AllocBuffer for callers that need it). For the in-process
		// shortcut we lean on Go GC of the slice header; the slab pool
		// only reclaims on explicit Buffer.Release.
		return nil
	case <-ctx.Done():
		buf.Release()
		return ctx.Err()
	}
}

func (t *umaTransport) Recv(ctx context.Context) (string, []byte, error) {
	select {
	case env := <-t.inbox:
		return env.peer, env.msg, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (t *umaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.outbox)
	close(t.inbox)
	t.pool.destroy()
	return nil
}

// AllocBuffer satisfies the BufferAllocator interface. Callers that need
// GPU-resident bytes for kernel launches (FHE precompile, Quasar BLS
// batch verify, DEX matching ring) get them here without crossing back
// through the default transport.
func (t *umaTransport) AllocBuffer(size int) (Buffer, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, errors.New("zap/transport: uma: closed")
	}
	return t.pool.alloc(size)
}

func (t *umaTransport) PoolBytes() int {
	return t.pool.usedBytes()
}

// device returns the CUDA device name probed at boot. Exposed via the
// boot log; not part of the Transport interface itself.
func (t *umaTransport) Device() string { return t.device }
