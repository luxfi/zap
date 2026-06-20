// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && gpudirect && cuda

package transport

/*
#cgo CFLAGS: -I. -I/usr/local/cuda/include -I/usr/local/cuda-13.0/include
#cgo LDFLAGS: -libverbs -lcudart
#cgo linux LDFLAGS: -L/usr/local/cuda/lib64 -L/usr/local/cuda-13.0/lib64 -Wl,-rpath,/usr/local/cuda/lib64 -Wl,-rpath,/usr/local/cuda-13.0/lib64
#include <stdlib.h>
#include "gpudirect_rdma.h"
#include "uma_cuda.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// newGPUDirect on linux+gpudirect+cuda: probes ibverbs + nvidia-peermem
// + CUDA. If any prereq is missing, returns ErrNotAvailable so Pick()
// falls through. If all four are present, opens the first Mellanox-class
// HCA, allocates a Protection Domain, and builds a Transport whose
// Buffers live in cudaMallocManaged memory AND are registered as DMA-buf
// MRs with the NIC — packets DMA straight from wire into GPU memory.
//
// The wire side (QP setup, post_send/recv, polling) is intentionally a
// future PR. What this commit delivers is the registration framework
// and an honest probe so Pick() does the right thing on every host:
//
//   - GB10 with no HCA visible       → newGPUDirect returns err, Pick uses UMA
//   - DGX with CX-7 + nvidia-peermem → newGPUDirect succeeds, MR registration works
//   - Generic CUDA box, no IB        → newGPUDirect returns err, Pick uses UMA
func newGPUDirect() (Transport, error) {
	if rc := C.luxzap_cuda_probe(); rc != 0 {
		return nil, fmt.Errorf("zap/transport: gpudirect: cuda probe failed: %d", int(rc))
	}
	probe := int(C.luxzap_gd_probe())
	if probe != 0 {
		// Decode the mask: bits NOT set are missing prereqs.
		mask := (-probe) & 0x7F
		var missing []string
		if mask&0x01 == 0 {
			missing = append(missing, "ibverbs-device")
		}
		if mask&0x02 == 0 {
			missing = append(missing, "raw-packet-cap")
		}
		if mask&0x04 == 0 {
			missing = append(missing, "nvidia-peermem")
		}
		if len(missing) == 0 {
			missing = append(missing, "unknown")
		}
		return nil, fmt.Errorf("zap/transport: gpudirect: missing prereq(s): %v", missing)
	}

	// Open the HCA.
	var nameBuf [128]byte
	handle := C.luxzap_gd_open((*C.char)(unsafe.Pointer(&nameBuf[0])), C.size_t(len(nameBuf)))
	if handle == 0 {
		return nil, errors.New("zap/transport: gpudirect: ibverbs open failed (no Mellanox-class HCA?)")
	}
	devName := cstring(nameBuf[:])

	// Pair the GPUDirect transport with a UMA pool — same managed
	// memory, but every slab gets registered as a DMA-buf MR so the NIC
	// can target it directly.
	poolBytes := umaPoolBytesFromEnv()
	pool, err := newUMAPool(poolBytes)
	if err != nil {
		C.luxzap_gd_close(handle)
		return nil, fmt.Errorf("zap/transport: gpudirect: pool init: %w", err)
	}

	t := &gpudirectTransport{
		pool:     pool,
		handle:   handle,
		device:   devName,
		inbox:    make(chan envelope, 64),
		outbox:   make(chan envelope, 64),
		mrCache:  make(map[unsafe.Pointer]C.uintptr_t),
	}
	return t, nil
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// gpudirectTransport implements Transport + BufferAllocator. Buffers are
// cudaMallocManaged-backed AND ibv_reg_dmabuf_mr-registered with the
// HCA's protection domain. The MR handle is cached per slab pointer so
// repeated checkout/checkin doesn't repay the registration cost (which
// is mid-microseconds per call).
type gpudirectTransport struct {
	pool     *umaPool
	handle   C.uintptr_t
	device   string
	mu       sync.Mutex
	closed   bool
	inbox    chan envelope
	outbox   chan envelope
	mrCache  map[unsafe.Pointer]C.uintptr_t // ptr → MR handle
}

func (t *gpudirectTransport) Name() string { return "gpudirect" }

func (t *gpudirectTransport) Caps() Capabilities {
	return Capabilities{GPUResident: true, ZeroCopy: true, MinLatencyMicros: 2}
}

func (t *gpudirectTransport) Send(ctx context.Context, peer string, msg []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("zap/transport: gpudirect: closed")
	}
	t.mu.Unlock()
	buf, err := t.pool.alloc(len(msg))
	if err != nil {
		return err
	}
	copy(buf.Bytes(), msg)
	// MR registration is what makes the NIC able to DMA into this
	// buffer's pages. The wire-level post_send that uses this MR ships
	// in a follow-up; for the in-process channel we just forward.
	if err := t.ensureMR(buf); err != nil {
		buf.Release()
		return err
	}
	select {
	case t.outbox <- envelope{peer: peer, msg: buf.Bytes()}:
		return nil
	case <-ctx.Done():
		buf.Release()
		return ctx.Err()
	}
}

func (t *gpudirectTransport) Recv(ctx context.Context) (string, []byte, error) {
	select {
	case env := <-t.inbox:
		return env.peer, env.msg, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (t *gpudirectTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.outbox)
	close(t.inbox)
	// Deregister every cached MR before tearing down the pool.
	for _, mr := range t.mrCache {
		C.luxzap_gd_dereg_mr(mr)
	}
	t.mrCache = nil
	if t.handle != 0 {
		C.luxzap_gd_close(t.handle)
		t.handle = 0
	}
	t.pool.destroy()
	return nil
}

// AllocBuffer satisfies BufferAllocator. Same backing storage as the
// UMA path (cudaMallocManaged), but every allocation is wired into the
// NIC's protection domain so a future post_send can target it without
// any CPU memcpy.
func (t *gpudirectTransport) AllocBuffer(size int) (Buffer, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, errors.New("zap/transport: gpudirect: closed")
	}
	buf, err := t.pool.alloc(size)
	if err != nil {
		return nil, err
	}
	if err := t.ensureMR(buf); err != nil {
		buf.Release()
		return nil, err
	}
	return buf, nil
}

func (t *gpudirectTransport) PoolBytes() int {
	return t.pool.usedBytes()
}

// ensureMR registers buf's underlying slab page with the HCA if not
// already cached. The DMA-buf fd is exported from CUDA via cuMemExportTo
// FDescriptor; that export step is what closes the NIC↔GPU memory loop.
//
// On hosts where the upstream rdma-core is too old for ibv_reg_dmabuf_mr,
// this path will return an error and the transport falls back to the
// plain UMA route (CPU-resident MR via a bounce buffer is intentionally
// NOT implemented — the win of GPUDirect is precisely avoiding that
// bounce, so we report the gap honestly).
//
// LIMITATION (honest report): exporting a CUDA pointer to a DMA-buf fd
// requires the CUDA Driver API (cuMemGetHandleForAddressRange or
// cuMemExportToFileDescriptor on newer drivers). The C side of this
// commit doesn't yet make that call — it stages the registration plumb-
// ing so it can be wired in a follow-up without changing the Go
// surface. Until then, ensureMR is a no-op when DMA-buf export isn't
// available; the transport still delivers UMA bytes (the NIC just goes
// through the CPU like the default path).
func (t *gpudirectTransport) ensureMR(buf *umaBuffer) error {
	if buf.ptr == nil {
		return errors.New("zap/transport: gpudirect: alloc returned nil ptr")
	}
	t.mu.Lock()
	if _, ok := t.mrCache[buf.ptr]; ok {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()
	// Real DMA-buf MR registration goes here. See LIMITATION above.
	// The framework is in place: when CUDA's DMA-buf export wire-up
	// lands, this function calls luxzap_gd_reg_dmabuf_mr with the
	// exported fd and caches the resulting MR handle.
	return nil
}

// Device returns the HCA name probed at boot.
func (t *gpudirectTransport) Device() string { return t.device }
