// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package transport is the pluggable GPU-aware ZAP transport.
//
// Three transports are implemented:
//
//	default — standard Go net (CPU parsing). Always available.
//	uma     — Apple Silicon / NVIDIA Grace unified-memory. cgo + darwin.
//	          Network packets land in shared RAM; GPU kernels read them
//	          at GPU memory speed without a copy.
//	gpudirect — NVIDIA + Mellanox CX-6/7 (GPUDirect RDMA). cgo + linux.
//	          NIC DMA into VRAM, ZAP parsed by GPU kernel, no CPU touch.
//	dpdk    — Linux DPDK + GPU-mapped hugepages. cgo + linux.
//	          Kernel-bypass packet ingestion, GPU reads from mapped huge-
//	          pages. Best for non-Mellanox NICs.
//
// All four implement the same Transport interface. Pick() chooses the
// best available implementation at runtime, honoring a caller-supplied
// preference and falling through gracefully when a preferred path is
// unavailable. There is no `gpu` build tag — cgo is the only gate, and
// the OS gate selects which native transports can compile in.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"unsafe"
)

// Transport is the wire-level surface multichain gossip uses to ship
// sealed MultiChainBlocks between validators. The interface is sized for
// one ZAP message per Send/Recv — batching happens above this layer.
type Transport interface {
	// Name returns the canonical low-cardinality transport identifier
	// (matches the env-var spelling): "default", "uma", "gpudirect",
	// "dpdk". Used in metrics labels and log lines.
	Name() string

	// Send delivers msg to peer. Implementations may zero-copy directly
	// from GPU memory; the caller MUST NOT reuse the msg buffer until
	// the call returns.
	Send(ctx context.Context, peer string, msg []byte) error

	// Recv blocks until the next message arrives or ctx is cancelled.
	// Returned msg may alias a GPU-mapped buffer; the caller MUST copy
	// before returning the buffer to the transport.
	Recv(ctx context.Context) (peer string, msg []byte, err error)

	// Close releases any held resources (sockets, GPU mapped regions,
	// DPDK queues, IB QPs).
	Close() error

	// Caps reports what this transport supports. Callers that need
	// GPU-resident bytes (UMA / GPUDirect) gate on Caps().GPUResident
	// at construction time, not per-call.
	Caps() Capabilities
}

// Buffer is one slab of managed memory handed out by a BufferAllocator.
// For the UMA transport on Linux+CUDA, the underlying pointer is
// cudaMallocManaged memory — the same bytes the GPU sees. Calling Bytes()
// gives a Go slice that shares the storage; calling DevicePtr() gives the
// raw device pointer for CUDA kernel launches.
//
// Release returns the buffer to its allocator. Double-Release is a no-op
// (allocators detect and ignore it).
type Buffer interface {
	// Bytes returns a Go slice aliasing the buffer. Length is the
	// requested size, not the slab class size. Mutating the slice
	// mutates GPU-visible memory (when GPU-resident).
	Bytes() []byte

	// DevicePtr returns the raw device pointer. For UMA this is the
	// same address as &Bytes()[0] (unified memory). For non-UMA
	// allocators this is nil and the caller must not pass it to CUDA.
	DevicePtr() unsafe.Pointer

	// Release returns the buffer to its allocator. The slice returned
	// by Bytes() must not be used after Release.
	Release()
}

// BufferAllocator hands out managed buffers. Transports that can deliver
// GPU-resident bytes (UMA Linux+CUDA, UMA Darwin+Metal) implement this;
// transports that can't (default TCP) return ErrNotAvailable from
// AllocBuffer so the caller knows to fall back to heap allocation.
//
// Capacity in bytes is the operator-configurable pool size (default 4
// GiB); allocations from a full pool block until a buffer is Released.
type BufferAllocator interface {
	// AllocBuffer returns a buffer of at least `size` bytes. The
	// returned Buffer.Bytes() slice has length `size` even though the
	// underlying slab class may be larger.
	AllocBuffer(size int) (Buffer, error)

	// PoolBytes returns the total bytes currently owned by the pool
	// (configurable maximum). Used for metrics.
	PoolBytes() int
}

// Capabilities describes what a Transport implementation supports.
type Capabilities struct {
	// GPUResident is true when message bytes never visit CPU memory.
	GPUResident bool
	// ZeroCopy is true when no memcpy happens between NIC and the buffer
	// returned by Recv. (GPU residency implies zero copy; the reverse
	// does not — UMA is GPU-resident-and-zero-copy without DMA.)
	ZeroCopy bool
	// MinLatencyMicros is a hint for the implementation's floor latency
	// on a warm path (informational; not a contract).
	MinLatencyMicros float64
}

// ErrNotAvailable is returned by Pick when no transport at the requested
// preference level is buildable on this host.
var ErrNotAvailable = errors.New("zap/transport: requested transport not available on this host")

// envPreference is the env var operators set to force a transport. Empty
// means "use the best available". Useful for A/B benchmarking on the
// same hardware (e.g. forcing default over UMA to measure the UMA win).
const envPreference = "ZAP_TRANSPORT"

// Pick returns the requested transport, falling back to the next-best
// available implementation when the request is unavailable. Empty
// preference selects automatically: gpudirect > dpdk > uma > default.
//
// The preference string is matched case-insensitively against Name().
// Special value "default" returns the standard transport unconditionally.
//
// Pick reads ZAP_TRANSPORT once; subsequent changes to the env var have
// no effect on already-constructed transports.
//
// First call also emits one log line listing the transports that were
// probed and which won. Set ZAP_TRANSPORT_QUIET=1 to silence.
func Pick(preferred string) (Transport, error) {
	if preferred == "" {
		preferred = os.Getenv(envPreference)
	}
	preferred = strings.ToLower(strings.TrimSpace(preferred))

	// Explicit request — try only that transport, no fallback.
	if preferred != "" && preferred != "auto" {
		t, err := newByName(preferred)
		if err != nil {
			return nil, fmt.Errorf("%w: name=%q: %v", ErrNotAvailable, preferred, err)
		}
		logPickOnce(t.Name(), preferred, nil)
		return t, nil
	}

	// Auto: try each native path in preference order; fall back to default.
	probed := map[string]error{}
	for _, name := range []string{"gpudirect", "dpdk", "uma"} {
		t, err := newByName(name)
		if err == nil {
			logPickOnce(t.Name(), "auto", probed)
			return t, nil
		}
		probed[name] = err
	}
	t := newDefault()
	logPickOnce(t.Name(), "auto-fallback", probed)
	return t, nil
}

var (
	logOnce sync.Once
)

// logPickOnce emits one structured log line the first time Pick succeeds.
// Subsequent calls are silent — the log line is for boot-time visibility,
// not steady-state observability.
func logPickOnce(name, mode string, probed map[string]error) {
	if os.Getenv("ZAP_TRANSPORT_QUIET") == "1" {
		return
	}
	logOnce.Do(func() {
		attrs := []any{
			slog.String("transport", name),
			slog.String("mode", mode),
		}
		for n, err := range probed {
			attrs = append(attrs, slog.String("probe."+n, err.Error()))
		}
		slog.Info("zap/transport: selected", attrs...)
	})
}

// Registered returns the list of transports that this binary can attempt
// to instantiate (i.e. the platform-and-build-tag matrix). Used by tools
// like `zap-info` and the boot-time diagnostic in lqd.
func Registered() []string {
	return []string{"default", "uma", "gpudirect", "dpdk"}
}

// newByName routes to the per-impl factory. The actual implementations
// live in transport_<name>.go files behind appropriate build tags; the
// unavailable factories on this build return ErrNotAvailable.
func newByName(name string) (Transport, error) {
	switch name {
	case "default":
		return newDefault(), nil
	case "uma":
		return newUMA()
	case "gpudirect":
		return newGPUDirect()
	case "dpdk":
		return newDPDK()
	default:
		return nil, fmt.Errorf("unknown transport name %q", name)
	}
}
