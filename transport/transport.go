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
	"os"
	"strings"
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
		return t, nil
	}

	// Auto: try each native path in preference order; fall back to default.
	for _, name := range []string{"gpudirect", "dpdk", "uma"} {
		if t, err := newByName(name); err == nil {
			return t, nil
		}
	}
	return newDefault(), nil
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
