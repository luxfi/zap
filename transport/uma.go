// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import "errors"

// newUMA returns the unified-memory transport for hosts where CPU and
// GPU share physical RAM (Apple Silicon, NVIDIA Grace-Hopper with
// NVLink-C2C). Network packets arrive via standard sockets, but because
// CPU and GPU see the same physical pages, the GPU kernel can parse the
// ZAP message in place without any DMA copy.
//
// Implementation lives in uma_darwin.go (cgo && darwin) and
// uma_grace_linux.go (cgo && linux + Grace detection). Stub here returns
// ErrNotAvailable so the Pick() auto-selector falls through cleanly.
//
// The real implementation will be a thin shim around
// github.com/luxfi/zap NodeClient: it reads packets via the existing
// transport, then exposes the packet buffer to GPU kernels via
// MTLBuffer.contents (darwin) or cudaMallocManaged (Grace). The ZAP
// parser (the same logic as zap.Message at package github.com/luxfi/zap)
// is ported to a GPU kernel so the parse never touches CPU.
//
// Real shipping criterion: a darwin build that wires this through the
// fhe / cevm / dex GPU contexts so the parsed ZAP message lands as a
// device-resident view that the kernel reads directly.
func newUMAStub() (Transport, error) {
	return nil, errors.New("zap/transport: uma not yet wired on this host (cgo+darwin or Grace)")
}
