// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux

package transport

// newGPUDirect on linux: factory hook for the NVIDIA GPUDirect RDMA
// path. The real implementation links libibverbs + nvidia-peermem and
// dispatches the ZAP parser as a CUDA kernel reading from VRAM-mapped
// receive queues. Until that lands the stub returns "not yet wired" and
// Pick() falls through to the next-best transport on this host.
func newGPUDirect() (Transport, error) { return newGPUDirectStub() }
