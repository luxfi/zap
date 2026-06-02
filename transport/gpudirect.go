// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import "errors"

// newGPUDirectStub returns the sentinel error until the GPUDirect RDMA
// path is wired. See gpudirect_linux.go for the build-tagged factory.
//
// Hardware required for the real impl:
//   - NVIDIA GPU with GPUDirect RDMA support (Hopper / Ada / Ampere)
//   - Mellanox / NVIDIA ConnectX-6+ NIC
//   - Linux kernel with nv_peer_mem / nvidia-peermem loaded
//   - libfabric or libibverbs build-time deps
//
// Reference architecture: NVIDIA DOCA GPUNetIO + Holoscan transport
// layer. Packets DMA from NIC into VRAM, GPU kernel parses ZAP header
// in place, CPU is never touched on the receive path.
func newGPUDirectStub() (Transport, error) {
	return nil, errors.New("zap/transport: gpudirect not yet wired (needs NVIDIA + Mellanox CX-6+ on linux)")
}
