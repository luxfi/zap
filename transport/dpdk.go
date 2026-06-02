// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import "errors"

// newDPDKStub returns the sentinel error until the DPDK + GPU-mapped
// hugepage path is wired. See dpdk_linux.go for the build-tagged factory.
//
// Hardware/software required for the real impl:
//   - Linux kernel with hugepage support (2MB or 1GB pages)
//   - DPDK 23.11+ build with cuda_gha or cuda_kernel mempool driver
//   - Any DPDK-supported NIC (broader than GPUDirect's Mellanox-only)
//   - NVIDIA GPU with CUDA Toolkit 12+
//
// The real path: DPDK takes the NIC via kernel-bypass, ingests packets
// into hugepages, cudaHostRegister maps the hugepages into CUDA-visible
// host pinned memory, GPU kernel reads them at peer DMA speed. Slightly
// slower than GPUDirect RDMA but supports a much wider NIC matrix.
func newDPDKStub() (Transport, error) {
	return nil, errors.New("zap/transport: dpdk not yet wired (needs DPDK + hugepages + CUDA on linux)")
}
