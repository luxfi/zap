// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux

package transport

// newDPDK on linux: factory hook for the DPDK + GPU-mapped hugepage
// path. The real implementation calls rte_eal_init via cgo, registers
// the hugepage pool with cudaHostRegister, and dispatches the ZAP
// parser as a CUDA kernel. Stub until the wire-up lands.
func newDPDK() (Transport, error) { return newDPDKStub() }
