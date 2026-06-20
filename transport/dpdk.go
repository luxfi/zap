// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

// dpdk.go is the cross-platform doc comment for the DPDK PMD-backed
// transport. The factory lives in:
//
//	dpdk_linux_real.go — //go:build cgo && linux && dpdk
//	    Real rte_eal_init probe + EAL bring-up.
//	dpdk_linux.go      — //go:build cgo && linux && !dpdk
//	    Clean "not available" when the dpdk tag isn't set.
//	dpdk_other.go      — //go:build !cgo || !linux
//	    Clean "not available" off-Linux or without cgo.
//
// What DPDK buys us (vs the kernel network stack):
//
//   - Userspace polling instead of interrupts — sub-microsecond ack
//     latency under load.
//   - Hugepage-backed mempool — TLB cost amortised across the entire
//     ring.
//   - Lockless burst RX/TX — 100 Gbps line rate per worker thread.
//
// Why DPDK and not just GPUDirect: DPDK works on any modern NIC (not
// just Mellanox). On a Liquidity validator with an Intel E810 or
// Broadcom NetXtreme NIC, DPDK is the right path. On a DGX with a
// CX-7, GPUDirect is the right path. UMA is the right path on Apple
// Silicon and Grace-Hopper / GB10 (no discrete NIC↔GPU memory split).
//
// Pick() chooses in this order: gpudirect > dpdk > uma > default.
// Operators force a specific transport via ZAP_TRANSPORT.
