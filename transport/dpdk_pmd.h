// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Host-side C API for the DPDK PMD-backed transport. The data plane
// (per-queue poll loop, RX/TX burst, hugepage mempool) is staged
// behind the dpdk build tag; until rte_eal_init succeeds the Go side
// reports not-available and Pick() falls through.
#ifndef LUX_ZAP_TRANSPORT_DPDK_PMD_H
#define LUX_ZAP_TRANSPORT_DPDK_PMD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// luxzap_dpdk_probe reports whether DPDK's prerequisites are satisfied
// on this host. Returns 0 when ALL prereqs are met, otherwise a
// non-zero error code:
//
//   1 : hugepages not configured
//   2 : librte_eal not linkable (build was --tags dpdk but DPDK not
//       installed at runtime)
//   3 : rte_eal_init failed (no DPDK-bound NICs, vfio-pci absent, etc.)
//
// The probe is callable from any process without privileges. The
// rte_eal_init attempt does require CAP_SYS_NICE / CAP_IPC_LOCK in
// production setups.
int luxzap_dpdk_probe(void);

// luxzap_dpdk_init initialises the EAL with the supplied arg vector.
// argv must be NULL-terminated. Returns 0 on success, the rte_errno on
// failure. Safe to call once per process.
int luxzap_dpdk_init(int argc, char** argv);

// luxzap_dpdk_shutdown tears down the EAL. After this returns the
// process can re-init only by exec'ing — DPDK is process-singleton.
int luxzap_dpdk_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif  // LUX_ZAP_TRANSPORT_DPDK_PMD_H
