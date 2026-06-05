// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
//go:build cgo && linux && dpdk
//
// DPDK PMD-backed transport, host-side glue. Linked into the luxfi/zap
// binary only when the cgo + linux + dpdk build tags are set; see
// dpdk_linux_real.go for the Go cgo bridge.
//
// We deliberately keep this file pure C and avoid heavy DPDK headers
// outside the dpdk build tag. The build tag pulls in <rte_eal.h> via
// the per-tag flag-only file in dpdk_pmd_eal.c.

#include "dpdk_pmd.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

// hugepages_configured returns 1 when /sys/kernel/mm/hugepages reports
// at least one configured size with nr_hugepages > 0. We don't insist
// on a specific size — DPDK's mempool driver picks at init.
static int hugepages_configured(void) {
  DIR* d = opendir("/sys/kernel/mm/hugepages");
  if (!d) return 0;
  int ok = 0;
  struct dirent* e;
  while ((e = readdir(d)) != NULL) {
    if (strncmp(e->d_name, "hugepages-", 10) != 0) continue;
    char path[512];
    snprintf(path, sizeof(path),
             "/sys/kernel/mm/hugepages/%s/nr_hugepages", e->d_name);
    FILE* f = fopen(path, "r");
    if (!f) continue;
    unsigned long n = 0;
    if (fscanf(f, "%lu", &n) == 1 && n > 0) {
      ok = 1;
    }
    fclose(f);
    if (ok) break;
  }
  closedir(d);
  return ok;
}

// luxzap_dpdk_init / shutdown are defined in dpdk_pmd_eal.c which is
// compiled only when the dpdk build tag is set. To keep this file
// always-compilable (so static analysis sees a definition) we provide
// weak fall-back stubs that return EOPNOTSUPP. The link order ensures
// the real symbols win when present.

int __attribute__((weak)) luxzap_dpdk_init(int argc, char** argv) {
  (void)argc;
  (void)argv;
  return EOPNOTSUPP;
}

int __attribute__((weak)) luxzap_dpdk_shutdown(void) { return EOPNOTSUPP; }

int luxzap_dpdk_probe(void) {
  if (!hugepages_configured()) return 1;
  // We cannot tell at runtime whether librte_eal is present without
  // either dlopen'ing it or attempting rte_eal_init. The build-tag
  // separation in dpdk_pmd_eal.c handles that: if the dpdk tag is
  // set, that file's strong symbols replace the weak stubs here, and
  // a one-shot probe-init returns 0 or the rte_errno.
  int rc = luxzap_dpdk_init(0, NULL);
  if (rc == EOPNOTSUPP) return 2;
  if (rc != 0) return 3;
  // Successful probe-init — leave EAL up for the live transport.
  return 0;
}
