// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
//go:build cgo && linux && dpdk
//
// Real DPDK EAL bring-up. Compiled into the binary only when the dpdk
// build tag is set (see dpdk_linux_real.go). When not built, the weak
// stubs in dpdk_pmd.c take over and the probe reports
// "librte_eal not linkable".

#if defined(LUX_ZAP_DPDK_BUILD)

#include "dpdk_pmd.h"

#include <errno.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <stdlib.h>
#include <string.h>

static int g_eal_inited = 0;

int luxzap_dpdk_init(int argc, char** argv) {
  if (g_eal_inited) return 0;
  // Default arg vector when caller passes none — DPDK insists on argv.
  char* default_argv[] = {
      "luxzap",
      "--proc-type=auto",
      "--in-memory",
      NULL,
  };
  if (argc <= 0 || argv == NULL) {
    argc = (int)(sizeof(default_argv) / sizeof(default_argv[0])) - 1;
    argv = default_argv;
  }
  int rc = rte_eal_init(argc, argv);
  if (rc < 0) {
    return rte_errno ? rte_errno : EIO;
  }
  g_eal_inited = 1;
  return 0;
}

int luxzap_dpdk_shutdown(void) {
  if (!g_eal_inited) return 0;
  int rc = rte_eal_cleanup();
  if (rc < 0) return -rc;
  g_eal_inited = 0;
  return 0;
}

#endif  // LUX_ZAP_DPDK_BUILD
