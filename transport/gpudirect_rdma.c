// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
//go:build cgo && linux && gpudirect && cuda
//
// GPUDirect RDMA probe + DMA-buf MR registration. Linked into the
// luxfi/zap binary only when the cgo + linux + gpudirect + cuda build
// tags are set; see gpudirect_linux_real.go for the Go cgo bridge.

#include "gpudirect_rdma.h"

#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int peermem_loaded(void) {
  FILE* f = fopen("/proc/modules", "r");
  if (!f) return 0;
  char line[512];
  int found = 0;
  while (fgets(line, sizeof(line), f)) {
    // Either "nvidia_peermem " or "nv_peer_mem " — match the prefix.
    if (strncmp(line, "nvidia_peermem ", 15) == 0 ||
        strncmp(line, "nv_peer_mem ", 12) == 0) {
      found = 1;
      break;
    }
  }
  fclose(f);
  return found;
}

// device_opens_with_pd checks whether at least one ibverbs device can
// be opened AND an ibv_pd allocated on it. The PD allocation is what
// actually exercises the kernel driver — a device that's plugged but
// the kernel module is missing will open() but fail alloc_pd. This is
// the most portable equivalent of "the HCA is live and ready for QPs"
// across rdma-core versions (the IBV_DEVICE_RAW_PACKET device-cap was
// renamed to a per-QP-type capability in newer headers).
static int device_opens_with_pd(void) {
  int num = 0;
  struct ibv_device** list = ibv_get_device_list(&num);
  if (!list || num <= 0) {
    if (list) ibv_free_device_list(list);
    return 0;
  }
  int ok = 0;
  for (int i = 0; i < num; ++i) {
    struct ibv_context* ctx = ibv_open_device(list[i]);
    if (!ctx) continue;
    struct ibv_pd* pd = ibv_alloc_pd(ctx);
    if (pd) {
      ibv_dealloc_pd(pd);
      ok = 1;
    }
    ibv_close_device(ctx);
    if (ok) break;
  }
  ibv_free_device_list(list);
  return ok;
}

int luxzap_gd_probe(void) {
  int bits = 0;
  int num = 0;
  struct ibv_device** list = ibv_get_device_list(&num);
  if (list && num > 0) {
    bits |= 0x01;  // at least one device exists
  }
  if (list) ibv_free_device_list(list);

  if (device_opens_with_pd()) {
    bits |= 0x02;  // device opens AND PD allocates (HCA is live)
  }

  if (peermem_loaded()) {
    bits |= 0x04;
  }

  // CUDA availability is delegated to luxzap_cuda_probe via the Go
  // side — this file is the ibverbs side only. The Go newGPUDirect
  // does the AND with the cuda probe before deciding.
  bits |= 0x08;  // optimistic; cuda probe is the canonical source.

  if (bits == 0x0F) return 0;
  return -(0x80 | (bits & 0x7F));
}

struct luxzap_gd_ctx {
  struct ibv_context* ibv;
  struct ibv_pd* pd;
};

uintptr_t luxzap_gd_open(char* name_buf, size_t name_buflen) {
  int num = 0;
  struct ibv_device** list = ibv_get_device_list(&num);
  if (!list || num <= 0) {
    if (list) ibv_free_device_list(list);
    errno = ENODEV;
    return 0;
  }
  struct ibv_context* ibv = NULL;
  const char* picked_name = NULL;
  for (int i = 0; i < num; ++i) {
    struct ibv_context* try_ctx = ibv_open_device(list[i]);
    if (!try_ctx) continue;
    // Pick the first device whose PD allocates — same portable test
    // as device_opens_with_pd. Callers that need IBV_QPT_RAW_PACKET
    // for the final QP will get a verifiable error from ibv_create_qp
    // at QP-creation time; bouncing that decision out of the probe
    // keeps this file compilable against older rdma-core headers.
    struct ibv_pd* pd = ibv_alloc_pd(try_ctx);
    if (pd) {
      ibv_dealloc_pd(pd);
      ibv = try_ctx;
      picked_name = ibv_get_device_name(list[i]);
      break;
    }
    ibv_close_device(try_ctx);
  }
  ibv_free_device_list(list);
  if (!ibv) {
    errno = ENODEV;
    return 0;
  }
  struct ibv_pd* pd = ibv_alloc_pd(ibv);
  if (!pd) {
    int e = errno ? errno : EIO;
    ibv_close_device(ibv);
    errno = e;
    return 0;
  }
  struct luxzap_gd_ctx* c =
      (struct luxzap_gd_ctx*)calloc(1, sizeof(struct luxzap_gd_ctx));
  if (!c) {
    ibv_dealloc_pd(pd);
    ibv_close_device(ibv);
    errno = ENOMEM;
    return 0;
  }
  c->ibv = ibv;
  c->pd = pd;
  if (name_buf && name_buflen > 0 && picked_name) {
    size_t n = strnlen(picked_name, name_buflen - 1);
    memcpy(name_buf, picked_name, n);
    name_buf[n] = '\0';
  }
  return (uintptr_t)c;
}

void luxzap_gd_close(uintptr_t handle) {
  struct luxzap_gd_ctx* c = (struct luxzap_gd_ctx*)handle;
  if (!c) return;
  if (c->pd) ibv_dealloc_pd(c->pd);
  if (c->ibv) ibv_close_device(c->ibv);
  free(c);
}

int luxzap_gd_reg_dmabuf_mr(uintptr_t handle, int dmabuf_fd,
                            uint64_t offset, uint64_t size,
                            int access_flags,
                            uintptr_t* out_mr_handle) {
  if (!handle || !out_mr_handle) return -EINVAL;
  struct luxzap_gd_ctx* c = (struct luxzap_gd_ctx*)handle;
  // ibv_reg_dmabuf_mr appeared in rdma-core 35 / kernel 5.12. If the
  // build has older headers this will be a link-time miss — caller
  // should detect via build tag.
  struct ibv_mr* mr =
      ibv_reg_dmabuf_mr(c->pd, offset, size, /*iova=*/0, dmabuf_fd, access_flags);
  if (!mr) {
    return -(errno ? errno : EIO);
  }
  *out_mr_handle = (uintptr_t)mr;
  return 0;
}

int luxzap_gd_dereg_mr(uintptr_t mr_handle) {
  if (!mr_handle) return 0;
  return ibv_dereg_mr((struct ibv_mr*)mr_handle);
}
