// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Host-side C API for the GPUDirect RDMA probe + DMA-buf MR registration.
// The data-plane (QP create / post_send / poll_cq) is intentionally
// minimal — what changes the wire is the MR registration, which lets the
// NIC DMA straight into GPU memory.
#ifndef LUX_ZAP_TRANSPORT_GPUDIRECT_RDMA_H
#define LUX_ZAP_TRANSPORT_GPUDIRECT_RDMA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// luxzap_gd_probe reports whether GPUDirect RDMA's prerequisites are
// satisfied on this host:
//
//   bit 0 (0x01)  : at least one ibverbs device is open-able
//   bit 1 (0x02)  : at least one device reports IBV_DEVICE_RAW_PACKET
//                   (Mellanox CX-6/7 etc.)
//   bit 2 (0x04)  : nvidia_peermem (or its successor nvidia-peermem)
//                   kernel module appears in /proc/modules
//   bit 3 (0x08)  : at least one CUDA device is usable
//
// Returns 0 when ALL four bits would be set; otherwise returns a
// negative value whose lower nibble is the bitmask of bits that WERE
// set, OR'd with 0x80 to distinguish from a clean 0.
//
// Operators read the returned bitmask via `negate-and-mask 0x7f` to see
// which prereq is missing.
int luxzap_gd_probe(void);

// luxzap_gd_open opens the first ibverbs device that reports
// IBV_DEVICE_RAW_PACKET. Returns a non-zero opaque handle on success
// (passed to subsequent calls) and writes the device name into
// `name_buf` (caller-allocated, name_buflen bytes, NUL-terminated).
// Returns 0 on failure with errno set.
uintptr_t luxzap_gd_open(char* name_buf, size_t name_buflen);

// luxzap_gd_close releases an opened context.
void luxzap_gd_close(uintptr_t handle);

// luxzap_gd_reg_dmabuf_mr registers a chunk of GPU memory (DMA-buf fd
// exported from CUDA) as an ibverbs Memory Region. Returns 0 on success
// (the MR handle is written to *out_mr_handle), or a negative errno
// otherwise. The NIC can DMA into this region without bouncing through
// CPU memory.
//
// `offset` and `size` are in bytes. `access_flags` is the bitmask of
// IBV_ACCESS_* flags the caller wants.
int luxzap_gd_reg_dmabuf_mr(uintptr_t handle, int dmabuf_fd,
                            uint64_t offset, uint64_t size,
                            int access_flags,
                            uintptr_t* out_mr_handle);

// luxzap_gd_dereg_mr deregisters a previously-registered MR.
int luxzap_gd_dereg_mr(uintptr_t mr_handle);

#ifdef __cplusplus
}
#endif

#endif  // LUX_ZAP_TRANSPORT_GPUDIRECT_RDMA_H
