// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Host-side C API for the cudaMallocManaged-backed UMA pool. Headers are
// kept ASCII-clean so non-cgo builds can still include this file for
// static analysis.
#ifndef LUX_ZAP_TRANSPORT_UMA_CUDA_H
#define LUX_ZAP_TRANSPORT_UMA_CUDA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// luxzap_cuda_probe returns 0 if at least one CUDA device is usable on
// this host, otherwise a non-zero CUDA error code. Side-effect free
// beyond a single cudaGetDeviceCount call — safe to call before any
// other cudaMalloc*.
int luxzap_cuda_probe(void);

// luxzap_cuda_alloc_managed allocates `size` bytes via cudaMallocManaged
// with cudaMemAttachGlobal. Returns 0 on success; *out_ptr receives the
// unified pointer. Returns the cudaError_t on failure with *out_ptr=NULL.
int luxzap_cuda_alloc_managed(size_t size, void** out_ptr);

// luxzap_cuda_free releases memory previously returned by
// luxzap_cuda_alloc_managed. Safe to call with NULL.
int luxzap_cuda_free(void* ptr);

// luxzap_cuda_device_name fills `buf` with up to `buflen-1` chars of the
// device-0 name and NUL-terminates. Returns the number of bytes written
// (excluding the NUL), or 0 on error. Used only for the boot log line.
size_t luxzap_cuda_device_name(char* buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif  // LUX_ZAP_TRANSPORT_UMA_CUDA_H
