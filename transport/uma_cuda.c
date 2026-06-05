// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
//go:build cgo && linux && cuda
//
// cudaMallocManaged-backed UMA pool, host-side glue. Compiled into the
// luxfi/zap binary only when the cgo + linux + cuda build tags are set;
// see uma_linux_cuda.go for the Go cgo bridge.
//
// We keep this file pure C (not .cu) so the host's plain `gcc`/`cc` can
// build it; the CUDA runtime is linked via -lcudart and headers are
// pulled from cuda_runtime_api.h (the C-only subset of the CUDA SDK).

#include "uma_cuda.h"

#include <cuda_runtime_api.h>
#include <string.h>

int luxzap_cuda_probe(void) {
  int count = 0;
  cudaError_t e = cudaGetDeviceCount(&count);
  if (e != cudaSuccess) {
    return (int)e;
  }
  if (count == 0) {
    return -1;  // no device — distinct from a cuda error
  }
  return 0;
}

int luxzap_cuda_alloc_managed(size_t size, void** out_ptr) {
  if (!out_ptr) {
    return (int)cudaErrorInvalidValue;
  }
  *out_ptr = NULL;
  void* p = NULL;
  cudaError_t e = cudaMallocManaged(&p, size, cudaMemAttachGlobal);
  if (e != cudaSuccess) {
    return (int)e;
  }
  *out_ptr = p;
  return 0;
}

int luxzap_cuda_free(void* ptr) {
  if (!ptr) {
    return 0;
  }
  return (int)cudaFree(ptr);
}

size_t luxzap_cuda_device_name(char* buf, size_t buflen) {
  if (!buf || buflen == 0) {
    return 0;
  }
  buf[0] = '\0';
  struct cudaDeviceProp prop;
  if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) {
    return 0;
  }
  size_t n = strnlen(prop.name, sizeof(prop.name));
  if (n >= buflen) {
    n = buflen - 1;
  }
  memcpy(buf, prop.name, n);
  buf[n] = '\0';
  return n;
}
