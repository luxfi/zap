// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && !cuda

package transport

import "errors"

// newUMA on linux without the cuda build tag returns a clean
// not-available error so Pick() falls through to the next transport.
// To get the real cudaMallocManaged-backed UMA pool, build with
// `-tags cuda` and link against libcudart. The actual implementation
// lives in uma_linux_cuda.go (build tag: cgo,linux,cuda).
func newUMA() (Transport, error) {
	return nil, errors.New("zap/transport: uma: built without -tags cuda; rebuild with cuda to enable")
}
