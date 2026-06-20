// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && darwin

package transport

import "errors"

// newUMA on darwin: hook for the Metal-backed unified-memory path.
//
// Apple Silicon (M1+, M3 Ultra) has CPU + GPU on a shared SoC die with
// physically unified memory. MTLBuffer with .storageModeShared exposes
// the same bytes to CPU and GPU. The real wire-up will mirror
// uma_linux_cuda.go: a slab pool of MTLBuffer allocations, a Buffer
// interface returning Go slices that alias the buffer.contents pointer,
// and a Transport whose Recv hands those buffers out.
//
// Until that lands, this returns ErrNotAvailable so Pick() falls
// through to the default transport on macOS. The error string names
// the gap so operators don't think it's a misconfiguration.
func newUMA() (Transport, error) {
	return nil, errors.New("zap/transport: uma: darwin Metal path pending — Pick() falling through")
}
