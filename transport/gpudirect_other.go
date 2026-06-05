// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !linux

package transport

import "errors"

// newGPUDirect off-Linux or without cgo: not implementable, Pick() falls
// through. The real implementation lives in gpudirect_linux_real.go and
// requires Mellanox + nvidia-peermem + libibverbs + CUDA.
func newGPUDirect() (Transport, error) {
	return nil, errors.New("zap/transport: gpudirect: requires linux + cgo + libibverbs + CUDA")
}
