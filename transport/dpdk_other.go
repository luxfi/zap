// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !linux

package transport

import "errors"

// newDPDK off-Linux or without cgo: DPDK is Linux-only. Pick() falls
// through. The real implementation lives in dpdk_linux_real.go and
// requires hugepages + a DPDK-bound NIC + the dpdk build tag.
func newDPDK() (Transport, error) {
	return nil, errors.New("zap/transport: dpdk: requires linux + cgo + hugepages + DPDK")
}
