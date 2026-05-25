// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux

package transport

// newUMA on linux: only valid on Grace-Hopper / NVLink-C2C hosts (CPU
// and GPU share physical memory). On discrete-GPU hosts the gpudirect
// or dpdk paths are correct; we don't try to detect the Grace topology
// here — set ZAP_TRANSPORT=uma to force, otherwise Pick() picks the
// right path automatically.
func newUMA() (Transport, error) { return newUMAStub() }
