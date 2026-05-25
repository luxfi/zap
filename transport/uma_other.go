// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || (!darwin && !linux)

package transport

func newUMA() (Transport, error) { return newUMAStub() }
