// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !linux

package transport

func newGPUDirect() (Transport, error) { return newGPUDirectStub() }
