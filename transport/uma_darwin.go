// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && darwin

package transport

// newUMA on darwin: hook for the Metal-backed unified-memory path.
// Until the real wire-up lands the stub returns "not yet wired" so the
// Pick() auto-selector falls through to the default transport. This file
// pins the build-tag axis so adding the real impl is a single-file edit
// with no surrounding refactor.
func newUMA() (Transport, error) { return newUMAStub() }
