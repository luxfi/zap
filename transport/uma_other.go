// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || (!darwin && !linux)

package transport

import "errors"

// newUMA on hosts without cgo or outside the {darwin, linux} matrix:
// UMA is not implementable here, so Pick() must fall through.
func newUMA() (Transport, error) {
	return nil, errors.New("zap/transport: uma: not available on this OS/build")
}
