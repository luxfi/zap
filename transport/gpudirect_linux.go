// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && !(gpudirect && cuda)

package transport

import "errors"

// newGPUDirect on linux without the gpudirect AND cuda build tags
// returns a clean not-available error so Pick() falls through. The
// real implementation requires:
//
//   - `-tags gpudirect,cuda`
//   - libibverbs userspace (Ubuntu: libibverbs-dev)
//   - Mellanox ConnectX-6/7 HCA visible (/dev/infiniband/uverbsN)
//   - nvidia-peermem kernel module loaded
//   - libcudart at link/run time
//
// See gpudirect_linux_real.go (build tag cgo,linux,gpudirect,cuda) for
// the live implementation.
func newGPUDirect() (Transport, error) {
	return nil, errors.New("zap/transport: gpudirect: built without -tags gpudirect,cuda")
}
