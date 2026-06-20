// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && !dpdk

package transport

import "errors"

// newDPDK on linux without the dpdk build tag returns a clean
// not-available error so Pick() falls through. The real
// implementation requires:
//
//   - `-tags dpdk`
//   - DPDK 23.11+ installed with pkg-config visible (`pkg-config
//     --modversion libdpdk` must succeed)
//   - Hugepages configured (`/sys/kernel/mm/hugepages/<size>/nr_hugepages > 0`)
//   - At least one NIC bound to vfio-pci or uio_pci_generic
//   - Process privileges for CAP_SYS_NICE + CAP_IPC_LOCK
//
// See dpdk_linux_real.go (build tag cgo,linux,dpdk) for the live
// implementation.
func newDPDK() (Transport, error) {
	return nil, errors.New("zap/transport: dpdk: built without -tags dpdk; rebuild with -tags dpdk and pkg-config libdpdk to enable")
}
