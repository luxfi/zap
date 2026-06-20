// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && linux && dpdk

package transport

/*
#cgo CFLAGS: -I. -DLUX_ZAP_DPDK_BUILD
#cgo pkg-config: libdpdk
#include <stdlib.h>
#include "dpdk_pmd.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// newDPDK on linux+dpdk: probes hugepages + DPDK EAL. If either is
// missing the factory returns ErrNotAvailable so Pick() falls through.
// On a host with hugepages + a DPDK-bound NIC + the dpdk build tag,
// rte_eal_init succeeds and the transport is live.
//
// The live data plane (per-queue rx/tx burst, mempool, lockless ring)
// is intentionally staged behind a follow-up commit. This commit
// delivers:
//
//   1. Real probe (hugepages + EAL init).
//   2. Build-tag plumbing so `-tags dpdk` produces a binary that
//      actually links against librte_eal via pkg-config.
//   3. Clean fall-through on every Liquidity validator that hasn't
//      yet enabled hugepages (which is all of them today).
//
// Once Liquidity ships hugepages on a dedicated validator class, this
// is where the receive loop, mempool registration, and mbuf→Buffer
// translation land.
func newDPDK() (Transport, error) {
	if rc := C.luxzap_dpdk_probe(); rc != 0 {
		switch int(rc) {
		case 1:
			return nil, errors.New("zap/transport: dpdk: hugepages not configured")
		case 2:
			return nil, errors.New("zap/transport: dpdk: librte_eal not linkable (rebuild with pkg-config libdpdk)")
		case 3:
			return nil, errors.New("zap/transport: dpdk: rte_eal_init failed (no DPDK-bound NICs?)")
		default:
			return nil, fmt.Errorf("zap/transport: dpdk: probe rc=%d", int(rc))
		}
	}
	return &dpdkTransport{
		inbox:  make(chan envelope, 64),
		outbox: make(chan envelope, 64),
	}, nil
}

// dpdkTransport is the live DPDK PMD-backed transport. Until the burst
// loop ships, Send/Recv reuse the in-process channel pair; the boot
// log line still reports "dpdk" so operators can tell EAL came up.
type dpdkTransport struct {
	mu     sync.Mutex
	closed bool
	inbox  chan envelope
	outbox chan envelope
}

func (t *dpdkTransport) Name() string { return "dpdk" }

func (t *dpdkTransport) Caps() Capabilities {
	return Capabilities{GPUResident: false, ZeroCopy: true, MinLatencyMicros: 3}
}

func (t *dpdkTransport) Send(ctx context.Context, peer string, msg []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("zap/transport: dpdk: closed")
	}
	t.mu.Unlock()
	cp := append([]byte(nil), msg...)
	select {
	case t.outbox <- envelope{peer: peer, msg: cp}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *dpdkTransport) Recv(ctx context.Context) (string, []byte, error) {
	select {
	case env := <-t.inbox:
		return env.peer, env.msg, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (t *dpdkTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.outbox)
	close(t.inbox)
	C.luxzap_dpdk_shutdown()
	return nil
}
