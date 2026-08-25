// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"net"
	"testing"
	"time"
)

// stopCeiling is what a caller of Stop is promised: mDNS gives up after a
// second, zap waits at most waitBound on its own goroutines, and the rest is
// slack for a loaded machine.
const stopCeiling = 2*time.Second + waitBound

// A node that never started has nothing to take down. Base calls Stop from its
// terminate hook whether or not Start returned an error, so this is the path
// taken every time a port is already held.
func TestStopWithoutStart(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "never-started", Port: pickFreePortNode(t), NoDiscovery: true})

	start := time.Now()
	n.Stop()
	if elapsed := time.Since(start); elapsed > waitBound {
		t.Fatalf("Stop took %v on a node that never started, want immediate", elapsed)
	}
}

func TestStopAfterFailedStart(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer held.Close()

	n := NewNode(NodeConfig{
		NodeID:  "failed-start",
		Address: held.Addr().String(),
	})
	if err := n.Start(); err == nil {
		t.Fatal("Start succeeded on a held port")
	}

	start := time.Now()
	n.Stop()
	if elapsed := time.Since(start); elapsed > waitBound {
		t.Fatalf("Stop took %v after a failed Start, want immediate", elapsed)
	}
}

// dispatchLoop runs a registered Handler inline, and a connection still shaking
// hands is not in the conns map for Stop to close. Neither can be made to
// return, so Stop stops waiting on them.
func TestStopLeavesWedgedWork(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "wedged", Port: pickFreePortNode(t), NoDiscovery: true})
	n.wg.Add(1) // stands in for that work; nothing will ever call Done

	start := time.Now()
	n.Stop()
	elapsed := time.Since(start)

	if elapsed < waitBound {
		t.Errorf("Stop returned after %v, inside the %v bound -- it did not wait at all", elapsed, waitBound)
	}
	if elapsed > waitBound+time.Second {
		t.Errorf("Stop took %v, want under %v", elapsed, waitBound+time.Second)
	}
}

// The whole teardown, discovery included, on a node that really started. On a
// host with an interface that takes no multicast this is the path that used to
// never return.
func TestStopBounded(t *testing.T) {
	port := pickFreePortNode(t)
	n := NewNode(NodeConfig{NodeID: "bounded", ServiceType: "_zapstop._tcp", Port: port})
	if err := n.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	start := time.Now()
	n.Stop()
	if elapsed := time.Since(start); elapsed > stopCeiling {
		t.Fatalf("Stop took %v, want under %v", elapsed, stopCeiling)
	}

	ln, err := net.Listen("tcp", n.listenAddr())
	if err != nil {
		t.Fatalf("port %d still held after Stop: %v", port, err)
	}
	ln.Close()
}
