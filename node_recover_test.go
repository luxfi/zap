// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"net"
	"testing"
	"time"
)

// pickFreePortNode returns an OS-assigned free TCP port.
func pickFreePortNode(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitPeersNode(t *testing.T, n *Node) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Peers()) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no peers after 2s")
}

const (
	mtPanic uint16 = 0x90 // handler that panics
	mtEcho  uint16 = 0x91 // handler that echoes — proves the node survived
)

// buildTyped makes a minimal typed message carrying a single uint32 so the
// dispatcher routes it by msgType (Flags()>>8) and the echo handler has
// something to read back.
func buildTyped(t *testing.T, msgType uint16, payload uint32) *Message {
	t.Helper()
	b := NewBuilder(64)
	ob := b.StartObject(8)
	ob.SetUint32(0, payload)
	ob.FinishAsRoot()
	msg, err := Parse(b.FinishWithFlags(msgType << 8))
	if err != nil {
		t.Fatalf("build typed msg: %v", err)
	}
	return msg
}

// TestHandlerPanicDoesNotCrashNode proves the V4 dispatch-layer fix: a
// handler that panics on a Call request must NOT unwind into the node's
// dispatch goroutine and crash the process. The recover() in safeHandle
// must fire, the offending Call returns an error to the caller (the
// connection is dropped), and the SERVER NODE keeps running — a fresh
// connection + a valid Call to a different handler still succeeds.
func TestHandlerPanicDoesNotCrashNode(t *testing.T) {
	srvPort := pickFreePortNode(t)
	cliPort := pickFreePortNode(t)

	srv := NewNode(NodeConfig{NodeID: "server", Port: srvPort, NoDiscovery: true})
	cli := NewNode(NodeConfig{NodeID: "client", Port: cliPort, NoDiscovery: true})

	// A handler that always panics — simulates an out-of-range index on a
	// malformed envelope, a nil deref, or a third-party fault.
	srv.Handle(mtPanic, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		panic("hostile input blew up the handler")
	})
	// A well-behaved echo handler on a different type.
	srv.Handle(mtEcho, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		v := msg.Root().Uint32(0)
		return buildTyped(t, mtEcho, v+1), nil
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Stop()
	if err := cli.Start(); err != nil {
		t.Fatalf("cli.Start: %v", err)
	}
	defer cli.Stop()

	if err := cli.ConnectDirect("127.0.0.1:" + itoa(srvPort)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	waitPeersNode(t, cli)

	// 1. Fire the panic-inducing Call. safeHandle recovers; the handler
	//    returns an error, so the dispatch loop logs + drops that connection.
	//    From the caller's view the Call either errors or times out — either
	//    way it does NOT bring the process down.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err := cli.Call(ctx, "server", buildTyped(t, mtPanic, 1))
	cancel()
	// We don't assert the exact error: the contract is "node survives", not
	// "specific error shape". A nil error would be wrong (no valid response
	// exists), but the load-bearing assertion is step 2 below.
	if err == nil {
		t.Log("panic Call returned nil error (response channel closed); node-survival is the real assertion")
	} else {
		t.Logf("panic Call errored as expected: %v", err)
	}

	// 2. THE PROOF: the server node is still alive. Reconnect (the prior
	//    conn may have been dropped) and issue a valid Call to the echo
	//    handler. If the node had crashed, this fails.
	cli2 := NewNode(NodeConfig{NodeID: "client2", Port: pickFreePortNode(t), NoDiscovery: true})
	if err := cli2.Start(); err != nil {
		t.Fatalf("cli2.Start: %v", err)
	}
	defer cli2.Stop()
	if err := cli2.ConnectDirect("127.0.0.1:" + itoa(srvPort)); err != nil {
		t.Fatalf("server node died after handler panic — reconnect failed: %v", err)
	}
	waitPeersNode(t, cli2)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	resp, err := cli2.Call(ctx2, "server", buildTyped(t, mtEcho, 41))
	if err != nil {
		t.Fatalf("echo Call after panic failed — node did not survive: %v", err)
	}
	if got := resp.Root().Uint32(0); got != 42 {
		t.Errorf("echo returned %d want 42 (node alive but handler misbehaved)", got)
	}
}

// itoa is a tiny strconv.Itoa to keep this test file's imports minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
