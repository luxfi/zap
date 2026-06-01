// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Two-node end-to-end integration that drives Node.ConnectDirect,
// Node.handleConn (both Call and Send paths), Node.Call request/
// response correlation, and Node.Broadcast.

package zap

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Per the dispatcher: msgType = msg.Flags() >> 8.
const testMsgType uint16 = 0x42
const testMsgFlags uint16 = testMsgType << 8

func TestCoverage_TwoNodeFullFlow(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)

	a := NewNode(NodeConfig{NodeID: "A-node", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "B-node", Port: portB, NoDiscovery: true})

	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	// Register handler on B that echoes.
	var calls atomic.Int32
	b.Handle(testMsgType, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		calls.Add(1)
		// Echo the inbound bytes (a valid ZAP message).
		return msg, nil
	})

	// Also register on A so Broadcast can land somewhere on B's side.
	a.Handle(testMsgType, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		calls.Add(1)
		return nil, nil
	})

	// A connects to B.
	addrB := "127.0.0.1:" + strconv.Itoa(portB)
	if err := a.ConnectDirect(addrB); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}

	// Give the handshake exchange a moment.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(a.Peers()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(a.Peers()) == 0 {
		t.Fatal("A still has no peers after 2s")
	}

	// Build a ZAP message tagged with our msgType in Flags.
	bld := NewBuilder(64)
	ob := bld.StartObject(4)
	ob.SetUint32(0, 0xC0FFEE)
	ob.FinishAsRoot()
	msg := &Message{data: bld.FinishWithFlags(testMsgFlags)}

	// Call B from A — drives WrapCorrelated → handleConn's ReqFlagReq
	// path → handler → WrapCorrelated(ReqFlagResp) → ReqFlagResp path.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := a.Call(ctx, "B-node", msg)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response from Call")
	}

	// Wait for the handler to have run.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && calls.Load() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 1 {
		t.Fatal("handler never invoked")
	}

	// Send (no correlation) — drives the regular-message path in
	// handleConn.
	sendCtx, sendCancel := context.WithTimeout(context.Background(), time.Second)
	defer sendCancel()
	if err := a.Send(sendCtx, "B-node", msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Broadcast from A — drives Broadcast goroutine fan-out.
	bcCtx, bcCancel := context.WithTimeout(context.Background(), time.Second)
	defer bcCancel()
	results := a.Broadcast(bcCtx, msg)
	if _, ok := results["B-node"]; !ok {
		t.Fatalf("Broadcast results missing B-node: %v", results)
	}

	// Give B a moment to process the Send + Broadcast messages.
	time.Sleep(100 * time.Millisecond)
}

// TestCoverage_DuplicateConnectionRejected drives the
// duplicate-detection path inside handleConn (both pre- and
// post-handshake checks).
func TestCoverage_DuplicateConnectionRejected(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)
	a := NewNode(NodeConfig{NodeID: "DupA", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "DupB", Port: portB, NoDiscovery: true})
	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	addrB := "127.0.0.1:" + strconv.Itoa(portB)
	if err := a.ConnectDirect(addrB); err != nil {
		t.Fatalf("first connect: %v", err)
	}

	// Wait for peer registration.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(a.Peers()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Re-connect: duplicate detection wins one of two ways —
	//   (a) A's local "already in conns" check returns nil
	//   (b) B closes the conn before sending its handshake response → A sees EOF
	// Both are correct duplicate-rejection behaviours; just confirm
	// no panic and the connection count stayed at 1.
	_ = a.ConnectDirect(addrB)
	if len(a.Peers()) != 1 {
		t.Fatalf("duplicate connect should leave 1 peer, got %d", len(a.Peers()))
	}
}

// TestCoverage_NodeStopClosesConns: Stop with active conns drives
// the close-all-conns branch in Stop().
func TestCoverage_NodeStopClosesConns(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)
	a := NewNode(NodeConfig{NodeID: "StopA", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "StopB", Port: portB, NoDiscovery: true})
	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	if err := a.ConnectDirect("127.0.0.1:" + strconv.Itoa(portB)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	// Wait for the registration.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(a.Peers()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	// Stop with active connections.
	a.Stop()
}

// TestCoverage_ConnectDirectInvalidPeer drives the "invalid peer
// handshake" branch — peer sends garbage instead of a NodeID
// handshake message.
func TestCoverage_ConnectDirectInvalidPeer(t *testing.T) {
	// Spin a listener that responds with a bogus message.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read whatever, then send a length-prefixed message that
		// won't parse as a NodeID handshake (length=16, all-zero body).
		var hello [HeaderSize + 64]byte
		_, _ = c.Read(hello[:])
		bad := WrapCorrelated(0, ReqFlagReq, []byte{0xFF, 0xFF, 0xFF, 0xFF}) // not a NodeID
		_ = writeMessage(c, bad)
	}()

	n := NewNode(NodeConfig{NodeID: "client", NoDiscovery: true})
	err = n.ConnectDirect(ln.Addr().String())
	if err == nil {
		t.Fatal("ConnectDirect should fail on invalid peer handshake")
	}
	wg.Wait()
}

func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
