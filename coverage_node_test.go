// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage for Node accessors and lifecycle: NodeID, Start with
// NoDiscovery, Stop, getOrConnect nil-discovery branch, Conn.Send /
// Conn.Recv on an in-memory pipe, writeMessage / readMessage round
// trip, handlePeerEvent with both joined+lost.

package zap

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/mdns"
)

// TestCoverage_NodeIDAccessor drives Node.NodeID (node.go:283).
func TestCoverage_NodeIDAccessor(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "alpha", NoDiscovery: true})
	if n.NodeID() != "alpha" {
		t.Fatalf("NodeID = %q", n.NodeID())
	}
}

// TestCoverage_NodeStartStopNoDiscovery drives Start (no-discovery
// branch) and verifies post-Start state: NodeID accessor returns
// the configured ID, listener is actually accepting (we dial it),
// and post-Stop the listener no longer accepts.
func TestCoverage_NodeStartStopNoDiscovery(t *testing.T) {
	// Pick a deterministic free port so we can dial it specifically.
	port := pickFreePort(t)
	n := NewNode(NodeConfig{NodeID: "n1", Port: port, NoDiscovery: true})
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if n.NodeID() != "n1" {
		t.Fatalf("NodeID = %q, want n1", n.NodeID())
	}

	// Verify the listener is up by dialing it.
	addr := "127.0.0.1:" + strconv.Itoa(port)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("listener should accept post-Start: %v", err)
	}
	_ = c.Close()

	n.Stop()

	// Post-Stop the listener should be closed; dial should fail.
	if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		t.Fatal("listener should refuse post-Stop")
	}
}

// TestCoverage_NodeSendNoDiscovery drives getOrConnect's nil-
// discovery branch (the M-3-equivalent nil-deref guard we added to
// node.go:540).
func TestCoverage_NodeSendNoDiscovery(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "n2", Port: 0, NoDiscovery: true})
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Stop()

	err := n.Send(context.Background(), "nonexistent-peer", &Message{data: []byte{}})
	if err == nil {
		t.Fatal("Send to unknown peer should fail")
	}
	if !strings.Contains(err.Error(), "peer not found") &&
		!strings.Contains(err.Error(), "discovery unavailable") {
		t.Fatalf("error %v should mention peer not found / discovery unavailable", err)
	}
}

// TestCoverage_NodeBroadcastEmpty drives Broadcast on a node with
// no peers (covers the early-return branch).
func TestCoverage_NodeBroadcastEmpty(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "n3", Port: 0, NoDiscovery: true})
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Stop()

	results := n.Broadcast(context.Background(), &Message{data: []byte{}})
	if len(results) != 0 {
		t.Fatalf("Broadcast with no peers returned %d results", len(results))
	}
	if peers := n.Peers(); len(peers) != 0 {
		t.Fatalf("Peers() = %v on fresh node", peers)
	}
}

// TestCoverage_NodeHandleRegistersAndOverwrites verifies the
// handlers map round-trip — two registrations on the same type
// MUST overwrite (last writer wins), and the handler stored is the
// one we registered.
func TestCoverage_NodeHandleRegistersAndOverwrites(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "n4", Port: 0, NoDiscovery: true})

	var hits []string
	n.Handle(0x01, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		hits = append(hits, "first")
		return nil, nil
	})
	// Verify it's in the map.
	n.handlersMu.RLock()
	h1, ok1 := n.handlers[0x01]
	n.handlersMu.RUnlock()
	if !ok1 {
		t.Fatal("first handler missing")
	}
	_, _ = h1(context.Background(), "peer", &Message{})
	if len(hits) != 1 || hits[0] != "first" {
		t.Fatalf("first invocation hits=%v", hits)
	}

	// Overwrite with a second handler.
	n.Handle(0x01, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		hits = append(hits, "second")
		return nil, nil
	})
	n.handlersMu.RLock()
	h2 := n.handlers[0x01]
	n.handlersMu.RUnlock()
	_, _ = h2(context.Background(), "peer", &Message{})
	if len(hits) != 2 || hits[1] != "second" {
		t.Fatalf("after overwrite hits=%v, want [first, second]", hits)
	}
}

// TestCoverage_HandlePeerEventBothBranches: joined=true with higher
// local ID MUST NOT initiate a connect (no conn added); joined=false
// against an absent peer MUST NOT panic and MUST leave the conns map
// unchanged.
func TestCoverage_HandlePeerEventBothBranches(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "z-highest", Port: 0, NoDiscovery: true})
	peer := &mdns.Peer{NodeID: "a-lower", Addr: "127.0.0.1", Port: 1, LastSeen: time.Now()}

	n.handlePeerEvent(peer, true)
	// Lower-NodeID peer joined; OUR ID is HIGHER, so we wait for them
	// to dial us. Conns map should still be empty.
	if c := len(n.Peers()); c != 0 {
		t.Fatalf("conns map should stay empty when local ID > peer ID, got %d", c)
	}

	n.handlePeerEvent(peer, false)
	// Lost peer that we never had; conns map still empty.
	if c := len(n.Peers()); c != 0 {
		t.Fatalf("conns map should stay empty after lost-but-absent, got %d", c)
	}
}

// TestCoverage_HandlePeerEventInitiatesConnect drives the
// joined=true + nodeID<peer.NodeID branch which spawns a connect
// goroutine via ConnectDirect. We stand up a real listener on the
// target address that ACCEPTS one connection — then verify that a
// connection arrived (the goroutine actually executed ConnectDirect).
func TestCoverage_HandlePeerEventInitiatesConnect(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "a-low", Port: 0, NoDiscovery: true})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	gotConn := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Send the peer's handshake response so ConnectDirect can
		// complete its decode (or fail at handshake).
		_, _ = writeMessageBytes(c, EncodeNodeIDHandshake("z-high"))
		_ = c.Close()
		select {
		case gotConn <- struct{}{}:
		default:
		}
	}()

	peer := &mdns.Peer{NodeID: "z-high", Addr: addr.IP.String(), Port: addr.Port, LastSeen: time.Now()}
	n.handlePeerEvent(peer, true)

	select {
	case <-gotConn:
		// good — the goroutine actually dialed
	case <-time.After(2 * time.Second):
		t.Fatal("handlePeerEvent did not initiate connect within 2s")
	}
}

// writeMessageBytes is a small wrapper so the test doesn't depend
// on the internal writeMessage signature drifting.
func writeMessageBytes(w net.Conn, data []byte) (int, error) {
	if err := writeMessage(w, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// TestCoverage_HandlePeerEventConnectedThenLost drives joined=false
// when the peer DOES exist in our conns map — exercises the close +
// delete branch.
func TestCoverage_HandlePeerEventConnectedThenLost(t *testing.T) {
	n := NewNode(NodeConfig{NodeID: "alpha", Port: 0, NoDiscovery: true})
	// Plant a fake conn for peerID "beta".
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c2.Close() })
	n.connsMu.Lock()
	n.conns["beta"] = &Conn{NodeID: "beta", Addr: "fake", conn: c1}
	n.connsMu.Unlock()

	peer := &mdns.Peer{NodeID: "beta", Addr: "127.0.0.1", Port: 1, LastSeen: time.Now()}
	n.handlePeerEvent(peer, false)

	n.connsMu.RLock()
	_, stillThere := n.conns["beta"]
	n.connsMu.RUnlock()
	if stillThere {
		t.Fatal("handlePeerEvent(joined=false) should have deleted the conn")
	}
}

// TestCoverage_ConnSendRecvOverPipe drives Conn.Send / Conn.Recv /
// writeMessage / readMessage by piping a small message through.
func TestCoverage_ConnSendRecvOverPipe(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Build a minimal valid ZAP message.
	bld := NewBuilder(0)
	ob := bld.StartObject(4)
	ob.SetUint32(0, 0xCAFEBABE)
	ob.FinishAsRoot()
	data := bld.Finish()

	connA := &Conn{NodeID: "A", conn: a}
	connB := &Conn{NodeID: "B", conn: b}

	done := make(chan error, 1)
	go func() {
		msg, err := connB.Recv()
		if err != nil {
			done <- err
			return
		}
		if msg.Root().Uint32(0) != 0xCAFEBABE {
			done <- &errStr{"payload mismatch"}
			return
		}
		done <- nil
	}()

	if err := connA.Send(&Message{data: data}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Recv: %v", err)
	}
}

type errStr struct{ s string }

func (e *errStr) Error() string { return e.s }
