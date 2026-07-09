// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"errors"
	"testing"
)

// recordingIface is a test double standing in for a network interface, so the
// routing logic is exercised without opening a socket.
type recordingIface struct {
	name      string
	cost      int
	reachable bool
	delivered *Payload
}

func (r *recordingIface) Name() string              { return r.name }
func (r *recordingIface) Cost() int                 { return r.cost }
func (r *recordingIface) CanReach(Destination) bool { return r.reachable }
func (r *recordingIface) Deliver(_ context.Context, _ Destination, p Payload) (Payload, error) {
	r.delivered = &p
	return Payload{}, nil
}

// The core P1 contract: when the destination lives in this process, the in-process
// interface (cost 0) wins over the network interface (cost 10) AND the payload is
// delivered as the LIVE native value — Encode is never called, so nothing is
// serialized and no socket is touched. This is "skip TCP when in-process", proven.
func TestRouter_InProcessPreferredAndZeroSerialize(t *testing.T) {
	tr := NewRouter()
	net := &recordingIface{name: "net", cost: 10, reachable: true}
	tr.Register(net)

	inproc := NewInProcessInterface()
	var got any
	inproc.Register("hanzo.o11y.traces", func(_ context.Context, _ Destination, p Payload) (Payload, error) {
		got = p.Value
		return Payload{}, nil
	})
	tr.Register(inproc)

	encodeCalled := false
	pl := Payload{
		Value:  "SPANS",
		Encode: func() *Message { encodeCalled = true; return nil },
	}
	if _, err := tr.Send(context.Background(), "hanzo.o11y.traces", pl); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got != "SPANS" {
		t.Fatalf("in-process handler got %v, want the native value SPANS", got)
	}
	if encodeCalled {
		t.Fatal("Encode was called on the in-process path — serialization must be skipped")
	}
	if net.delivered != nil {
		t.Fatal("network interface was used though the dst is in-process (cost routing broken)")
	}
}

// When the destination is NOT served in-process, the router falls through to the
// network interface.
func TestRouter_FallsBackToNetwork(t *testing.T) {
	tr := NewRouter()
	net := &recordingIface{name: "net", cost: 10, reachable: true}
	tr.Register(net)
	tr.Register(NewInProcessInterface()) // no local handlers

	pl := Payload{Value: 1, Encode: func() *Message { return nil }}
	if _, err := tr.Send(context.Background(), "remote.peer", pl); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if net.delivered == nil {
		t.Fatal("network interface not used for a non-local dst")
	}
}

// No interface can reach the destination ⇒ ErrNoRoute, never a panic or silent drop.
func TestRouter_NoRoute(t *testing.T) {
	tr := NewRouter()
	tr.Register(NewInProcessInterface())
	if _, err := tr.Send(context.Background(), "nowhere", Payload{}); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("want ErrNoRoute, got %v", err)
	}
}

// Register keeps the interface set sorted ascending by cost so Send stops at the
// cheapest reachable one.
func TestRouter_RegisterSortsByCost(t *testing.T) {
	tr := NewRouter()
	tr.Register(&recordingIface{name: "b", cost: 10, reachable: true})
	tr.Register(&recordingIface{name: "a", cost: 0, reachable: true})
	ifaces := tr.Interfaces()
	if ifaces[0].Name() != "a" || ifaces[1].Name() != "b" {
		t.Fatalf("interfaces not sorted by cost: got %s, %s", ifaces[0].Name(), ifaces[1].Name())
	}
}

// Re-registering a destination replaces its handler; a nil handler unregisters it.
func TestInProcess_ReregisterAndUnregister(t *testing.T) {
	p := NewInProcessInterface()
	p.Register("d", func(context.Context, Destination, Payload) (Payload, error) { return Payload{}, nil })
	if !p.CanReach("d") {
		t.Fatal("dst should be reachable after Register")
	}
	p.Register("d", nil)
	if p.CanReach("d") {
		t.Fatal("dst should be unreachable after nil-handler unregister")
	}
}

// A network interface must refuse an in-process-only payload (no wire form) rather
// than silently drop it — a routing bug should surface as an error.
func TestNodeInterface_NilEncodeRejected(t *testing.T) {
	ni := NewNodeInterface(nil)
	if _, err := ni.Deliver(context.Background(), "peer", Payload{Value: 1}); !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("want ErrNotEncodable, got %v", err)
	}
}

// The optimistic (default) NodeInterface is the network catch-all: it claims to
// reach any destination and lets delivery discover+dial, so it always sits behind
// the in-process interface as the fallback.
func TestNodeInterface_OptimisticCatchAll(t *testing.T) {
	ni := NewNodeInterface(NewNode(NodeConfig{NodeID: "self"}))
	if !ni.CanReach("any.peer") {
		t.Fatal("optimistic NodeInterface should report CanReach for any dst")
	}
	if ni.ConnectedOnly().CanReach("any.peer") {
		t.Fatal("ConnectedOnly NodeInterface should not reach an unconnected peer")
	}
}
