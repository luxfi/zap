// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// Router is ZAP's locality-adaptive router: ONE Send API over many interfaces.
//
// The complected thing in classic RPC is `Send(host:port, msg)` — WHO you are
// talking to, HOW the bytes travel, and WHERE the peer lives are braided into a
// single address. Router pulls them apart (Reticulum's model, made
// post-quantum and zero-copy):
//
//   - Destination — WHO/WHAT (a capability aspect, later a PQ-identity hash).
//   - Interface   — HOW one hop travels (in-process memory, TCP, UDP, radio…).
//   - Payload     — the message, dual-form so each medium pays only for itself.
//   - Router      — routes: the cheapest Interface that can currently reach dst.
//
// "If in-process, skip TCP; else use the network" is therefore NOT a branch any
// caller writes — it is the Cost table (InProcess 0 < UDS 1 < TCP 10 < routed
// 100+). A caller only ever says:
//
//	router.Send(ctx, dst, payload)
//
// and never names a port or a transport again. Router is distinct from the
// wire-level Transport enum (TransportTCP/TransportQUIC), which selects HOW one
// Node's socket speaks; a NodeInterface adapts such a Node into this router.
type Router struct {
	mu     sync.RWMutex
	ifaces []Interface // kept sorted ascending by Cost()
}

// Destination names WHO/WHAT a message is for, decoupled from HOW it is reached.
// In P1 it is a dotted capability aspect ("hanzo.o11y.traces"); the announce-
// routed PQ-identity destination hash (multi-hop) refines this in the transport
// HIP WITHOUT changing this call site — that is the whole point of the seam.
type Destination string

// Payload is the value a Router delivers. It is deliberately dual-form so the
// interface the router picks pays only for what that medium needs:
//
//   - Value is the LIVE native value. The in-process interface hands it to the
//     local handler by pointer — zero serialization, zero copy, zero TCP. This
//     is the "skip the wire entirely when we share an address space" fast path.
//   - Encode lazily produces the zero-copy wire Message; a NETWORK interface
//     calls it (and only then, so an in-process delivery never encodes). A nil
//     Encode means the payload is in-process-only and cannot cross a wire.
type Payload struct {
	Value  any
	Encode func() *Message
}

// LocalHandler consumes a Payload delivered IN-PROCESS. It receives the live
// Value (type-assert to the concrete type the aspect defines) and may return a
// reply Payload (nil Value ⇒ no reply). This is the handler an InProcessInterface
// dispatches to — distinct from Node's wire Handler, which decodes bytes first.
type LocalHandler func(ctx context.Context, from Destination, p Payload) (Payload, error)

// Interface moves a Payload one hop toward a Destination over a single medium.
// Interfaces are ranked by Cost; Router always prefers the cheapest one that
// can currently reach the destination. Implementations are the ONLY place a
// transport detail (a socket, a serial line, a memory handoff) lives.
type Interface interface {
	// Name identifies the interface for logs/metrics ("inprocess", "node-tcp").
	Name() string
	// Cost ranks interfaces; lower is preferred. Convention: in-process 0,
	// same-host IPC 1, LAN/cluster TCP 10, multi-hop routed 100+.
	Cost() int
	// CanReach reports whether this interface can deliver to dst RIGHT NOW
	// (destination registered locally, peer connected/discovered, path known).
	CanReach(dst Destination) bool
	// Deliver hands the payload to dst over this medium and returns an optional
	// reply (nil-Value Payload ⇒ none). It must not be called unless CanReach.
	Deliver(ctx context.Context, dst Destination, p Payload) (Payload, error)
}

// ErrNoRoute is returned when no registered interface can reach the destination.
var ErrNoRoute = errors.New("zap: no interface can reach destination")

// NewRouter returns an empty Router. Register interfaces onto it; the cheapest
// reachable one wins per Send. A Router with no interfaces routes nothing (Send
// returns ErrNoRoute) — safe, never panics.
func NewRouter() *Router { return &Router{} }

// Register adds an interface, keeping the set sorted ascending by Cost so Send is
// a linear scan that stops at the first (cheapest) interface that CanReach. Ties
// keep registration order (stable), so an earlier-registered interface of equal
// cost is preferred.
func (t *Router) Register(i Interface) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ifaces = append(t.ifaces, i)
	sort.SliceStable(t.ifaces, func(a, b int) bool {
		return t.ifaces[a].Cost() < t.ifaces[b].Cost()
	})
}

// Interfaces returns a snapshot of the registered interfaces, cheapest first.
func (t *Router) Interfaces() []Interface {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Interface, len(t.ifaces))
	copy(out, t.ifaces)
	return out
}

// Send routes payload to dst over the cheapest interface that can reach it. It is
// the whole public contract: the caller expresses intent (dst + payload) and the
// locality decision (memory vs. wire) is the router's, made from the live Cost/
// CanReach table — never the caller's branch. Returns ErrNoRoute if nothing can
// currently reach dst.
func (t *Router) Send(ctx context.Context, dst Destination, p Payload) (Payload, error) {
	t.mu.RLock()
	ifaces := t.ifaces // slice header copy under lock; entries are immutable
	t.mu.RUnlock()
	for _, i := range ifaces {
		if i.CanReach(dst) {
			return i.Deliver(ctx, dst, p)
		}
	}
	return Payload{}, ErrNoRoute
}
