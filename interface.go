// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// InProcessInterface is the cost-0 interface: it delivers to destinations that
// live in THIS address space by calling their handler directly. No serialization,
// no copy, no socket, no loopback TCP — a call is a call. It is the primitive
// behind "if the sink is in my own binary, don't touch the network."
//
// A Payload's live Value is handed straight to the LocalHandler; the payload's
// Encode (the wire form) is never invoked on this path, so an in-process delivery
// pays nothing for encoding. When sender and receiver are folded into one binary
// (the unified-cloud monolith), this is the interface that always wins the Cost
// race, and the ZAP wire never enters the picture.
type InProcessInterface struct {
	mu       sync.RWMutex
	handlers map[Destination]LocalHandler
}

// NewInProcessInterface returns an empty in-process interface. Register the
// destinations this binary serves onto it, then Register it on a Router.
func NewInProcessInterface() *InProcessInterface {
	return &InProcessInterface{handlers: make(map[Destination]LocalHandler)}
}

// Register binds a destination (capability aspect) to a local handler. Calling it
// again for the same dst replaces the handler (last writer wins) — a subsystem
// re-mounting its sink is idempotent. A nil handler unregisters the destination
// so CanReach falls through to the next (network) interface.
func (p *InProcessInterface) Register(dst Destination, h LocalHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h == nil {
		delete(p.handlers, dst)
		return
	}
	p.handlers[dst] = h
}

// Name identifies this interface.
func (p *InProcessInterface) Name() string { return "inprocess" }

// Cost is 0 — a same-address-space handoff is the cheapest possible delivery, so
// Router prefers it over every wire interface whenever the dst is local.
func (p *InProcessInterface) Cost() int { return 0 }

// CanReach reports whether dst has a handler registered in THIS process.
func (p *InProcessInterface) CanReach(dst Destination) bool {
	p.mu.RLock()
	_, ok := p.handlers[dst]
	p.mu.RUnlock()
	return ok
}

// Deliver dispatches the live payload to the local handler. The sender identity
// is left empty for a same-process call (the caller is us); a handler that needs
// provenance reads it from the Payload.Value it defines. Returns the handler's
// reply Payload (nil-Value ⇒ none).
func (p *InProcessInterface) Deliver(ctx context.Context, dst Destination, pl Payload) (Payload, error) {
	p.mu.RLock()
	h, ok := p.handlers[dst]
	p.mu.RUnlock()
	if !ok {
		// CanReach guards this; a lost race (handler unregistered between the
		// two calls) is reported honestly rather than silently dropped.
		return Payload{}, fmt.Errorf("zap: in-process destination %q not registered", dst)
	}
	return h(ctx, "", pl)
}

// NodeInterface adapts the existing *Node (TCP/QUIC + conn_pq PQ session + mDNS
// discovery) to the Interface seam, WITHOUT changing Node. It is the network
// fallback: whenever a destination is not served in-process, Router routes here
// and the Node discovers/dials the peer and ships the ZAP wire Message.
//
// This is where the wire actually happens — and ONLY here. The Payload's live
// Value never crosses a socket; Deliver calls Payload.Encode() to materialize the
// zero-copy Message exactly once, at the moment a network hop is unavoidable.
//
// P1 scope: one-way delivery (Node.Send) — sufficient for telemetry and event
// fan-out, which is what folds first. Request/reply over the wire (Node.Call) and
// announce-driven multi-hop reachability are P2 refinements that slot in behind
// this same Interface without moving the Router.Send call site.
type NodeInterface struct {
	node *Node
	cost int
	// connectedOnly restricts CanReach to peers with a live connection. Default
	// (false) is optimistic: the interface is the network catch-all and lets
	// Node.Send discover+dial on demand, surfacing a real error if the peer is
	// genuinely unreachable rather than silently declining the route.
	connectedOnly bool
}

// compile-time proof the interfaces satisfy the seam.
var (
	_ Interface = (*InProcessInterface)(nil)
	_ Interface = (*NodeInterface)(nil)
)

// DefaultNodeCost is the Cost of a LAN/cluster TCP hop — above in-process (0) and
// same-host IPC (1), below multi-hop routed (100+).
const DefaultNodeCost = 10

// NewNodeInterface wraps n as the network interface at DefaultNodeCost.
func NewNodeInterface(n *Node) *NodeInterface {
	return &NodeInterface{node: n, cost: DefaultNodeCost}
}

// WithCost overrides the interface cost (e.g. a metered/slow link ranks higher).
func (i *NodeInterface) WithCost(c int) *NodeInterface { i.cost = c; return i }

// ConnectedOnly makes CanReach report true only for already-connected peers,
// turning the interface from an optimistic catch-all into a strict "route only
// where a session already exists" interface. Useful when a higher-cost interface
// should own first-contact.
func (i *NodeInterface) ConnectedOnly() *NodeInterface { i.connectedOnly = true; return i }

// Name identifies this interface.
func (i *NodeInterface) Name() string { return "node-tcp" }

// Cost ranks this interface (default DefaultNodeCost).
func (i *NodeInterface) Cost() int { return i.cost }

// CanReach reports whether the Node can deliver to dst. Optimistic by default (the
// network catch-all); strict when ConnectedOnly is set.
func (i *NodeInterface) CanReach(dst Destination) bool {
	if i.node == nil {
		return false
	}
	if !i.connectedOnly {
		return true // catch-all: let Deliver discover+dial and error honestly
	}
	for _, p := range i.node.Peers() {
		if p == string(dst) {
			return true
		}
	}
	return false
}

// ErrNotEncodable is returned when a network interface is asked to deliver a
// payload that carries no wire form (Encode == nil) — an in-process-only value
// that must not silently cross a socket.
var ErrNotEncodable = errors.New("zap: payload has no wire encoding (in-process only)")

// Deliver ships the payload to dst (peer ID) over the Node's ZAP wire. It
// materializes the wire Message lazily — the encode cost is paid here and nowhere
// else — then hands it to Node.Send. A nil Encode is a hard error, never a silent
// drop: an in-process-only payload reaching the wire is a routing bug.
func (i *NodeInterface) Deliver(ctx context.Context, dst Destination, p Payload) (Payload, error) {
	if p.Encode == nil {
		return Payload{}, ErrNotEncodable
	}
	if err := i.node.Send(ctx, string(dst), p.Encode()); err != nil {
		return Payload{}, err
	}
	return Payload{}, nil // one-way delivery; no reply in P1
}
