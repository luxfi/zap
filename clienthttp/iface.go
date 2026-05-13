// iface.go — small, orthogonal interfaces that compose into the
// clienthttp transport.
//
// Three concerns, three interfaces:
//
//   - Discovery: what peers exist for a service type, right now.
//   - Picker:    given a peer snapshot, choose one for this request.
//   - Dialer:    given a chosen peer address, return an
//                http.RoundTripper that speaks to it.
//
// NewClient composes them; each can be swapped independently:
//
//   - Tests inject FakeDiscovery + FakeDialer for hermetic unit tests.
//   - Production layers swap Dialer (zap-proto/http today, raw ZAP
//     RPC tomorrow) without touching discovery / picking.
//   - Locality-aware policies replace Picker without touching the
//     transport or discovery.
//
// The concrete ZAP-HTTP + mDNS combo is wired in clienthttp.go as
// the default factory. This file defines only the contracts.

package clienthttp

import (
	"context"
	"net/http"
	"time"
)

// Peer is the discovery view of one reachable instance of a service.
//
// Address is the dial target ("host:port"). Metadata carries optional
// hints (zone, version, capabilities) — implementations choose what
// to surface. NodeID uniquely identifies the peer within ServiceType
// across discovery cycles so callers can correlate sticky-routing
// decisions.
type Peer struct {
	NodeID      string
	ServiceType string
	Address     string
	Metadata    map[string]string
	LastSeen    time.Time
}

// Discovery is the peer-enumeration contract.
//
// Implementations MUST be goroutine-safe; clienthttp may call Peers()
// from every in-flight RoundTrip and from background reconciliation.
// PeerCount() is a hot-path helper for waitForPeers and similar
// gating logic; it MUST return cheap snapshot semantics, not require
// a network probe.
type Discovery interface {
	// Peers returns the current peer snapshot. Order is implementation-
	// defined; consumers MUST NOT mutate the returned slice.
	Peers() []Peer

	// PeerCount returns len(Peers()) cheaply.
	PeerCount() int

	// ServiceType reports the service the Discovery is browsing.
	ServiceType() string

	// Start begins the discovery loop. Calling Start twice on the same
	// Discovery is a programmer error.
	Start() error

	// Stop releases all resources. Idempotent.
	Stop()
}

// Picker selects one peer from a Discovery snapshot.
//
// Pick is called once per RoundTrip; implementations MUST be cheap
// (sub-microsecond) and goroutine-safe.
type Picker interface {
	// Pick returns the chosen peer. ErrNoPeers if peers is empty.
	Pick(peers []Peer) (Peer, error)
}

// Dialer returns an http.RoundTripper that talks to one peer.
//
// The returned RoundTripper SHOULD be cached per address so the
// underlying transport's connection pool gets reused. clienthttp's
// default transport handles caching internally; custom Dialers MAY
// cache or return fresh RoundTrippers as appropriate.
type Dialer interface {
	// Dial returns a RoundTripper speaking to peer.Address. The
	// returned RoundTripper is goroutine-safe and reusable.
	Dial(ctx context.Context, peer Peer) (http.RoundTripper, error)
}

// AuthAttacher injects per-call authentication onto outgoing
// requests. It runs after Picker selects the peer but before the
// RoundTrip itself, so the chosen peer can influence which credential
// gets attached (e.g. local-trust skips the bearer, cross-cluster
// uses a different key).
//
// Implementations MUST NOT block — set headers and return. Network
// I/O belongs in the Dialer's RoundTripper, not the AuthAttacher.
type AuthAttacher interface {
	// Attach mutates req in place. A non-nil error aborts the
	// RoundTrip — surface this rather than silently dropping auth.
	Attach(req *http.Request, peer Peer) error
}
