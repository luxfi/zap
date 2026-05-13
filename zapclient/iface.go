// Package zapclient — native ZAP client + server with mDNS discovery.
//
// ZAP is its own binary protocol — NOT layered on HTTP. This package
// wraps lux/zap's Node with procedure-name dispatch and discovery
// helpers so service-to-service callers can write:
//
//   client := zapclient.MustConnect(ctx, "liquidity-ta")
//   defer client.Close()
//   resp, err := client.Call(ctx, "ListSecurity", req)
//
// instead of the lower-level (opcode, peerID, *zap.Message) loop.
//
// For browser/web clients use zapsse (separate package): ZAP over
// Server-Sent Events. Optional WebSocket support is offered when SSE
// is unsuitable. HTTP/REST is reserved for the public-edge Ingress.

package zapclient

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Callers branch via errors.Is.
var (
	// ErrNoPeers is returned when discovery has no live peer for the
	// requested service type.
	ErrNoPeers = errors.New("zapclient: no peers discovered")

	// ErrUnknownProcedure is returned by the server when an incoming
	// opcode does not match any Register call.
	ErrUnknownProcedure = errors.New("zapclient: unknown procedure")

	// ErrPeerUnauthorized is returned when PeerVerifier refuses the
	// incoming peer. Maps to a transport-layer reject.
	ErrPeerUnauthorized = errors.New("zapclient: peer unauthorized")

	// ErrCallTimeout is returned by Call when the per-call deadline
	// elapses before the response arrives.
	ErrCallTimeout = errors.New("zapclient: call timed out")
)

// Peer is the discovery view of one reachable instance of a service.
//
// NodeID uniquely identifies the peer within ServiceType across
// discovery cycles. Address is the dial target (host:port). For
// in-cluster peers under mTLS, the authenticated peer identity comes
// from the TLS session — NodeID is a hint, not a trust anchor.
type Peer struct {
	NodeID      string
	ServiceType string
	Address     string
	Metadata    map[string]string
	LastSeen    time.Time
}

// Discovery is the peer-enumeration contract.
//
// Implementations MUST be goroutine-safe; the client may call Peers()
// from every in-flight Call and Send.
type Discovery interface {
	// Peers returns the current peer snapshot. The returned slice is
	// freshly allocated; callers may retain it.
	Peers() []Peer

	// PeerCount returns len(Peers()) cheaply.
	PeerCount() int

	// ServiceType reports the service the Discovery is browsing.
	ServiceType() string

	// Start begins the discovery loop. Calling Start twice on the
	// same Discovery is a programmer error.
	Start() error

	// Stop releases all resources. Idempotent.
	Stop()
}

// Picker selects one peer from a Discovery snapshot for a single
// Call or Send. Implementations MUST be cheap (sub-microsecond) and
// goroutine-safe; the client invokes Pick from every concurrent op.
type Picker interface {
	// Pick returns the chosen peer. ErrNoPeers if peers is empty.
	Pick(peers []Peer) (Peer, error)
}

// PeerVerifier is the server-side authorisation hook. Runs on every
// inbound message before procedure dispatch — return non-nil to
// reject the call.
//
// The PeerInfo carries the authenticated peer identity (NodeID +
// mTLS cert chain if present). Procedure is the procedure name the
// caller requested. PeerVerifier should compare the (peer, procedure)
// pair against the service's authorisation policy.
type PeerVerifier interface {
	// Verify returns nil on accept, ErrPeerUnauthorized (or wrapping
	// error) on reject. Implementations MUST NOT block — refer to
	// pre-built decision tables, not network calls.
	Verify(ctx context.Context, peer PeerInfo, procedure string) error
}

// PeerInfo is the authenticated peer identity surfaced to server-side
// handlers and PeerVerifier.
type PeerInfo struct {
	NodeID      string
	ServiceType string
	// TLSCertSubject is the Subject CN of the mTLS peer cert, when
	// the listener was configured with TLS. Empty under plaintext
	// (local-dev) transport.
	TLSCertSubject string
	// TLSCertSANs are the Subject Alternative Names from the peer
	// cert. Authorisation should prefer SANs over the legacy CN.
	TLSCertSANs []string
}

// LocalTrustVerifier accepts any peer presenting a valid mTLS cert
// from the cluster CA. The underlying TLS handshake already verified
// the chain; this verifier returns nil for every authenticated peer.
//
// Use when:
//   - the peer is on the cluster-private network
//   - the listener was constructed with the cluster CA in ClientCAs
//   - all in-cluster services should be allowed to call all
//     procedures (apply per-procedure RBAC in the handler if needed)
type LocalTrustVerifier struct{}

// Verify accepts any authenticated peer.
func (LocalTrustVerifier) Verify(ctx context.Context, peer PeerInfo, procedure string) error {
	if peer.NodeID == "" && peer.TLSCertSubject == "" {
		// Plaintext + no NodeID is a programmer error — reject.
		return ErrPeerUnauthorized
	}
	return nil
}

// AllowListVerifier accepts only peers whose NodeID appears in
// Allowed[procedure]. Empty Allowed[procedure] means the procedure is
// not exposed.
type AllowListVerifier struct {
	// Allowed maps procedure name → set of NodeIDs permitted to call
	// it. Empty set = procedure disabled.
	Allowed map[string]map[string]struct{}
}

// Verify accepts if NodeID is in Allowed[procedure].
func (a AllowListVerifier) Verify(ctx context.Context, peer PeerInfo, procedure string) error {
	if a.Allowed == nil {
		return ErrPeerUnauthorized
	}
	set, ok := a.Allowed[procedure]
	if !ok || len(set) == 0 {
		return ErrPeerUnauthorized
	}
	if _, ok := set[peer.NodeID]; ok {
		return nil
	}
	return ErrPeerUnauthorized
}
