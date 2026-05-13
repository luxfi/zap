// Package clienthttp — service-discovery-aware HTTP client over ZAP-HTTP.
//
// Three orthogonal pieces (see iface.go for contracts) compose into the
// returned *http.Client:
//
//   Discovery + Picker + Dialer + AuthAttacher  →  http.RoundTripper
//
// The default wiring uses mDNS (luxfi/mdns) for Discovery, round-robin
// for Picker, ZAP-HTTP (zap-proto/http) for Dialer, and bearer-token
// attach for AuthAttacher.
//
// Drop-in usage:
//
//	c, stop, err := clienthttp.NewClient("liquidity-ta",
//	    clienthttp.WithBearer(os.Getenv("BD_SIGNING_KEY")),
//	)
//	defer stop()
//	resp, err := c.Get("http://ta/v1/ta/securities/sec-1/list")
//
// In-cluster ZAP-native trust mode (no bearer required because the
// trust comes from the mDNS-bounded ZAP TLS scope):
//
//	c, stop, err := clienthttp.NewClient("liquidity-ta",
//	    clienthttp.WithLocalTrust(),
//	)
//	defer stop()
//	resp, err := c.Get("http://ta/v1/ta/securities/sec-1/list")
//
// The Host portion of req.URL is ignored — clienthttp resolves the
// peer from discovery at RoundTrip time — but the path + query +
// headers are forwarded verbatim. Existing http.Client machinery
// (cookies, retries, redirects) works unchanged.

package clienthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Sentinel errors. Callers branch via errors.Is.
var (
	// ErrNoPeers is returned by Picker when discovery has no live
	// peers for the service.
	ErrNoPeers = errors.New("clienthttp: no peers discovered")
)

// RoundRobinPicker rotates through peers in registration order.
// Zero-value is ready to use; safe for concurrent Pick calls.
type RoundRobinPicker struct {
	next atomic.Uint64
}

// Pick returns the next peer via round-robin.
func (p *RoundRobinPicker) Pick(peers []Peer) (Peer, error) {
	if len(peers) == 0 {
		return Peer{}, ErrNoPeers
	}
	idx := p.next.Add(1) - 1
	return peers[idx%uint64(len(peers))], nil
}

// BearerAttacher attaches a bearer token. Empty Bearer is a no-op
// (the bearer field is the no-trust-needed signal).
type BearerAttacher struct {
	Bearer string
}

// Attach sets `Authorization: Bearer <Bearer>` unless the request
// already carries an Authorization header (per-call overrides win).
func (a BearerAttacher) Attach(req *http.Request, _ Peer) error {
	if a.Bearer == "" {
		return nil
	}
	if req.Header.Get("Authorization") != "" {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+a.Bearer)
	return nil
}

// NoAuthAttacher is the local-trust attacher: trust comes from the
// mDNS-bounded ZAP TLS scope, not from a header. Calling code can
// still pass per-call headers; this attacher just does nothing.
type NoAuthAttacher struct{}

// Attach is a no-op.
func (NoAuthAttacher) Attach(*http.Request, Peer) error { return nil }

// Options configure NewClient. Construct via WithX options; do not
// instantiate directly.
type Options struct {
	// ClientID identifies this caller in mDNS announcements. Empty
	// generates a small uuid-like suffix. The id has no security
	// meaning — auth lives in AuthAttacher.
	ClientID string
	// Bearer is shorthand for the default BearerAttacher. Mutually
	// exclusive with WithLocalTrust / WithAuthAttacher; later option
	// wins.
	Bearer string
	// MinPeers blocks NewClient until at least N peers are discovered
	// (or DiscoverTimeout elapses). Default 1.
	MinPeers int
	// DiscoverTimeout caps the initial peer-discovery wait. Default
	// 10 * BrowseInterval.
	DiscoverTimeout time.Duration
	// BrowseInterval is how often mDNS re-browses for peers. Default
	// 5 seconds.
	BrowseInterval time.Duration
	// HTTPTimeout caps each outbound request. Default 30 seconds.
	HTTPTimeout time.Duration

	// Pluggable wiring. nil means "use default for this concern."
	Discovery Discovery
	Picker    Picker
	Dialer    Dialer
	Auth      AuthAttacher
}

// Option is the functional-option constructor knob.
type Option func(*Options)

// WithBearer attaches `Authorization: Bearer <b>` on every call.
// Mutually exclusive with WithLocalTrust / WithAuthAttacher.
func WithBearer(b string) Option {
	return func(o *Options) { o.Bearer = b; o.Auth = nil }
}

// WithLocalTrust signals that this client runs inside the trusted
// ZAP mesh — the bearer attach is skipped. Use only when:
//
//   - The peer is reachable only on the cluster-private network
//     (k8s pod network, not the public internet).
//   - Discovery is mDNS bounded to that network (multicast scope).
//   - ZAP TLS verifies peers against the cluster CA so even an
//     attacker on the same segment cannot impersonate a service.
//
// Cross-cluster + ingress callers MUST NOT use this; they require an
// explicit bearer attached via WithBearer or a custom AuthAttacher.
func WithLocalTrust() Option {
	return func(o *Options) { o.Bearer = ""; o.Auth = NoAuthAttacher{} }
}

// WithAuthAttacher pins a custom AuthAttacher (mTLS-derived identity,
// signed-request headers, etc.). Overrides WithBearer and
// WithLocalTrust.
func WithAuthAttacher(a AuthAttacher) Option {
	return func(o *Options) { o.Auth = a }
}

// WithMinPeers waits for at least N peers before NewClient returns.
func WithMinPeers(n int) Option { return func(o *Options) { o.MinPeers = n } }

// WithDiscoverTimeout caps the initial peer-discovery wait.
func WithDiscoverTimeout(d time.Duration) Option {
	return func(o *Options) { o.DiscoverTimeout = d }
}

// WithBrowseInterval sets the mDNS browse interval (default backend).
func WithBrowseInterval(d time.Duration) Option {
	return func(o *Options) { o.BrowseInterval = d }
}

// WithPicker overrides the per-RoundTrip peer selector.
func WithPicker(p Picker) Option { return func(o *Options) { o.Picker = p } }

// WithDialer overrides the per-peer RoundTripper factory.
func WithDialer(d Dialer) Option { return func(o *Options) { o.Dialer = d } }

// WithDiscovery overrides the peer-discovery backend. Useful for
// tests + non-mDNS environments (Consul, etcd, static).
func WithDiscovery(d Discovery) Option {
	return func(o *Options) { o.Discovery = d }
}

// WithHTTPTimeout caps each outbound request's total time.
func WithHTTPTimeout(d time.Duration) Option {
	return func(o *Options) { o.HTTPTimeout = d }
}

// WithClientID names this caller in its mDNS announcement.
func WithClientID(id string) Option { return func(o *Options) { o.ClientID = id } }

// NewClient resolves a service and returns an *http.Client that
// composes Discovery + Picker + Dialer + AuthAttacher.
//
// The returned stop function releases the underlying Discovery and
// the Dialer's cached transports. Always defer stop() on success.
func NewClient(serviceType string, opts ...Option) (*http.Client, func(), error) {
	o := defaults()
	for _, opt := range opts {
		opt(&o)
	}
	if serviceType == "" {
		return nil, nil, fmt.Errorf("clienthttp: serviceType is required")
	}

	// Wire the four concerns. Fall back to defaults where the caller
	// did not override.
	disc := o.Discovery
	if disc == nil {
		disc = newMDNSDiscovery(serviceType, o.ClientID, o.BrowseInterval)
	}
	picker := o.Picker
	if picker == nil {
		picker = &RoundRobinPicker{}
	}
	dialer := o.Dialer
	if dialer == nil {
		dialer = NewZAPHTTPDialer()
	}
	auth := o.Auth
	if auth == nil {
		auth = BearerAttacher{Bearer: o.Bearer}
	}

	if err := disc.Start(); err != nil {
		return nil, nil, fmt.Errorf("clienthttp: discovery start: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.DiscoverTimeout)
	defer cancel()
	if err := waitForPeers(ctx, disc, o.MinPeers); err != nil {
		disc.Stop()
		return nil, nil, fmt.Errorf("clienthttp: discover: %w", err)
	}

	tx := &transport{
		disc:   disc,
		picker: picker,
		dialer: dialer,
		auth:   auth,
	}

	stop := func() {
		disc.Stop()
		tx.mu.Lock()
		tx.cache = nil
		tx.mu.Unlock()
	}

	return &http.Client{Transport: tx, Timeout: o.HTTPTimeout}, stop, nil
}

// defaults populates omitted Options fields with the recommended values.
func defaults() Options {
	return Options{
		ClientID:        "clienthttp-" + randomSuffix(),
		MinPeers:        1,
		DiscoverTimeout: 10 * time.Second,
		BrowseInterval:  5 * time.Second,
		HTTPTimeout:     30 * time.Second,
	}
}

func waitForPeers(ctx context.Context, disc Discovery, min int) error {
	if min <= 0 {
		return nil
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if disc.PeerCount() >= min {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %d peer(s) of type %q (have %d)",
				min, disc.ServiceType(), disc.PeerCount())
		case <-ticker.C:
		}
	}
}

// transport composes Discovery + Picker + Dialer + AuthAttacher into
// an http.RoundTripper. One transport per *http.Client; per-peer
// RoundTrippers are cached by the Dialer (default impl) or by this
// transport's own map (when the Dialer returns fresh ones each time).
type transport struct {
	disc   Discovery
	picker Picker
	dialer Dialer
	auth   AuthAttacher

	mu    sync.Mutex
	cache map[string]http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	peers := t.disc.Peers()
	peer, err := t.picker.Pick(peers)
	if err != nil {
		return nil, err
	}
	rt, err := t.getOrDial(req.Context(), peer)
	if err != nil {
		return nil, err
	}
	if err := t.auth.Attach(req, peer); err != nil {
		return nil, err
	}
	return rt.RoundTrip(req)
}

func (t *transport) getOrDial(ctx context.Context, peer Peer) (http.RoundTripper, error) {
	t.mu.Lock()
	if t.cache == nil {
		t.cache = make(map[string]http.RoundTripper)
	}
	if rt, ok := t.cache[peer.Address]; ok {
		t.mu.Unlock()
		return rt, nil
	}
	t.mu.Unlock()

	rt, err := t.dialer.Dial(ctx, peer)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.cache[peer.Address] = rt
	t.mu.Unlock()
	return rt, nil
}

// randomSuffix returns a small non-secret string suffix for ClientID.
func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()&0xffff)
}
