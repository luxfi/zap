// Package clienthttp — service-discovery-aware HTTP client over ZAP-HTTP.
//
// Combines two pieces:
//
//   - github.com/luxfi/mdns — zero-config peer discovery (mDNS/DNS-SD).
//   - github.com/zap-proto/http — net/http.RoundTripper speaking
//     ZAP-HTTP (zero-copy capnp binary instead of plaintext HTTP/1.1).
//
// Callers construct via NewClient(serviceType) and get an *http.Client
// that:
//
//  1. Resolves peers for serviceType via mDNS (single shared Discovery
//     per process, refreshed on the configured BrowseInterval).
//  2. Per RoundTrip, picks one peer from the current set (round-robin
//     by default; see WithPicker for alternatives).
//  3. Dials that peer via zap-proto/http and proxies the request.
//
// Usage:
//
//	c, stop, err := clienthttp.NewClient("liquidity-ta",
//	    clienthttp.WithBearer(os.Getenv("BD_SIGNING_KEY")),
//	    clienthttp.WithMinPeers(1),
//	)
//	if err != nil { ... }
//	defer stop()
//	resp, err := c.Get("http://ta/v1/ta/securities/sec-1/list")
//
// The Host portion of the URL is ignored — clienthttp picks the peer
// from discovery — but the path + query are forwarded verbatim. Existing
// http.Client machinery (cookies, retries, redirects) works unchanged.

package clienthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/mdns"
	zaphttp "github.com/zap-proto/http"
)

// Picker selects one peer from a discovery snapshot. Implementations
// MUST be goroutine-safe; clienthttp calls Pick concurrently from
// every in-flight RoundTrip.
type Picker interface {
	Pick(peers []*mdns.Peer) (*mdns.Peer, error)
}

// RoundRobinPicker rotates through peers in registration order.
// Zero-value is ready to use.
type RoundRobinPicker struct {
	next atomic.Uint64
}

// Pick returns the next peer via round-robin.
func (p *RoundRobinPicker) Pick(peers []*mdns.Peer) (*mdns.Peer, error) {
	if len(peers) == 0 {
		return nil, ErrNoPeers
	}
	idx := p.next.Add(1) - 1
	return peers[idx%uint64(len(peers))], nil
}

// Sentinel errors. Callers branch via errors.Is.
var (
	// ErrNoPeers is returned by Picker when discovery has no live
	// peers for the service. Surfaces as a transport error from
	// http.Client.Do.
	ErrNoPeers = errors.New("clienthttp: no peers discovered")
)

// Options configure NewClient.
type Options struct {
	// ClientID identifies this caller in mDNS announcements. Empty
	// generates a random uuid-like string. The id has no security
	// meaning — auth lives in the Authorization header.
	ClientID string
	// Bearer is attached as `Authorization: Bearer <bearer>` on every
	// outgoing request. Empty disables auth-header injection. Single
	// attach point — never log the underlying Transport's request
	// without redacting this header.
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
	// Picker selects a peer per RoundTrip. Default RoundRobinPicker.
	Picker Picker
	// HTTPTimeout caps each outbound request. Default 30 seconds.
	HTTPTimeout time.Duration
	// OrgIDHeader is the header key for the X-Org-Id forwarder.
	// Default "X-Org-Id". Callers do not set this directly; they pass
	// org context via request.Header.
	OrgIDHeader string
}

// Option is the functional-option constructor knob.
type Option func(*Options)

// WithBearer pins the service-bearer to attach on every call.
func WithBearer(b string) Option { return func(o *Options) { o.Bearer = b } }

// WithMinPeers waits for at least N peers before NewClient returns.
func WithMinPeers(n int) Option { return func(o *Options) { o.MinPeers = n } }

// WithDiscoverTimeout caps the initial peer-discovery wait.
func WithDiscoverTimeout(d time.Duration) Option {
	return func(o *Options) { o.DiscoverTimeout = d }
}

// WithBrowseInterval sets the mDNS browse interval.
func WithBrowseInterval(d time.Duration) Option {
	return func(o *Options) { o.BrowseInterval = d }
}

// WithPicker overrides the per-RoundTrip peer selector.
func WithPicker(p Picker) Option { return func(o *Options) { o.Picker = p } }

// WithHTTPTimeout caps each outbound request's total time.
func WithHTTPTimeout(d time.Duration) Option {
	return func(o *Options) { o.HTTPTimeout = d }
}

// WithClientID names this caller in its mDNS announcement.
func WithClientID(id string) Option { return func(o *Options) { o.ClientID = id } }

// NewClient resolves a service via mDNS and returns an *http.Client
// that routes requests to discovered peers over ZAP-HTTP.
//
// The returned stop function releases the underlying mDNS Discovery
// and the cached transports.
func NewClient(serviceType string, opts ...Option) (*http.Client, func(), error) {
	o := defaults()
	for _, opt := range opts {
		opt(&o)
	}
	if serviceType == "" {
		return nil, nil, fmt.Errorf("clienthttp: serviceType is required")
	}

	disc := mdns.New(
		serviceType,
		o.ClientID,
		0, // we don't expose a port — pure client side
		mdns.WithBrowseInterval(o.BrowseInterval),
	)
	if err := disc.Start(); err != nil {
		return nil, nil, fmt.Errorf("clienthttp: mdns start: %w", err)
	}

	// Wait for at least MinPeers peers (or DiscoverTimeout). This
	// front-loads the discovery hit so the first RoundTrip is fast.
	ctx, cancel := context.WithTimeout(context.Background(), o.DiscoverTimeout)
	defer cancel()
	if err := waitForPeers(ctx, disc, o.MinPeers); err != nil {
		disc.Stop()
		return nil, nil, fmt.Errorf("clienthttp: discover: %w", err)
	}

	tx := &transport{
		disc:    disc,
		picker:  o.Picker,
		bearer:  o.Bearer,
		orgKey:  o.OrgIDHeader,
		cache:   make(map[string]*zaphttp.Transport),
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
		Picker:          &RoundRobinPicker{},
		HTTPTimeout:     30 * time.Second,
		OrgIDHeader:     "X-Org-Id",
	}
}

func waitForPeers(ctx context.Context, disc *mdns.Discovery, min int) error {
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

// transport is the http.RoundTripper that picks a peer per request +
// proxies via zap-proto/http. Transports are cached per peer address
// so the underlying ZAP TCP connection can amortize handshakes once
// zap-proto/http supports pooling.
type transport struct {
	disc   *mdns.Discovery
	picker Picker
	bearer string
	orgKey string

	mu    sync.Mutex
	cache map[string]*zaphttp.Transport
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	peers := t.disc.Peers()
	peer, err := t.picker.Pick(peers)
	if err != nil {
		return nil, err
	}
	addr := peer.Address()

	tx := t.getOrDial(addr)

	// Single auth-attach point. Callers who need per-call bearers can
	// set Authorization themselves before Do; this fills it in only if
	// unset, so a per-call header always wins.
	if t.bearer != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+t.bearer)
	}
	return tx.RoundTrip(req)
}

func (t *transport) getOrDial(addr string) *zaphttp.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tx, ok := t.cache[addr]; ok {
		return tx
	}
	tx := zaphttp.NewTransport(addr)
	t.cache[addr] = tx
	return tx
}

// randomSuffix returns a small string suffix for the default ClientID.
// Not cryptographically secure — the id has no auth meaning.
func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()&0xffff)
}
