// client.go — service-discovery-aware native ZAP client.

package zapclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	zap "github.com/luxfi/zap"
)

// RoundRobinPicker rotates through peers in registration order.
// Zero-value is ready to use; goroutine-safe.
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

// ClientOptions configure Connect. Construct via WithX options.
type ClientOptions struct {
	// NodeID is the caller's identity in mDNS announcements. Empty
	// auto-generates a short suffix.
	NodeID string
	// MinPeers blocks Connect until at least N peers are discovered
	// (or DiscoverTimeout elapses). Default 1.
	MinPeers int
	// DiscoverTimeout caps the initial peer-discovery wait. Default
	// 10 * BrowseInterval.
	DiscoverTimeout time.Duration
	// BrowseInterval is how often the default mDNS Discovery
	// re-browses. Default 5 seconds.
	BrowseInterval time.Duration
	// CallTimeout caps each Call. Zero = no timeout. Default 30s.
	CallTimeout time.Duration
	// TLS configures mutual TLS. Nil = plaintext (dev only — local-
	// trust mode requires mTLS against the cluster CA).
	TLS *tls.Config
	// Logger for ZAP node + client. Defaults to slog.Default().
	Logger *slog.Logger

	// Pluggable wiring. nil means "use default for this concern."
	Discovery Discovery
	Picker    Picker
}

// ClientOption is the functional-option constructor knob.
type ClientOption func(*ClientOptions)

// WithNodeID names the caller in mDNS announcements.
func WithNodeID(id string) ClientOption {
	return func(o *ClientOptions) { o.NodeID = id }
}

// WithMinPeers blocks Connect until N peers are discovered.
func WithMinPeers(n int) ClientOption {
	return func(o *ClientOptions) { o.MinPeers = n }
}

// WithDiscoverTimeout caps the initial peer-discovery wait.
func WithDiscoverTimeout(d time.Duration) ClientOption {
	return func(o *ClientOptions) { o.DiscoverTimeout = d }
}

// WithBrowseInterval sets the default mDNS browse interval.
func WithBrowseInterval(d time.Duration) ClientOption {
	return func(o *ClientOptions) { o.BrowseInterval = d }
}

// WithCallTimeout caps each Call's wait for a response.
func WithCallTimeout(d time.Duration) ClientOption {
	return func(o *ClientOptions) { o.CallTimeout = d }
}

// WithTLS configures mutual TLS for the underlying ZAP connection.
// Required for the local-trust authorisation model on the server
// side (the server's PeerVerifier reads the peer cert).
func WithTLS(cfg *tls.Config) ClientOption {
	return func(o *ClientOptions) { o.TLS = cfg }
}

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) ClientOption {
	return func(o *ClientOptions) { o.Logger = l }
}

// WithDiscovery overrides the peer-discovery backend (mDNS by default).
// Useful for tests + non-mDNS environments (Consul, etcd, static).
func WithDiscovery(d Discovery) ClientOption {
	return func(o *ClientOptions) { o.Discovery = d }
}

// WithPicker overrides the per-Call peer selector.
func WithPicker(p Picker) ClientOption {
	return func(o *ClientOptions) { o.Picker = p }
}

// Client is a native ZAP RPC client. Created by Connect; closed by
// Close (or returned stop function from MustConnect).
type Client struct {
	node      *zap.Node
	disc      Discovery
	picker    Picker
	timeout   time.Duration
	logger    *slog.Logger

	mu         sync.Mutex
	closed     bool
	stopDisc   func()
}

// Connect resolves a service via Discovery and returns a Client.
// Always defer Close on the returned client.
func Connect(ctx context.Context, serviceType string, opts ...ClientOption) (*Client, error) {
	if serviceType == "" {
		return nil, fmt.Errorf("zapclient: serviceType is required")
	}
	o := defaultClientOpts()
	for _, opt := range opts {
		opt(&o)
	}
	if o.NodeID == "" {
		o.NodeID = "zapclient-" + randomSuffix()
	}

	// The client-side Node has no listener of its own — discovery is
	// the only thing it advertises. ZAP's Node currently always opens
	// a listener; we set port=0 so the OS picks an ephemeral port and
	// the listener is effectively unused.
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      "client-" + o.NodeID,
		ServiceType: serviceType,
		Port:        0,
		NoDiscovery: o.Discovery != nil, // skip built-in discovery when caller supplied one
		TLS:         o.TLS,
		Logger:      o.Logger,
	})
	if err := n.Start(); err != nil {
		return nil, fmt.Errorf("zapclient: node start: %w", err)
	}

	disc := o.Discovery
	stopDisc := func() {}
	if disc == nil {
		// Use Node's built-in mDNS discovery. Wrap it in a tiny
		// adapter that exposes our Discovery contract.
		disc = nodeDiscovery{n: n, serviceType: serviceType}
	} else {
		if err := disc.Start(); err != nil {
			n.Stop()
			return nil, fmt.Errorf("zapclient: discovery start: %w", err)
		}
		stopDisc = disc.Stop
	}

	ctx2, cancel := context.WithTimeout(ctx, o.DiscoverTimeout)
	defer cancel()
	if err := waitForPeers(ctx2, disc, o.MinPeers); err != nil {
		stopDisc()
		n.Stop()
		return nil, fmt.Errorf("zapclient: discover: %w", err)
	}

	return &Client{
		node:     n,
		disc:     disc,
		picker:   o.Picker,
		timeout:  o.CallTimeout,
		logger:   o.Logger,
		stopDisc: stopDisc,
	}, nil
}

// MustConnect is Connect that panics on error.
func MustConnect(ctx context.Context, serviceType string, opts ...ClientOption) *Client {
	c, err := Connect(ctx, serviceType, opts...)
	if err != nil {
		panic(err)
	}
	return c
}

// Call invokes procedure on the picked peer and waits for a response.
// Respects the client-level CallTimeout in addition to ctx.
func (c *Client) Call(ctx context.Context, procedure string, req *zap.Message) (*zap.Message, error) {
	op, err := ProcedureOpcode(procedure)
	if err != nil {
		return nil, err
	}
	peer, err := c.pick()
	if err != nil {
		return nil, err
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	// Tag the message's flags with the procedure opcode. The node
	// stamps a separate request-correlation header on top; the
	// procedure opcode rides in the message flags field.
	tagged := withFlags(req, op)
	return c.node.Call(ctx, peer.NodeID, tagged)
}

// Send invokes procedure as fire-and-forget — no response awaited.
func (c *Client) Send(ctx context.Context, procedure string, req *zap.Message) error {
	op, err := ProcedureOpcode(procedure)
	if err != nil {
		return err
	}
	peer, err := c.pick()
	if err != nil {
		return err
	}
	return c.node.Send(ctx, peer.NodeID, withFlags(req, op))
}

// Broadcast sends procedure to every current peer. Returns a map of
// peer NodeID → error so the caller can re-try the failures.
func (c *Client) Broadcast(ctx context.Context, procedure string, req *zap.Message) map[string]error {
	op, err := ProcedureOpcode(procedure)
	if err != nil {
		return map[string]error{"": err}
	}
	return c.node.Broadcast(ctx, withFlags(req, op))
}

// Peers returns the current peer snapshot.
func (c *Client) Peers() []Peer { return c.disc.Peers() }

// Close releases the underlying ZAP node + discovery.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.stopDisc()
	c.node.Stop()
	return nil
}

func (c *Client) pick() (Peer, error) {
	peers := c.disc.Peers()
	return c.picker.Pick(peers)
}

func defaultClientOpts() ClientOptions {
	return ClientOptions{
		MinPeers:        1,
		DiscoverTimeout: 10 * time.Second,
		BrowseInterval:  5 * time.Second,
		CallTimeout:     30 * time.Second,
		Picker:          &RoundRobinPicker{},
		Logger:          slog.Default(),
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

// withFlags returns a new *zap.Message with the lower 16 bits of
// flags replaced by op. Used to encode the procedure opcode on each
// outbound call.
//
// Until lux/zap exposes a public flag-setter, we encode by re-parsing
// the raw bytes with the requested flag. The original buffer is not
// mutated.
func withFlags(msg *zap.Message, op uint16) *zap.Message {
	if msg == nil {
		// caller should provide a payload; nil here is rare but
		// acceptable for parameter-less procedures. Build a stub.
		b := zap.NewBuilder(zap.HeaderSize)
		ob := b.StartObject(0)
		ob.FinishAsRoot()
		out, _ := zap.Parse(b.FinishWithFlags(op))
		return out
	}
	raw := append([]byte(nil), msg.Bytes()...)
	// Flags occupy bytes 6..8 in the ZAP header (see zap.go: Flags()
	// reads from raw[6:8] little-endian).
	raw[6] = byte(op)
	raw[7] = byte(op >> 8)
	out, _ := zap.Parse(raw)
	return out
}

func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()&0xffff)
}

// nodeDiscovery is the default Discovery: it delegates to the Node's
// built-in mDNS. Used when no WithDiscovery override is supplied.
type nodeDiscovery struct {
	n           *zap.Node
	serviceType string
}

func (nd nodeDiscovery) Peers() []Peer {
	ids := nd.n.Peers()
	out := make([]Peer, 0, len(ids))
	for _, id := range ids {
		out = append(out, Peer{NodeID: id, ServiceType: nd.serviceType})
	}
	return out
}

func (nd nodeDiscovery) PeerCount() int     { return len(nd.n.Peers()) }
func (nd nodeDiscovery) ServiceType() string { return nd.serviceType }
func (nd nodeDiscovery) Start() error        { return nil } // Node already started it
func (nd nodeDiscovery) Stop()               {}              // Node.Stop handles it

// compile-time: RoundRobinPicker satisfies Picker; the *Client uses it.
var _ Picker = (*RoundRobinPicker)(nil)
var _ Discovery = (*mdnsDiscovery)(nil)
var _ Discovery = nodeDiscovery{}

// unused stub to avoid an "imported and not used" if a build tag
// strips errors.
var _ = errors.New
