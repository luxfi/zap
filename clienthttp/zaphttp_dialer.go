// zaphttp_dialer.go — Dialer backed by zap-proto/http.
//
// Default Dialer used by NewClient when no WithDialer override is
// supplied. Returns a *zaphttp.Transport per peer address; the
// transport's own keep-alive + handshake amortization runs underneath.

package clienthttp

import (
	"context"
	"net/http"
	"sync"

	zaphttp "github.com/zap-proto/http"
)

// ZAPHTTPDialer returns RoundTrippers speaking ZAP-HTTP. Goroutine-
// safe; one instance can serve many concurrent peers via the
// per-address cache.
type ZAPHTTPDialer struct {
	mu    sync.Mutex
	cache map[string]*zaphttp.Transport
}

// NewZAPHTTPDialer constructs a ZAPHTTPDialer with an empty cache.
func NewZAPHTTPDialer() *ZAPHTTPDialer {
	return &ZAPHTTPDialer{cache: make(map[string]*zaphttp.Transport)}
}

// Dial returns the cached zaphttp.Transport for peer.Address,
// constructing one on first use.
func (d *ZAPHTTPDialer) Dial(_ context.Context, peer Peer) (http.RoundTripper, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache == nil {
		d.cache = make(map[string]*zaphttp.Transport)
	}
	if tx, ok := d.cache[peer.Address]; ok {
		return tx, nil
	}
	tx := zaphttp.NewTransport(peer.Address)
	d.cache[peer.Address] = tx
	return tx, nil
}
