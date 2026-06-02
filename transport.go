// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"errors"
)

// Transport selects which network transport a Node uses.
//
// The default zero value, TransportTCP, preserves the historical
// behavior of NewNode (TCP + optional TLS via NodeConfig.TLS) so every
// existing caller keeps working untouched.
//
// TransportQUIC selects the QUIC transport defined in the quic
// subpackage. The quic subpackage must be imported anonymously by the
// process for TransportQUIC to be available; otherwise NewNode returns
// ErrTransportUnavailable.
type Transport int

const (
	// TransportTCP is ZAP's original transport: framed Cap'n Proto
	// over TCP, with optional TLS 1.3 supplied via NodeConfig.TLS.
	// This is the default for backward compatibility.
	TransportTCP Transport = iota

	// TransportQUIC selects the QUIC transport from the quic
	// subpackage. Requires:
	//
	//   import _ "github.com/luxfi/zap/quic"
	//
	// in some package linked into the binary, so the QUIC factory
	// registers itself at init time.
	TransportQUIC
)

// ErrTransportUnavailable is returned by NewNode when the requested
// Transport has no registered factory. For TransportQUIC, this means
// the quic subpackage was not imported.
var ErrTransportUnavailable = errors.New("zap: transport unavailable (did you import _ \"github.com/luxfi/zap/quic\"?)")

// TransportFactory is the extension point the quic subpackage uses
// to register itself with this package at init time, avoiding an
// import cycle.
//
// A TransportFactory wraps the existing Node so all the higher-level
// APIs (Handle, Send, Call, Broadcast) work identically regardless of
// transport. The factory is responsible for:
//
//   - Binding a listener on n.port (cfg.Port).
//   - Yielding accepted connections via the supplied dispatch hook.
//   - Implementing outbound dial via the supplied dispatch hook.
//
// Today only QUIC uses this hook; TCP is wired directly in node.go
// because the original Node embeds the TCP listener fields. This is
// pragmatic — once QUIC ships we can refactor TCP onto the same
// factory shape without a single user-visible change.
type TransportFactory interface {
	// Listen starts a listener on the address derived from cfg.
	// The listener calls onConn for each accepted, post-handshake
	// connection. Listen must not block; it returns the bound
	// address (so tests using port 0 can learn the kernel port) and
	// a Close func.
	Listen(ctx context.Context, cfg NodeConfig, onConn func(peerID string, conn TransportConn)) (string, func() error, error)

	// Dial opens a connection to addr. The returned TransportConn
	// is symmetric with the conns yielded by Listen.
	Dial(ctx context.Context, cfg NodeConfig, addr string) (peerID string, conn TransportConn, err error)
}

// TransportConn is the transport-level abstraction over a single
// peer connection. It mirrors the existing TCP *Conn semantics
// (Send/Recv/Close) and is used by the transport-aware Node code
// path in node.go.
type TransportConn interface {
	// Send writes one ZAP frame to the peer.
	Send(frame []byte) error

	// Recv blocks until the next ZAP frame arrives, or returns
	// io.EOF when the peer cleanly closes.
	Recv() ([]byte, error)

	// Close performs a graceful close.
	Close() error

	// RemoteAddr returns the peer's network address (best effort —
	// for QUIC this is the address at handshake time, not necessarily
	// the latest after migration).
	RemoteAddr() string
}

// transportRegistry holds the registered factories, keyed by
// Transport. Read-only after init.
var transportRegistry = map[Transport]TransportFactory{}

// RegisterTransport plugs a TransportFactory into the registry. The
// quic subpackage calls this in its init function.
//
// Registration is idempotent — re-registering the same Transport
// overwrites — but in practice each Transport has exactly one
// factory linked into the binary.
func RegisterTransport(t Transport, f TransportFactory) {
	transportRegistry[t] = f
}

// lookupTransport returns the registered factory for t or
// ErrTransportUnavailable.
func lookupTransport(t Transport) (TransportFactory, error) {
	f, ok := transportRegistry[t]
	if !ok {
		return nil, ErrTransportUnavailable
	}
	return f, nil
}
