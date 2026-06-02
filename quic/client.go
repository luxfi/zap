// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// ClientConfig configures a QUIC dialer.
type ClientConfig struct {
	// NodeID is this node's ZAP identity. Sent on the control stream
	// during the post-handshake identity exchange. Required.
	NodeID string

	// TLS is the TLS 1.3 client config. Required.
	//
	// If MinVersion / CurvePreferences / NextProtos are not set, they
	// are defaulted to:
	//
	//   MinVersion       = TLS 1.3
	//   CurvePreferences = [X25519MLKEM768, X25519]
	//   NextProtos       = ["zap/1"]
	//
	// The caller is responsible for providing RootCAs or
	// VerifyPeerCertificate. Test code may set InsecureSkipVerify; do
	// not do this in production.
	TLS *tls.Config

	// QUIC, if non-nil, is the quic-go Config used for dialing.
	QUIC *quicgo.Config

	// SessionCache is the client-side TLS 1.3 session ticket cache.
	// When non-nil, 0-RTT resumption is enabled for second-and-later
	// dials to the same peer.
	//
	// If nil, the TLS config's own ClientSessionCache (defaulted to
	// an in-memory LRU of 128 entries by applyZAPDefaults) is used.
	SessionCache tls.ClientSessionCache

	// Logger for transport events. Defaults to slog.Default().
	Logger *slog.Logger
}

// Client is a QUIC dialer with optional connection migration and
// 0-RTT support.
//
// One Client may be shared across many goroutines and used to Dial
// multiple peers concurrently. The Client owns one *quic.Transport
// which is bound to a single UDP socket — every Dial uses the same
// local socket, so a connection migration of the local side will
// affect all connections owned by this Client (this matches QUIC
// semantics).
type Client struct {
	cfg ClientConfig
	tr  *quicgo.Transport
	log *slog.Logger
	mu  sync.Mutex // guards tr lifecycle
}

// NewClient returns a Client that listens on a random local UDP port.
//
// NewClient does NOT establish any QUIC connections; use Dial to
// connect to a specific peer.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("zap/quic: ClientConfig.NodeID required")
	}
	if cfg.TLS == nil {
		return nil, errors.New("zap/quic: ClientConfig.TLS required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("zap/quic: resolve UDP: %w", err)
	}
	pktConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: listen UDP: %w", err)
	}
	tr := &quicgo.Transport{Conn: pktConn}

	return &Client{
		cfg: cfg,
		tr:  tr,
		log: cfg.Logger,
	}, nil
}

// LocalAddr returns the local UDP address bound by NewClient.
func (c *Client) LocalAddr() net.Addr {
	return c.tr.Conn.LocalAddr()
}

// Transport returns the underlying *quic.Transport. Exposed for tests
// that need to trigger a deliberate path migration.
func (c *Client) Transport() *quicgo.Transport {
	return c.tr
}

// Dial establishes a QUIC connection to addr.
//
// addr is an "ip:port" string resolvable as a UDP address.
//
// On a second-and-later dial to the same peer, if a valid TLS 1.3
// session ticket is cached, 0-RTT resumption is attempted (the
// returned Conn's IsZeroRTT() reports whether the server accepted it).
func (c *Client) Dial(ctx context.Context, addr string) (*Conn, error) {
	return c.dial(ctx, addr, false)
}

// DialEarly is identical to Dial but explicitly attempts a 0-RTT
// handshake. If no session ticket is cached for the peer, this
// behaves identically to Dial (a full 1-RTT handshake is performed).
func (c *Client) DialEarly(ctx context.Context, addr string) (*Conn, error) {
	return c.dial(ctx, addr, true)
}

func (c *Client) dial(ctx context.Context, addr string, earlyData bool) (*Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: resolve %q: %w", addr, err)
	}

	tlsCfg := c.cfg.TLS.Clone()
	if c.cfg.SessionCache != nil {
		tlsCfg.ClientSessionCache = c.cfg.SessionCache
	}
	applyZAPDefaults(tlsCfg)

	quicCfg := clientQUICConfig(c.cfg)

	var qc *quicgo.Conn
	if earlyData {
		qc, err = c.tr.DialEarly(ctx, udpAddr, tlsCfg, quicCfg)
	} else {
		qc, err = c.tr.Dial(ctx, udpAddr, tlsCfg, quicCfg)
	}
	if err != nil {
		return nil, fmt.Errorf("zap/quic: dial %s: %w", addr, err)
	}

	// DialEarly returns before the TLS handshake fully completes;
	// we must wait for handshake to learn the negotiated ALPN.
	if earlyData {
		select {
		case <-qc.HandshakeComplete():
		case <-ctx.Done():
			_ = qc.CloseWithError(0x10, "handshake timeout")
			return nil, ctx.Err()
		}
	}

	if err := validateNegotiatedALPN(qc.ConnectionState().TLS); err != nil {
		_ = qc.CloseWithError(0x10, err.Error())
		return nil, err
	}

	// Open the control stream — server expects us to open it first.
	ctrlCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	ctrl, err := qc.OpenStreamSync(ctrlCtx)
	if err != nil {
		_ = qc.CloseWithError(0x11, "open control stream failed")
		return nil, fmt.Errorf("zap/quic: open control stream: %w", err)
	}

	peerID, err := performClientHandshake(ctx, ctrl, c.cfg.NodeID)
	if err != nil {
		_ = qc.CloseWithError(0x12, "handshake failed")
		return nil, fmt.Errorf("zap/quic: handshake: %w", err)
	}

	c.log.Debug("zap/quic: dialed connection",
		"peerID", peerID,
		"remote", qc.RemoteAddr().String(),
		"curveID", fmt.Sprintf("0x%x", uint16(qc.ConnectionState().TLS.CurveID)),
		"0rtt", qc.ConnectionState().Used0RTT,
	)

	return newConnFromQUIC(qc, ctrl, peerID), nil
}

// Close releases the underlying UDP socket. In-flight Dial calls
// return errors; existing *Conn objects remain valid until their
// own Close.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tr == nil {
		return nil
	}
	err := c.tr.Close()
	c.tr = nil
	return err
}

func clientQUICConfig(cfg ClientConfig) *quicgo.Config {
	q := &quicgo.Config{}
	if cfg.QUIC != nil {
		*q = *cfg.QUIC
	}
	if q.MaxIdleTimeout == 0 {
		q.MaxIdleTimeout = 30 * time.Second
	}
	if q.KeepAlivePeriod == 0 {
		q.KeepAlivePeriod = 15 * time.Second
	}
	if q.MaxIncomingStreams == 0 {
		q.MaxIncomingStreams = 1024
	}
	if q.MaxIncomingUniStreams == 0 {
		q.MaxIncomingUniStreams = 1024
	}
	// Connection migration is automatic in quic-go as long as the
	// local socket can receive packets from new paths.
	return q
}
