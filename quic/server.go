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

// ServerConfig configures a QUIC listener.
type ServerConfig struct {
	// NodeID is this node's ZAP identity. Sent on the control stream
	// of every accepted connection. Required.
	NodeID string

	// Addr is the UDP address to listen on. Empty means ":0" (random
	// kernel-assigned port). Resolved as a UDP address.
	Addr string

	// TLS is the TLS 1.3 server config. Required field
	// Certificates (or GetCertificate) must be populated by the caller.
	//
	// If MinVersion / CurvePreferences / NextProtos are not set, they
	// are defaulted to:
	//
	//   MinVersion       = TLS 1.3
	//   CurvePreferences = [X25519MLKEM768, X25519]
	//   NextProtos       = ["zap/1"]
	//
	// Any caller-supplied NextProtos list will have "zap/1" prepended
	// if missing.
	TLS *tls.Config

	// QUIC, if non-nil, is the quic-go Config. Defaults are picked
	// for the common ZAP workload (multiplex up to 1024 streams,
	// enable 0-RTT, allow connection migration).
	QUIC *quicgo.Config

	// RejectEarlyData, if true, disables 0-RTT resumption. Application
	// handlers that are NOT idempotent should set this to eliminate
	// the 0-RTT replay-attack surface.
	RejectEarlyData bool

	// Logger for transport events. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server is a QUIC listener that yields *Conn instances ready for
// ZAP-frame exchange.
//
// Server is the QUIC analogue of net.Listener. The outer ZAP Node
// drives the accept loop; this type does not spawn its own goroutines.
type Server struct {
	cfg ServerConfig
	ln  quicListener
	log *slog.Logger
}

// quicListener abstracts the two flavours of listener exposed by
// quic-go: Listener (post-handshake) and EarlyListener (returns the
// connection before the handshake completes, enabling 0-RTT
// processing). Both expose the same Accept / Addr / Close shape.
type quicListener interface {
	Accept(context.Context) (*quicgo.Conn, error)
	Addr() net.Addr
	Close() error
}

// Listen creates a new QUIC listener bound to cfg.Addr.
//
// The returned Server is ready for Accept calls. Close releases the
// UDP socket and all in-flight connections.
func Listen(cfg ServerConfig) (*Server, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("zap/quic: ServerConfig.NodeID required")
	}
	if cfg.TLS == nil {
		return nil, errors.New("zap/quic: ServerConfig.TLS required")
	}
	if cfg.TLS.Certificates == nil && cfg.TLS.GetCertificate == nil {
		return nil, errors.New("zap/quic: ServerConfig.TLS must supply Certificates or GetCertificate")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	tlsCfg := cfg.TLS.Clone()
	applyZAPDefaults(tlsCfg)

	addr := cfg.Addr
	if addr == "" {
		addr = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: resolve UDP addr: %w", err)
	}

	quicCfg := serverQUICConfig(cfg)

	pktConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: listen UDP: %w", err)
	}

	tr := &quicgo.Transport{Conn: pktConn}
	var ln quicListener
	if cfg.RejectEarlyData {
		ln, err = tr.Listen(tlsCfg, quicCfg)
	} else {
		ln, err = tr.ListenEarly(tlsCfg, quicCfg)
	}
	if err != nil {
		_ = pktConn.Close()
		return nil, fmt.Errorf("zap/quic: start listener: %w", err)
	}

	return &Server{cfg: cfg, ln: ln, log: cfg.Logger}, nil
}

// serverQUICConfig builds the quic-go Config used by Listen. We keep
// these defaults conservative — production deployments can override.
func serverQUICConfig(cfg ServerConfig) *quicgo.Config {
	q := &quicgo.Config{}
	if cfg.QUIC != nil {
		*q = *cfg.QUIC
	}
	if q.MaxIncomingStreams == 0 {
		q.MaxIncomingStreams = 1024
	}
	if q.MaxIncomingUniStreams == 0 {
		q.MaxIncomingUniStreams = 1024
	}
	if q.MaxIdleTimeout == 0 {
		q.MaxIdleTimeout = 30 * time.Second
	}
	if q.KeepAlivePeriod == 0 {
		q.KeepAlivePeriod = 15 * time.Second
	}
	q.Allow0RTT = !cfg.RejectEarlyData
	return q
}

// Addr returns the underlying UDP listen address. Useful when the
// caller bound to ":0" and needs to learn the kernel-assigned port.
func (s *Server) Addr() net.Addr {
	return s.ln.Addr()
}

// Accept waits for and returns the next ZAP-QUIC connection. The
// returned Conn has already completed the node-identity handshake
// on the control stream.
func (s *Server) Accept(ctx context.Context) (*Conn, error) {
	qc, err := s.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}

	// Belt-and-suspenders ALPN check.
	if err := validateNegotiatedALPN(qc.ConnectionState().TLS); err != nil {
		_ = qc.CloseWithError(0x10, err.Error())
		return nil, err
	}

	// Accept the control stream — the client opens it first.
	ctrlCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	ctrl, err := qc.AcceptStream(ctrlCtx)
	if err != nil {
		_ = qc.CloseWithError(0x11, "control stream accept failed")
		return nil, fmt.Errorf("zap/quic: accept control stream: %w", err)
	}

	peerID, err := performServerHandshake(ctx, ctrl, s.cfg.NodeID)
	if err != nil {
		_ = qc.CloseWithError(0x12, "handshake failed")
		return nil, fmt.Errorf("zap/quic: handshake: %w", err)
	}

	s.log.Debug("zap/quic: accepted connection",
		"peerID", peerID,
		"remote", qc.RemoteAddr().String(),
		"curveID", fmt.Sprintf("0x%x", uint16(qc.ConnectionState().TLS.CurveID)),
		"0rtt", qc.ConnectionState().Used0RTT,
	)

	return newConnFromQUIC(qc, ctrl, peerID), nil
}

// Close releases the listener and the underlying UDP socket. Any
// in-flight Accept call returns ErrServerClosed.
func (s *Server) Close() error {
	return s.ln.Close()
}

// ErrServerClosed is returned by Accept after Close has been called.
// It is the unwrap target for errors from a closed listener.
var ErrServerClosed = errors.New("zap/quic: server closed")

// Helper for tests that need to share a single Server across multiple
// goroutines without leaking partial state.
type acceptResult struct {
	conn *Conn
	err  error
}

// acceptOnce is a tiny wrapper that turns Accept into a one-shot
// channel send, used by integration tests.
func (s *Server) acceptOnce(ctx context.Context, out chan<- acceptResult, wg *sync.WaitGroup) {
	defer wg.Done()
	c, err := s.Accept(ctx)
	out <- acceptResult{c, err}
}
