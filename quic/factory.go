// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic

import (
	"context"
	"errors"
	"fmt"
	"sync"

	zap "github.com/luxfi/zap"
)

// init registers the QUIC TransportFactory with the parent zap
// package. Importing this package — even with a blank import — is
// sufficient to enable TransportQUIC.
func init() {
	zap.RegisterTransport(zap.TransportQUIC, &factory{})
}

// factory is the zap.TransportFactory implementation backed by this
// package's Server + Client.
//
// One ZAP node has one factory invocation: one Server, one Client.
// Per-peer dials reuse the Client's single UDP socket so all
// connections share connection-migration state.
type factory struct {
	mu     sync.Mutex
	srv    *Server
	client *Client
}

// Listen binds a QUIC listener on cfg.Port and dispatches each
// accepted post-handshake connection via onConn.
func (f *factory) Listen(ctx context.Context, cfg zap.NodeConfig, onConn func(peerID string, c zap.TransportConn)) (string, func() error, error) {
	if cfg.TLS == nil {
		return "", nil, errors.New("zap/quic: NodeConfig.TLS required for TransportQUIC (must contain server Certificates or GetCertificate)")
	}

	srvCfg := ServerConfig{
		NodeID: cfg.NodeID,
		Addr:   fmt.Sprintf(":%d", cfg.Port),
		TLS:    cfg.TLS,
		Logger: cfg.Logger,
	}
	if cfg.QUICConfig != nil {
		if qc, ok := cfg.QUICConfig.(*Config); ok {
			srvCfg.QUIC = qc.QUIC
			srvCfg.RejectEarlyData = qc.RejectEarlyData
		}
	}

	srv, err := Listen(srvCfg)
	if err != nil {
		return "", nil, err
	}

	cli, err := NewClient(ClientConfig{
		NodeID: cfg.NodeID,
		TLS:    cloneClientTLS(cfg.TLS),
		Logger: cfg.Logger,
	})
	if err != nil {
		_ = srv.Close()
		return "", nil, err
	}

	f.mu.Lock()
	f.srv = srv
	f.client = cli
	f.mu.Unlock()

	// Accept loop. Each accepted *Conn is wrapped in a transportConnAdapter
	// so the parent package sees the TransportConn interface only.
	go func() {
		for {
			c, err := srv.Accept(ctx)
			if err != nil {
				return
			}
			onConn(c.PeerID, &transportConnAdapter{c: c})
		}
	}()

	return srv.Addr().String(), func() error {
		_ = srv.Close()
		_ = cli.Close()
		return nil
	}, nil
}

// Dial opens a QUIC connection to addr.
func (f *factory) Dial(ctx context.Context, cfg zap.NodeConfig, addr string) (string, zap.TransportConn, error) {
	f.mu.Lock()
	cli := f.client
	f.mu.Unlock()
	if cli == nil {
		return "", nil, errors.New("zap/quic: Dial called before Listen (no client transport)")
	}
	c, err := cli.Dial(ctx, addr)
	if err != nil {
		return "", nil, err
	}
	return c.PeerID, &transportConnAdapter{c: c}, nil
}

// transportConnAdapter wraps a *Conn so it satisfies
// zap.TransportConn (which is an interface defined in the parent
// package, deliberately without any quic-go types).
type transportConnAdapter struct {
	c *Conn
}

func (a *transportConnAdapter) Send(frame []byte) error { return a.c.Send(frame) }
func (a *transportConnAdapter) Recv() ([]byte, error)   { return a.c.Recv() }
func (a *transportConnAdapter) Close() error            { return a.c.Close() }
func (a *transportConnAdapter) RemoteAddr() string      { return a.c.RemoteAddr.String() }
