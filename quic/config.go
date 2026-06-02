// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic

import (
	"crypto/tls"

	quicgo "github.com/quic-go/quic-go"
)

// Config is the user-facing knob that the zap parent package's
// NodeConfig.QUICConfig accepts. It's a thin wrapper so callers
// don't have to import quic-go just to flip RejectEarlyData; they
// can supply nil for QUIC if defaults are fine.
//
// Typical use:
//
//	cfg := zap.NodeConfig{
//	    NodeID:    "node-a",
//	    Port:      9999,
//	    TLS:       tlsCfg,
//	    Transport: zap.TransportQUIC,
//	    QUICConfig: &quic.Config{RejectEarlyData: true},
//	}
type Config struct {
	// QUIC is the underlying quic-go transport config. Optional;
	// nil yields ZAP's defaults (30s idle timeout, 15s keepalive,
	// 1024 max concurrent streams in each direction).
	QUIC *quicgo.Config

	// RejectEarlyData disables 0-RTT resumption on the server side.
	// Set this to true if any RPC handler is non-idempotent — 0-RTT
	// data is replayable by an active network adversary.
	RejectEarlyData bool
}

// cloneClientTLS clones a tls.Config but ensures the result has
// VerifyPeerCertificate set up for client mode. We leave most of
// the user's config alone — only ALPN / curves / MinVersion will
// be defaulted later inside applyZAPDefaults.
func cloneClientTLS(in *tls.Config) *tls.Config {
	if in == nil {
		return nil
	}
	return in.Clone()
}
