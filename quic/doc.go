// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package quic implements the QUIC transport for the ZAP messaging substrate.
//
// QUIC offers, compared to ZAP's existing TCP+TLS transport:
//
//   - Stream multiplexing: N concurrent RPCs over one connection without
//     head-of-line blocking.
//   - Connection migration: the connection survives client-IP changes
//     (Wi-Fi-to-LTE, NAT rebinding, etc.) because the QUIC connection ID
//     is independent of the 5-tuple.
//   - 0-RTT resumption: cached session tickets let the second handshake to
//     a peer complete without a round trip before app data flows.
//   - TLS 1.3 with the X25519MLKEM768 hybrid post-quantum key exchange
//     (IANA NamedGroup 0x11ec) baked in.
//
// # Wire format
//
// One ZAP message is one length-prefixed Cap'n Proto frame on a QUIC stream.
// The frame format is identical to the TCP transport:
//
//	[4-byte little-endian length][ZAP message bytes]
//
// Two stream patterns are used:
//
//   - Bidirectional streams carry one request/response exchange. After the
//     response is written the server side closes its half of the stream and
//     the client closes its half on Recv, freeing the stream ID. This maps
//     onto Node.Call.
//   - Unidirectional streams from the server carry one-way notifications
//     and subscription deliveries. The receiver routes each frame through
//     the same handler dispatch as the TCP path.
//
// The control stream (the first bidirectional stream opened by the dialer)
// carries the 64-byte ZAP node-identity handshake exchanged before any RPC.
//
// # Cryptography
//
// The default TLS 1.3 configuration prefers X25519MLKEM768. That is the
// IANA-registered hybrid: the shared secret is HKDF-Extract of X25519_ss
// concatenated with ML-KEM-768 ciphertext-derived ss. The Go runtime
// performs the combination internally — this package does not roll its
// own KEM combiner. See ../papers/pq-hybrid-kem/main.pdf.
//
// The server certificate signature is still classical (ECDSA or RSA);
// post-quantum signature schemes are not yet wired into Go's stdlib TLS.
// The threat model that motivates X25519MLKEM768 is harvest-now /
// decrypt-later against the confidentiality of the key-exchange, not
// forgery against a trusted-today certificate authority.
//
// # 0-RTT replay
//
// QUIC permits 0-RTT application data, which can be replayed by a network
// adversary. The server defaults to accepting 0-RTT data, but application
// handlers MUST treat 0-RTT-carried RPCs as either idempotent or rejected.
// Use ServerConfig.RejectEarlyData to force a full 1-RTT handshake for
// every connection.
package quic
