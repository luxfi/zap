# LLM.md - Hanzo Zap

## Overview
Go module: github.com/luxfi/zap

## Tech Stack
- **Language**: Go

## Build & Run
```bash
go build ./...
go test ./...
```

## Structure
```
zap/
  LICENSE
  README.md
  bench/
  benchmark_test.go
  builder.go
  consensus_test.go
  evm.go
  examples/
  go.mod
  go.sum
  grpc_comparison_test.go
  local_consensus_test.go
  mcp/
  mcp_bench_test.go
  memory_bench_test.go
```

## Key Files
- `README.md` -- Project documentation
- `go.mod` -- Go module definition

## PQ-TLS Support
Set `NodeConfig.TLS` to a `*tls.Config` to wrap all TCP connections
(listener, getOrConnect, ConnectDirect) with TLS. Supports PQ-TLS 1.3
when the Go runtime provides post-quantum key exchange (X25519Kyber768).
When `TLS` is nil (the default), connections are plaintext -- fully
backward compatible.

### QUIC transport (TLS 1.3 + X25519MLKEM768 by default)

`github.com/luxfi/zap/quic` provides a QUIC transport with TLS 1.3 and
the IANA-registered hybrid post-quantum key exchange `X25519MLKEM768`
(NamedGroup `0x11ec`) preferred by default. Opt in with:

```go
import _ "github.com/luxfi/zap/quic" // registers the QUIC factory

n := zap.NewNode(zap.NodeConfig{
    NodeID:    "node-a",
    Port:      9999,
    TLS:       tlsCfg,            // server Certificates required
    Transport: zap.TransportQUIC, // default stays TransportTCP
})
```

The QUIC transport adds, beyond what TCP+TLS gives:

- Multiplexed bidi/uni streams (one ZAP message exchange per stream).
- Connection migration on local-IP changes.
- 0-RTT resumption via TLS 1.3 session tickets (set
  `quic.Config{RejectEarlyData: true}` to force 1-RTT for
  non-idempotent handlers).
- ALPN allowlist `zap/1` only.

See `quic/README.md` for details, defaults, deployment notes, and the
threat-model discussion.
