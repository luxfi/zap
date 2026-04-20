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
