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

### GPU-aware `transport/` subpackage (LP-203 zero-copy)

`github.com/luxfi/zap/transport` registers four implementations behind
the same `Transport` interface:

| Name        | Build tags                          | Wire           | GPU-resident bytes |
|-------------|-------------------------------------|----------------|--------------------|
| `default`   | always                              | in-proc / TCP  | no                 |
| `uma`       | `cgo,linux,cuda` or `cgo,darwin`    | NIC → managed  | yes (cudaMallocManaged on linux, MTLBuffer on darwin) |
| `gpudirect` | `cgo,linux,gpudirect,cuda`          | NIC → GPU VRAM | yes (DMA-buf MR)   |
| `dpdk`      | `cgo,linux,dpdk` + `pkg-config libdpdk` | NIC poll loop | no (CPU hugepage)  |

`transport.Pick("")` selects in order `gpudirect > dpdk > uma >
default`. An operator override via `ZAP_TRANSPORT={default,uma,gpudirect,
dpdk}` returns ErrNotAvailable on a host that can't provide it (no
silent fallback when the operator was explicit).

Transports that can hand out GPU-resident buffers also implement
`BufferAllocator`:

```go
tr, _ := transport.Pick("uma")
alloc, ok := tr.(transport.BufferAllocator)
if !ok { /* default transport — heap allocate */ }
buf, _ := alloc.AllocBuffer(1 << 20)        // 1 MiB managed slab
copy(buf.Bytes(), payload)                  // CPU writes
gpuKernel.launch(buf.DevicePtr(), 1<<20)    // GPU reads same bytes
buf.Release()                                // back to slab pool
```

UMA pool is slab-allocated (`slabClasses = 256B, 1KiB, 4KiB, 16KiB,
64KiB, 1MiB`). Pool budget defaults to 4 GiB via `ZAP_UMA_POOL_BYTES`.
Sizes above 1 MiB take a cold-path `cudaMallocManaged` per call.

Boot emits one `slog.Info` line listing the chosen transport + probe
errors for the others. Silence with `ZAP_TRANSPORT_QUIET=1`.

Probe gaps are reported honestly: on a host with libibverbs but no
Mellanox HCA visible, `Pick("gpudirect")` returns
`missing prereq(s): [ibverbs-device raw-packet-cap nvidia-peermem]`
— never a fake success.
