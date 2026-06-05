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

### Read-buffer pool (bufpool.go)

The TCP dispatch read path sources frame buffers from a quantized
`sync.Pool` (`64B / 256B / 1 KiB / 4 KiB / 16 KiB / 64 KiB`) via
`readMessageRawPooled` + refcounted `*bufRef`. `Message` carries an
optional `refs *bufRef`; `Message.Release()` decrements the refcount
and (at zero) returns the slab. `Message.Retain()` extends lifetime
across goroutine boundaries (e.g. when a Call response is delivered
via channel).

Wire format is byte-identical — only the buffer lifecycle changed.
Frames over 64 KiB fall back to a one-off heap alloc transparent to
the caller. `Message.Release()` on a Builder-built or unpooled
message is a no-op so existing callers keep working unmodified.

Read benchmarks (Apple M1 Max, `go test -bench='BenchmarkRead'
-benchtime=2s -count=2`):

| Size  | Legacy ns/op | Pooled ns/op | Speedup | Allocs (legacy → pooled) |
|-------|--------------|--------------|---------|--------------------------|
| 64B   | 38           | 40           | 1.0x    | 2 → 1, 68 → 4 B/op       |
| 256B  | 68           | 43           | 1.6x    | 2 → 1, 260 → 4 B/op      |
| 1KB   | 284          | 54           | 5.3x    | 2 → 1, 1028 → 4 B/op     |
| 4KB   | 716          | 125          | 5.7x    | 2 → 1, 4100 → 4 B/op     |
| 16KB  | 2244         | 355          | 6.3x    | 2 → 1, 16388 → 4 B/op    |
| 64KB  | 4802         | 1142         | 4.2x    | 2 → 1, 65540 → 4 B/op    |

### Per-Call QUIC streams (TransportStreamer)

`Node.Call` over QUIC opens a fresh per-Call bidirectional stream via
`TransportStreamer.OpenCallStream` instead of serializing on the
shared control stream's `ctrlMu`. The server-side `acceptCallStreams`
goroutine spawns one handler goroutine per accepted stream so
concurrent Calls execute in parallel up to QUIC's stream limit (1024
by default).

Wire format on each per-Call stream is one length-prefixed ZAP frame
in each direction — no correlation header needed since each stream
carries exactly one request + one response.

Per-stream is the only Call path on QUIC; there is no fallback. The
control stream carries one-way Sends only.

End-to-end Call throughput (2 ms simulated handler):

| Concurrency | Per-stream  | Reference   | Speedup |
|-------------|-------------|-------------|---------|
| 1 worker    | 3.19 ms/op  | 3.17 ms/op  | 1.0x    |
| 10 workers  | 1.24 ms/op  | 3.01 ms/op  | 2.4x    |
| 100 workers | 1.06 ms/op  | 3.01 ms/op  | 2.85x   |

Reference = handler latency on a serialized control-stream path
(pre-optimization measurement, retained for context). Per-stream
overlaps handlers in flight (peak inflight = 32 observed in
`TestQUICCallConcurrent`).
