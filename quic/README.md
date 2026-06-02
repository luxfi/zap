# zap/quic — QUIC transport for ZAP

`github.com/luxfi/zap/quic` is the canonical QUIC transport for the ZAP
messaging substrate (KMS, MPC, IAM, arcd, every Hanzo / Lux service that
embeds ZAP).

It wraps `github.com/quic-go/quic-go` and exposes:

- TLS 1.3 with the IANA-registered hybrid post-quantum key exchange
  `X25519MLKEM768` (NamedGroup `0x11ec`) as the default.
- Multiplexed bidirectional + unidirectional streams over one
  connection (one ZAP message exchange per stream).
- Connection migration on local-IP changes (Wi-Fi to LTE, NAT rebind).
- 0-RTT resumption via TLS 1.3 session tickets.
- ALPN allowlist: `zap/1` only — other ALPN values are rejected at
  the TLS layer and again post-handshake as belt-and-suspenders.

## When to pick QUIC over TCP

QUIC is the better choice when **any one** of these applies:

- The connection serves many concurrent independent RPCs (KMS, MPC,
  threshold orchestrators). QUIC eliminates head-of-line blocking
  between streams.
- The client moves networks (laptop, validator that re-homes between
  ASNs, K8s pod migrated between nodes). The QUIC connection ID
  survives the path change; TCP would tear down.
- The latency budget cares about 0-RTT resumption. Repeat connections
  to a cached peer skip a round trip.

TCP is the better choice when middleboxes / firewalls block UDP, or
when the peer link is a kernel TCP pipe and the binary cannot afford
the UDP per-packet syscall overhead.

`NodeConfig.Transport` selects between them. Default is `TransportTCP`
for back-compat — every existing consumer keeps working untouched.

## Quick start

### As a standalone QUIC server / client

```go
import (
    "context"
    "crypto/tls"

    zapquic "github.com/luxfi/zap/quic"
)

cert, _ := zapquic.GenerateSelfSignedCert("example.com")
srv, _ := zapquic.Listen(zapquic.ServerConfig{
    NodeID: "node-a",
    Addr:   ":9999",
    TLS:    &tls.Config{Certificates: []tls.Certificate{cert}},
})
defer srv.Close()

go func() {
    for {
        c, err := srv.Accept(context.Background())
        if err != nil { return }
        go handle(c)
    }
}()

cli, _ := zapquic.NewClient(zapquic.ClientConfig{
    NodeID: "node-b",
    TLS:    &tls.Config{RootCAs: trustedCAs},
})
defer cli.Close()

c, _ := cli.Dial(context.Background(), "node-a.example.com:9999")
c.Send(reqBytes)
respBytes, _ := c.Recv()
```

### Via the ZAP Node API

```go
import (
    "github.com/luxfi/zap"
    _ "github.com/luxfi/zap/quic" // registers the QUIC TransportFactory
)

n := zap.NewNode(zap.NodeConfig{
    NodeID:    "node-a",
    Port:      9999,
    TLS:       tlsCfg,            // must contain server Certificates
    Transport: zap.TransportQUIC, // opt-in; default stays TCP
})
n.Start()
```

All existing `Handle` / `Send` / `Call` / `Broadcast` / `ConnectDirect`
calls work identically.

## Production deployment notes

- **UDP port reachability**: most cloud / on-prem firewalls deny UDP
  by default. Open the ZAP port (default 9999) explicitly for UDP.
- **MTU**: quic-go picks a safe IPv6 baseline (1232) but will probe up
  to the path MTU. On overlay networks (VXLAN, IP-in-IP, WireGuard)
  set `quic.Config.InitialPacketSize` conservatively to avoid PMTUD
  blackholes.
- **ECN**: Linux kernels >= 4.18 support QUIC ECN out of the box.
  No application-level configuration required.
- **Receive buffer**: quic-go warns on small SO_RCVBUF. On Linux:
  `sysctl -w net.core.rmem_max=7500000`.
- **Connection migration**: works automatically across local NAT
  rebinds. Cross-server migration (load balancer switching the
  backend) requires shared connection-ID state — out of scope for
  this transport.
- **0-RTT replay**: enabled by default. Application handlers MUST be
  idempotent, or set `ServerConfig.RejectEarlyData = true` to force a
  full 1-RTT handshake for every connection.

## Cipher and KEM defaults

Defaults installed by `applyZAPDefaults` (see `tls.go`):

| Field | Default |
|-------|---------|
| `MinVersion` | TLS 1.3 (required for ML-KEM) |
| `CurvePreferences` | `[X25519MLKEM768, X25519]` |
| `NextProtos` | `["zap/1"]` |
| `ClientSessionCache` (client) | in-memory LRU, 128 entries |
| Session-ticket lifetime | 1 hour (Go stdlib default; not extended) |

Override any field by setting it on `ServerConfig.TLS` / `ClientConfig.TLS`
before calling `Listen` / `NewClient`. `zap/1` is always prepended to the
caller's `NextProtos` if missing.

### Why `X25519MLKEM768`?

`X25519MLKEM768` is the IANA-registered NamedGroup `0x11ec`. It is the
hybrid post-quantum KEM jointly defined by Cloudflare, Google, and the
IETF TLS working group, shipped by Go 1.24+, BoringSSL, Cloudflare
production, and every other modern TLS stack with a PQ story.

The KEM combines:

- **X25519** (RFC 7748) — classical 128-bit ECC security
- **ML-KEM-768** (NIST FIPS 203) — NIST Level 3 lattice security

The combined shared secret is `HKDF-Extract(X25519_ss || MLKEM_ss)`,
performed by Go's `crypto/tls` internally. This package does NOT
implement its own KEM combiner; that would be a custom-crypto path
and a needless attack surface.

We deliberately do **not** ship a hybrid that deviates from `0x11ec`
(no "z-wing" fork, no rolled-our-own ID). Interop with every other
Hanzo / Lux service is the load-bearing property; the moment we
diverge from the IANA registry we lose it.

### Threat model — what is and isn't protected

Hybrid KEM defends against **harvest-now / decrypt-later**: a
captured ciphertext stays confidential even if a quantum adversary
eventually breaks X25519. The KEM half (ML-KEM-768) carries the
post-quantum security; X25519 is the classical fallback.

The server certificate signature is still classical (ECDSA or RSA).
Go's stdlib TLS does not yet support post-quantum signature schemes
(ML-DSA, SLH-DSA). A quantum adversary who can forge today's CA
signature can mount a real-time MITM, but cannot decrypt past
captures. This trade-off is acceptable under the published threat
model and is the same one Cloudflare ships today; for a fully
post-quantum auth path see the PQ-Hybrid-KEM paper at
`../papers/pq-hybrid-kem/main.pdf`.

## API surface

| Type / func | Purpose |
|-------------|---------|
| `Listen(ServerConfig)` | Start a QUIC listener. |
| `NewClient(ClientConfig)` | Construct a client with its own UDP socket. |
| `Server.Accept(ctx)` | Block for the next post-handshake connection. |
| `Client.Dial(ctx, addr)` | 1-RTT dial. |
| `Client.DialEarly(ctx, addr)` | 0-RTT-attempting dial (resumes via session ticket). |
| `Conn.Send(frame)` / `Conn.Recv()` | Send / receive ZAP frames on the control stream. |
| `Conn.OpenStream(ctx)` | Open a new bidirectional QUIC stream for an independent RPC. |
| `Conn.AcceptStream(ctx)` | Accept a peer-initiated bidirectional stream. |
| `Conn.OpenUniStream(ctx)` | Open a unidirectional stream (broadcasts, subscriptions). |
| `Conn.AcceptUniStream(ctx)` | Accept a peer-initiated unidirectional stream. |
| `Conn.ConnectionState()` | TLS connection state — `CurveID` is the negotiated NamedGroup. |
| `Conn.IsZeroRTT()` | Whether the QUIC handshake completed with 0-RTT accepted. |
| `Conn.Close()` | Graceful close: drain control stream, send `CONNECTION_CLOSE(0)`. |
| `GenerateSelfSignedCert(hosts...)` | Test-only ECDSA-P256 cert helper. |
| `ALPN` | `"zap/1"` — the only accepted ALPN. |
| `MaxFrameSize` | 10 MiB — same as the TCP transport. |

## Test vectors

`go test ./quic/... -v` runs the X25519MLKEM768 negotiation assertion
end-to-end. The `TestHandshake_NegotiatesX25519MLKEM768` test fails
loudly if `CurveID != 0x11ec` after either side completes the
handshake — keep it green.

## See also

- `../papers/pq-hybrid-kem/main.pdf` — formal security argument for
  the X25519MLKEM768 hybrid in ZAP's context.
- `../LLM.md` — top-level ZAP overview with the TCP transport.
- [IANA TLS NamedGroup registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
  — `0x11ec` is `X25519MLKEM768`.
- [draft-kwiatkowski-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/)
  — the spec.
