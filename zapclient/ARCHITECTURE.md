# Internal Traffic on Native ZAP — Architecture

## Wire-layer separation

ZAP is its own binary protocol — **not** layered on HTTP. Two
audiences, two transport choices:

```
                    PUBLIC INTERNET / EXTERNAL CALLERS
                    (browsers, partners, CLIs, mobile)
                                  │
                                  │  HTTP/1.1 + JSON
                                  │  HTTPS / public-CA TLS
                                  ▼
                  ┌───────────────────────────────────────┐
                  │  Ingress (hanzoai/ingress)            │
                  │  - terminates public TLS              │
                  │  - JWT validation                     │
                  │  - rate-limit, WAF                    │
                  └────────────────┬──────────────────────┘
                                   │
                                   │  HTTP → ZAP at the edge
                                   │  (Ingress speaks both)
                                   │
                  ─────────────────┼─────────────────  cluster boundary
                                   │
                                   │ Native ZAP (zap://...)
                                   │ - capnp-flavored zero-copy framing
                                   │ - mDNS service discovery
                                   │ - mTLS w/ cluster CA + ML-DSA + ML-KEM
                                   │ - NO HTTP semantics — uint16 opcodes,
                                   │   procedure-name dispatch
                                   ▼
                  ┌───────────────────────────────────────┐
                  │  Gateway (hanzoai/gateway)            │
                  └────────────────┬──────────────────────┘
                                   │
                                   │ Native ZAP
                                   ▼
       ┌───────────────────────────┴─────────────────────────────┐
       ▼                           ▼                              ▼
┌────────────┐             ┌────────────┐                  ┌────────────┐
│   ATS      │  Native ZAP │    BD      │   Native ZAP     │    TA      │
└─────┬──────┘             └─────┬──────┘                  └─────┬──────┘
      │                          │                               │
      │  Native ZAP              │  Native ZAP                   │
      ▼                          ▼                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Hanzo Tasks (hanzoai/tasks) — durable workflow + cron                  │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ Native ZAP
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Hanzo S3 (hanzos3/s3) — SQLite WAL replication target                  │
└─────────────────────────────────────────────────────────────────────────┘
```

```
                  BROWSER CLIENTS (in-cluster web UIs)
                            │
                            │  ZAP-over-SSE  (one-way server push)
                            │  or ZAP-over-WS (full-duplex, optional)
                            ▼
                  ┌─────────────────────────────────┐
                  │  zapsse / zapws bridge          │
                  │  (per-service edge component)   │
                  └─────────────┬───────────────────┘
                                │ Native ZAP
                                ▼
                       (rest of the cluster)
```

## Three transports, three audiences

1. **Native ZAP (`zap://`)** — service-to-service inside the trust
   boundary. The default for everything past Ingress.
2. **SSE** — server-pushed events to web clients. Used by SPAs +
   browser UIs that subscribe to streams (market ticks, audit feed,
   live order updates).
3. **WebSocket** — full-duplex for the same browser tier when SSE's
   one-way limitation is the wrong primitive (interactive auth
   flows, collaborative editing). Optional — adopt only when SSE
   cannot do the job.

**HTTP/REST is reserved for the public-edge Ingress.** No
service-to-service code path inside the cluster sends an HTTP
request — every internal hop is native ZAP.

## Code pattern

### Server side (e.g. TA exposes SecurityAdmin):

```go
import "github.com/luxfi/zap/zapclient"

srv, _ := zapclient.NewServer("liquidity-ta",
    zapclient.WithServerNodeID(os.Getenv("POD_NAME")),
    zapclient.WithServerTLS(clusterMTLS()),
    zapclient.WithVerifier(zapclient.LocalTrustVerifier{}),
)

srv.Register("ListSecurity",  taHandler.ListSecurity)
srv.Register("DelistSecurity", taHandler.DelistSecurity)
srv.Register("AddIdentity",   taHandler.AddIdentity)
srv.Register("AddIdentitiesBulk", taHandler.AddIdentitiesBulk)

_ = srv.Start()
defer srv.Stop()
```

### Client side (e.g. BD calls TA):

```go
import "github.com/luxfi/zap/zapclient"

ta, _ := zapclient.Connect(ctx, "liquidity-ta",
    zapclient.WithNodeID(os.Getenv("POD_NAME")),
    zapclient.WithTLS(clusterMTLS()),
)
defer ta.Close()

resp, err := ta.Call(ctx, "ListSecurity", req)
```

### Browser side (one-way subscribe to ATS market ticks):

```go
// service-side: serve SSE on a small HTTP listener at the edge
// of the service. Implementation lives in a sibling zapsse package.
http.Handle("/v1/stream/ticks", zapsse.Handler(srv, "MarketTicks"))
```

```js
// browser-side: standard EventSource API
const es = new EventSource("/v1/stream/ticks");
es.onmessage = (e) => { /* binary or JSON frame */ };
```

## Discovery + trust

- **Discovery**: mDNS. Service-type names are stable strings like
  `liquidity-ta`, `hanzo-tasks`, `hanzo-s3`. Each service advertises
  itself; clients browse. Picker selects which peer to call per
  request (default round-robin).
- **Trust**: cluster CA + mTLS. ZAP TLS verifies peer certs against
  the cluster CA root. The `LocalTrustVerifier` (default) accepts any
  peer that presented a valid cert. `AllowListVerifier` restricts a
  procedure to a named NodeID set.
- **Per-call identity**: the authenticated peer NodeID is surfaced to
  the procedure handler in `PeerInfo`. Procedure handlers apply
  per-call RBAC against that identity.

## Migration order (service-by-service)

Each migration step is independent — one service can speak native ZAP
to its peers while another still uses HTTP. The cluster runs both
fabrics during the transition.

| Phase | Service                | Action                                       |
|-------|------------------------|----------------------------------------------|
| 1     | hanzoai/tasks          | Already supports ZAP via tasks-client.       |
| 1     | hanzoai/replicate/s3   | Wire ZAP transport via Client.HTTPClient.    |
| 2     | liquidityio/ta         | NewServer + Register procedures.             |
| 2     | liquidityio/bd         | Connect to TA; deprecate BD's HTTP shim.     |
| 3     | liquidityio/ats        | NewServer + Register; clients of BD migrate. |
| 4     | hanzoai/gateway        | Native-ZAP fan-out for in-cluster routes.    |
| 5     | hanzoai/ingress        | Ingress speaks both: HTTP in, ZAP out.       |
| 6     | Browser-facing streams | zapsse handlers per service.                 |

## What this is NOT

- **Not a service mesh.** No sidecar terminates anything; the app
  speaks ZAP directly.
- **Not gRPC.** gRPC is HTTP/2 + protobuf; ZAP is its own framing +
  zero-copy. No protobuf required; capnp-flavored zero-copy reads.
- **Not REST.** No URL paths, no verbs. Procedure names dispatch to
  uint16 opcodes via FNV-1a.
- **Not a transport wrapper around HTTP.** Earlier drafts of this
  package mistakenly built `clienthttp` on `zap-proto/http`. That
  blended the two protocols — gone. The canonical path is native ZAP
  for S2S; HTTP only at the public Ingress edge.
