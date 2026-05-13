# clienthttp — Security & Trust Model

## Two operating modes

`clienthttp` is used in two postures. Pick the right one per call site.

### Bearer-auth mode (default — internet-facing or cross-cluster)

```go
c, stop, _ := clienthttp.NewClient("liquidity-ta",
    clienthttp.WithBearer(os.Getenv("BD_SIGNING_KEY")),
)
```

- Every outbound request carries `Authorization: Bearer <key>`.
- The server validates the bearer like any normal HTTP API.
- Use this when **any** of these is true:
  - The peer might be reachable over the public internet.
  - The peer might be in a different cluster / different trust root.
  - The peer is an ingress shim that re-broadcasts the request elsewhere.

### Local-trust mode (in-cluster S2S only)

```go
c, stop, _ := clienthttp.NewClient("liquidity-ta",
    clienthttp.WithLocalTrust(),
)
```

- No `Authorization` header attached.
- Trust comes from the ZAP-mDNS scope: the peer is reachable **only**
  because it announced itself on the same mDNS multicast scope and the
  ZAP transport's TLS handshake verified it against the cluster CA.
- Use this when **all** of these are true:
  1. The caller runs inside the cluster's private network (k8s pod
     network, VPC-private subnet, dedicated L2). mDNS multicast does
     not cross this boundary.
  2. The cluster CA is private to the cluster, not the public-web PKI.
     A device on the same L2 with a public-CA cert cannot impersonate
     a peer.
  3. The peer's ZAP TLS config requires client + server certs both
     signed by the cluster CA. (One-way TLS is **not** enough — that
     proves the server identity but not the caller identity.)

If any of those three is uncertain, fall back to bearer-auth mode.
Local-trust is the more efficient posture; bearer-auth is the safer
default.

## Defence-in-depth checklist

Even under local-trust, server-side handlers MUST still:

- **Authorize the action**, not just the peer. The mDNS scope says
  "you're inside the cluster"; it does not say "you are allowed to
  do this particular thing." Apply RBAC / capability checks per
  request regardless of mode.
- **Validate input**. Local-trust does not imply input is well-formed.
- **Rate-limit by peer NodeID**. A compromised in-cluster service
  should not be able to DoS its neighbors.
- **Audit-log the actor**. The peer NodeID from `clienthttp.Peer`
  belongs in the audit envelope; trust mode does not change that.

## Threat model

| Threat | Bearer-auth | Local-trust |
|---|---|---|
| Bearer key leak | Compromised callers can impersonate the service until rotation | Not applicable — no bearer |
| L2 attacker on same network with rogue mDNS announcement | Caller picks rogue peer; bearer attached; bearer leaks | Caller picks rogue peer; **mTLS handshake fails on cluster CA**; request never sends |
| Cluster CA private key compromise | Not applicable — bearer still required | Adversary forges valid certs and impersonates real peer; **catastrophic** |
| Network partition isolates a stale peer | Stale peer answers stale data; bearer still validated | Stale peer answers stale data; trust holds because it's the same cluster CA |
| Per-call bearer override (e.g. impersonation-on-behalf-of token) | Caller sets `req.Header.Set("Authorization", ...)`; per-call header wins | Per-call header also works — local-trust does not erase headers |

The cluster CA is the load-bearing root under local-trust. Treat its
key like the most sensitive secret in the cluster: KMS-resident, ML-KEM
wrapped where applicable, with rotation drills tested twice a year.

## Why not always use bearer-auth?

Two reasons:

1. **One credential bag per process.** A BD pod that talks to ATS, TA,
   and several internal services needs one bearer per peer in
   bearer-auth mode. Each one is a new secret to rotate, leak-detect,
   and key-mgmt. Local-trust collapses all of those to a single trust
   root: the cluster CA.

2. **Latency + memory.** Header construction + server-side bearer
   validation is real work on the hot path. For S2S calls inside a
   single cluster, the work is wasted — the mTLS handshake has
   already proved identity.

For internet-facing or cross-cluster calls neither argument applies —
use bearer-auth there.
