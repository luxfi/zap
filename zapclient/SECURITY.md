# zapclient — Security & Trust Model

## Mental model

ZAP is its own binary protocol with its own TLS handshake. There is
no HTTP `Authorization` header. Identity, encryption, and
authorisation come from three orthogonal sources:

1. **Identity** — the mTLS peer cert, verified by the cluster CA
   during the ZAP transport handshake.
2. **Encryption** — ML-KEM key exchange + AES-256-GCM bulk, baked
   into the ZAP TLS suite. Confidentiality survives a future
   quantum adversary (harvest-now-decrypt-later).
3. **Authorisation** — `PeerVerifier`, run server-side per call.
   Decides whether the authenticated peer is allowed to invoke this
   procedure.

These three are decomplected. Swapping out the TLS suite does not
touch the verifier. Replacing `LocalTrustVerifier` with an
`AllowListVerifier` does not require code changes in the transport.

## Two trust postures

### `LocalTrustVerifier` (default)

```go
srv, _ := zapclient.NewServer("liquidity-ta",
    zapclient.WithServerTLS(clusterMTLS()),
    // verifier omitted → LocalTrustVerifier
)
```

Accepts any peer that completed the cluster-CA mTLS handshake. Use
when:

- The peer is reachable only on the cluster-private network.
- The cluster CA is private to the cluster (not public-web PKI).
- All in-cluster services should be allowed to call all of this
  service's procedures. Per-procedure RBAC, if required, lives in
  the handler — not in the transport.

### `AllowListVerifier`

```go
srv, _ := zapclient.NewServer("liquidity-ta",
    zapclient.WithVerifier(zapclient.AllowListVerifier{
        Allowed: map[string]map[string]struct{}{
            "ListSecurity":   {"bd-prod-0": {}, "bd-prod-1": {}},
            "DelistSecurity": {"bd-prod-0": {}, "bd-prod-1": {}},
            "AddIdentity":    {"bd-prod-0": {}, "bd-prod-1": {}, "kyc-1": {}},
        },
    }),
)
```

Restricts each procedure to a named NodeID set. Use when:

- Stricter posture than "any cluster peer can call any procedure" is
  required (e.g., a treasury procedure that only the BD pods should
  invoke).
- An audit trail of "who can call what" needs to live in the source
  code, not just runtime config.

A procedure not present in the `Allowed` map is **disabled** — the
verifier returns `ErrPeerUnauthorized` for every caller. This makes
new procedures fail-closed by default; opt-in is explicit.

### Custom Verifier

Implement `PeerVerifier` for richer policy (e.g. attestation-bound
NodeIDs, JWT-extracted org IDs, organisation membership lookups).
The verifier runs in the hot path; keep it sub-millisecond and free
of network I/O.

## Defence-in-depth checklist

Even under `LocalTrustVerifier`, server-side handlers MUST still:

- **Authorise the action**. Trust mode says "you're inside the
  cluster"; it does not say "you can do this thing." Apply business
  RBAC per call regardless of mode.
- **Validate input**. ZAP framing is zero-copy — *trust the bytes
  came from a real peer, not that the bytes are well-formed*.
- **Rate-limit by NodeID**. A compromised in-cluster pod should not
  be able to DoS its neighbours.
- **Audit-log the actor**. `PeerInfo.NodeID` (and `TLSCertSubject`
  if available) belongs in the audit envelope. Trust mode does not
  change what gets logged.

## Threat model

| Threat | LocalTrustVerifier | AllowListVerifier |
|---|---|---|
| Compromised in-cluster pod tries to call privileged procedure | Pod gets in (it has a valid cluster cert) — handler-level RBAC must catch it | Pod gets rejected at the verifier unless its NodeID is in the allow list |
| L2 attacker on same network with rogue mDNS announcement | mTLS handshake fails — attacker has no cluster-CA-signed cert | Same — mTLS catches it before the verifier runs |
| Cluster CA private key compromise | Adversary forges valid certs and impersonates real services; catastrophic | Same — the CA is the load-bearing root in both modes |
| Stale peer answers with cached data | Stale peer has a valid cert; verifier accepts; data is wrong but authenticated | Same — staleness is a data problem, not a transport problem |
| Cross-cluster call from a public-internet peer | Should be impossible — mDNS doesn't cross L3 boundaries and the public peer has no cluster CA cert | Same |

The cluster CA is the load-bearing root. Treat its key like the most
sensitive secret in the cluster: KMS-resident, ML-KEM wrapped where
applicable, rotation drills tested twice a year.

## ZAP vs HTTP — why this matters for security

- **HTTP bearer keys** are a finger trap: easy to leak, hard to
  rotate, audit-burden grows linearly with the number of S2S edges.
- **mTLS over the cluster CA** scales sub-linearly: rotate the CA
  once and every service follows; revoke a single pod by
  re-issuing its leaf cert with a shorter TTL.
- **Procedure-name dispatch** (`Call("ListSecurity", req)`) makes
  authorisation decisions per call site, not per endpoint URL. The
  verifier sees the procedure name, the peer identity, and the
  context — that is all the input an authoriser needs.

For web/external clients (browsers, partners) the bearer pattern
still applies, served by the Ingress edge over HTTP. The internal
S2S fabric uses ZAP exclusively.
