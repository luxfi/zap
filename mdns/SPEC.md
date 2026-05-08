# Hanzo Service Discovery Spec

Every Hanzo-domain service on the local network advertises itself via mDNS so
peers — agents, tools, dashboards, the browser extension, hanzo-mcp itself —
discover it without configuration. The transport over the wire is **ZAP**
(Zero-latency Agent Protocol, ws-binary frame format defined by `zap-protocol`).

## Canonical service type

```
_hanzo._tcp.local.
```

One type for every role. Role differentiation is in the TXT record, not the
service-type. This means a single mDNS browse retrieves the entire mesh; the
caller filters by `role`.

## TXT keys (REQUIRED unless noted)

| key            | value                                                  |
|----------------|--------------------------------------------------------|
| `role`         | `mcp` \| `iam` \| `kms` \| `mpc` \| `base` \| `engine` \| `browser` \| `node` \| `desktop` \| `gateway` \| `static` |
| `server_id`    | unique stable identifier (`<role>-<host>-<pid>` recommended) |
| `org`          | `hanzo` \| `lux` \| `zoo` \| `osage` \| `liquidity` (default `hanzo`) |
| `version`      | semver of the service                                  |
| `proto`        | wire protocol identifier (`zap/1`, `http/1.1`, `grpc/1`) |
| `capabilities` | comma-separated capability list                        |
| `agent_label`  | OPTIONAL human-friendly label                          |
| `auth`         | OPTIONAL — `none` \| `iam` \| `mtls`                   |

## Role contracts

Each role MUST advertise the listed capabilities and accept the listed methods
over its protocol. Methods are JSON-RPC-style for ZAP, REST paths for HTTP.

### `role=mcp`
- protocol: `zap/1`
- methods: `tools/list`, `tools/call`, `prompts/list`, `prompts/get`,
  `resources/list`, `resources/read`
- capabilities include the names of the tools exposed.

### `role=iam`  (Hanzo IAM — Casdoor-derived)
- protocol: `zap/1` or `http/1.1` (or both — mDNS may publish two records)
- ZAP methods: `iam.login`, `iam.token.exchange`, `iam.user.get`,
  `iam.user.list`, `iam.session.refresh`, `iam.session.revoke`
- HTTP equivalents at `/v1/iam/*`.

### `role=kms`  (Hanzo KMS — secrets + signing)
- ZAP methods: `kms.kv.get`, `kms.kv.put`, `kms.kv.list`, `kms.kv.delete`,
  `kms.sign`, `kms.verify`, `kms.encrypt`, `kms.decrypt`,
  `kms.key.generate`, `kms.key.list`, `kms.key.delete`
- Auth: always `iam` or `mtls`.

### `role=mpc`  (multi-party compute / threshold signing)
- ZAP methods: `mpc.session.start`, `mpc.session.join`,
  `mpc.session.contribute`, `mpc.session.finalize`, `mpc.session.status`
- capabilities lists the supported curves: `secp256k1,ed25519,bls12-381`

### `role=base`  (Hanzo Base — embedded record store, IAM-native)
- ZAP methods: `base.collection.list`, `base.collection.get`,
  `base.record.list`, `base.record.get`, `base.record.create`,
  `base.record.update`, `base.record.delete`, `base.subscribe`
- capabilities lists the schemas the instance hosts.

### `role=engine`  (LLM serving / Hanzo Engine)
- ZAP methods: `engine.completion`, `engine.chat`, `engine.embed`,
  `engine.tokenize`, `engine.models.list`
- capabilities lists the loaded models.

### `role=browser`  (extension or browser-control endpoint)
- ZAP methods: `hanzo.listTabs`, `hanzo.screenshot`, `Page.navigate`,
  `Runtime.evaluate`, … (CDP-flavoured)
- capabilities lists supported actions per browser engine.

### `role=node`  (Hanzo Node — agentic infrastructure)
- ZAP methods: `node.status`, `node.peers.list`, `node.task.submit`,
  `node.task.status`

### `role=desktop`  (Hanzo Desktop — Electron host)
- ZAP methods: `desktop.window.list`, `desktop.window.focus`,
  `desktop.notify`, `desktop.shell.open`

### `role=gateway`  (api.hanzo.ai-style ingress)
- protocol: `http/1.1` (mDNS just for local LAN discovery)
- HTTP routes follow the platform's `/v1/<role>/*` convention.

### `role=static`  (CDN-style static asset serving)
- protocol: `http/1.1`
- capabilities: `etag,range,gzip,brotli`

## hanzo-mcp auto-discovery

`hanzo-mcp` browses `_hanzo._tcp.local.` at startup, maps each discovered
service into a namespaced tool family on its own MCP surface:

```
iam.*   → routed via ZAP/HTTP to role=iam
kms.*   → routed to role=kms
mpc.*   → routed to role=mpc
base.*  → routed to role=base
engine.* → routed to role=engine
browser.* → routed to role=browser (the extension)
```

Tool surface re-evaluates every 30 s — services coming online become
available without restarting Claude. Going offline removes them from the
manifest.

## Single source of truth

All publish/browse calls — Python, Node, Go, Rust, Swift — go through a
language binding of `@hanzo/zap-mdns`. The package owns the service-type
constant, the TXT key list, and the role enum. No handwritten mDNS
records anywhere in the tree.

| language     | package                                              |
|--------------|------------------------------------------------------|
| Python       | `hanzo-zap-mdns` (`pip install`, `~/work/zap/mdns/`) |
| TypeScript   | `@hanzo/zap-mdns`     (planned)                      |
| Go           | `github.com/hanzoai/zap-mdns-go` (planned)           |
| Rust         | `hanzo-zap-mdns`      (planned)                      |
