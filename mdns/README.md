# `zap-mdns` — mDNS auto-discovery for ZAP services

Replaces the hard-coded `[9999..9995]` port-probe in browser extensions
and the lock-file dance in `~/.hanzo/extension/config.json` with proper
multicast DNS service discovery (`_hanzo._tcp.local.`, canonical per HIP-0069).

## Why

- ZAP currently fixed-ports collide between agents, hosts, and accidentally
  mature `lqd-check` test daemons.
- Lock-file registry is single-host and fragile (stale PIDs, race on
  finally-cleanup).
- mDNS works across the LAN, multi-MCP, multi-host. Bonjour/Avahi gives us
  service-type browsing for free on every modern OS.

## Service definition

```
type:       _hanzo._tcp.local.
name:       <server_id>._hanzo._tcp.local.
port:       <bound port>
txt:
    server_id   = mcp-py-12345
    agent_label = osage-screenshot-test
    version     = 0.5.0
    capabilities = tabs,navigate,screenshot,evaluate,...
    proto       = zap/1
```

## Layout

```
python/      Python publisher + browser via `zeroconf`
ts/          TypeScript publisher (Node) + browser shim
ext/         Browser-extension polyfill (native-messaging helper)
README.md    this file
```

## Backwards compat

Existing port-probe path remains in the extension as a fallback. mDNS is
attempted FIRST; if zero services found within 2s, fall through to the
fixed-port probe. Once mDNS adoption is stable, port-probe is removed.

## Install

```
pip install zap-mdns
# or
uv pip install zap-mdns
```

## Status

Published on PyPI: <https://pypi.org/project/zap-mdns/> — wired into
`~/work/zap/` for cross-org reuse (hanzo / lux / zoo / liquidity all
consume the same package).
