"""omnihost / omnimcp / omnibrowser — unified mDNS discovery surface.

Same wire (`_hanzo._tcp.local.`) for everything: any host process, any
MCP server, any browser endpoint. The TXT `role` key disambiguates.

Why one type and not three:
    Discovery cost is O(n) on the wire regardless. One service-type means
    every consumer can browse once and filter by role — agents that span
    roles (e.g. a tool that wants both an MCP and a browser) get a single
    snapshot, not three.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from zap_mdns import publish as _publish_zap, browse as _browse_zap, ZapService


HANZO_SERVICE = "_hanzo._tcp.local."  # canonical for omni-anything

# Backwards-compat: ZAP-only services keep their narrower type so existing
# extensions that only browse `_hanzo-zap._tcp.local.` keep working until
# they migrate.


@dataclass
class OmniService:
    role: str                    # mcp | browser | host | gateway
    server_id: str
    host: str
    port: int
    org: str = "hanzo"           # hanzo | lux | zoo | osage | liquidity
    proto: str = "zap/1"
    version: str = ""
    capabilities: list[str] = field(default_factory=list)
    agent_label: str = ""

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}/"

    @classmethod
    def from_zap(cls, s: ZapService, role: str = "mcp") -> "OmniService":
        return cls(
            role=role,
            server_id=s.server_id,
            host=s.host,
            port=s.port,
            agent_label=s.agent_label,
            version=s.version,
            capabilities=list(s.capabilities or []),
            proto=s.proto,
        )


def publish_mcp(port: int, server_id: str, **kw):
    """Publish an MCP service (the most common case)."""
    return _publish_zap(port=port, server_id=server_id, **kw)


def publish_browser(port: int, server_id: str, browser_name: str, version: str = "", **kw):
    """Publish a browser-automation endpoint (browser extension)."""
    caps = list(kw.pop("capabilities", []))
    return _publish_zap(
        port=port,
        server_id=server_id,
        version=version,
        capabilities=[f"browser={browser_name}", *caps],
        **kw,
    )


def publish_host(port: int, server_id: str, **kw):
    """Publish a generic host endpoint (omnihost — opt-in services)."""
    return _publish_zap(port=port, server_id=server_id, **kw)


def browse_all(timeout: float = 2.0, role: Optional[str] = None) -> list[OmniService]:
    """Return live services. Filter by role if specified."""
    items = [OmniService.from_zap(s) for s in _browse_zap(timeout=timeout)]
    if role:
        items = [i for i in items if i.role == role]
    return items


def find_browser(timeout: float = 2.0, browser_name: Optional[str] = None) -> list[OmniService]:
    """Locate every browser-role endpoint, optionally filtering by browser
    (firefox/chrome/edge/safari)."""
    out = []
    for s in browse_all(timeout=timeout):
        for cap in s.capabilities:
            if cap.startswith("browser="):
                if browser_name is None or cap == f"browser={browser_name}":
                    out.append(s)
                break
    return out


def find_mcp(timeout: float = 2.0) -> list[OmniService]:
    """Locate every MCP server on the LAN."""
    return browse_all(timeout=timeout, role="mcp")


if __name__ == "__main__":
    import sys, json
    role = sys.argv[1] if len(sys.argv) >= 2 else None
    services = browse_all(timeout=2.5, role=role)
    if not services:
        print("(no services found)")
        sys.exit(0)
    for s in services:
        print(json.dumps({
            "role": s.role, "server_id": s.server_id, "url": s.url,
            "version": s.version, "agent_label": s.agent_label,
            "capabilities": s.capabilities,
        }))
