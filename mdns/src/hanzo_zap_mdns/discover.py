"""Discovery + auto-bridge for hanzo-mcp.

`expand_mcp_with_neighbors(server)` browses `_hanzo._tcp.local.`, finds every
peer service, and registers a namespaced tool family on the local MCP for
each role. New tools light up automatically as services join the LAN; gone
services drop off on the next refresh.

Call this once after hanzo-mcp's tool registry is up. Re-call every 30 s
(the spec's recommended re-poll cadence) to track peer churn.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from . import browse, ZapService
from .omni import HANZO_SERVICE  # canonical service type

logger = logging.getLogger(__name__)


# Map mDNS role → method-name prefix the namespaced MCP tool exposes.
ROLE_TO_NAMESPACE: dict[str, str] = {
    "mcp": "",            # peer mcp tools merge in unprefixed (de-duped by name)
    "iam": "iam",
    "kms": "kms",
    "mpc": "mpc",
    "base": "base",
    "engine": "engine",
    "browser": "browser",
    "node": "node",
    "desktop": "desktop",
    "gateway": "gateway",
    "static": "static",
}


async def discover_peers(timeout: float = 2.0) -> list[ZapService]:
    """Return every Hanzo-domain service currently on the LAN."""
    # Run the blocking zeroconf browse on a worker thread.
    return await asyncio.to_thread(browse, timeout)


async def fetch_peer_tools(svc: ZapService, *, timeout: float = 5.0) -> list[dict]:
    """Probe a peer ZAP server for its tool manifest. Best-effort — returns
    [] when the peer doesn't expose tools/list or is unreachable."""
    try:
        import websockets
    except ImportError:
        return []
    import json
    import struct

    MAGIC = b"\x5a\x41\x50\x01"
    MSG_HANDSHAKE = 0x01
    MSG_REQUEST = 0x10

    def encode(t: int, payload):
        body = json.dumps(payload).encode()
        return MAGIC + bytes([t]) + struct.pack(">I", len(body)) + body

    async with websockets.connect(svc.url, open_timeout=timeout) as ws:
        await ws.send(encode(MSG_HANDSHAKE, {
            "clientId": "hanzo-mcp-discover",
            "browser": "hanzo-mcp",
            "version": "discover",
        }))
        # First reply is HANDSHAKE_OK with tools manifest.
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            return []
        if not isinstance(raw, (bytes, bytearray)) or raw[:4] != MAGIC:
            return []
        n = struct.unpack(">I", raw[5:9])[0]
        body = json.loads(raw[9:9 + n].decode())
        return body.get("tools", []) if isinstance(body, dict) else []


def role_of(svc: ZapService) -> str:
    """Pull the role TXT key out of a ZapService, defaulting to 'mcp'."""
    # ZapService doesn't yet store TXT directly; capabilities is a stand-in.
    # First capability that matches a known role wins; otherwise 'mcp'.
    for cap in svc.capabilities or []:
        if cap.startswith("role="):
            return cap.split("=", 1)[1]
    # Fall back to inferring from server_id prefix.
    sid = (svc.server_id or "").lower()
    for known in ROLE_TO_NAMESPACE:
        if sid.startswith(known + "-") or sid.startswith(known + "."):
            return known
    return "mcp"


async def expand_mcp_with_neighbors(
    register_tool: Callable[[str, dict, Callable[[dict], Awaitable[Any]]], None],
    *,
    self_server_id: str | None = None,
    timeout: float = 2.0,
) -> int:
    """Browse the LAN and register a namespaced tool for every neighbour.

    `register_tool(name, schema, handler)` is the local MCP's tool registrar.
    Returns the count of tools registered.
    """
    services = await discover_peers(timeout=timeout)
    n = 0
    for svc in services:
        if self_server_id and svc.server_id == self_server_id:
            continue  # don't re-import our own tools
        role = role_of(svc)
        ns = ROLE_TO_NAMESPACE.get(role, role)
        peer_tools = await fetch_peer_tools(svc, timeout=timeout)
        for t in peer_tools:
            tool_name = f"{ns}.{t['name']}" if ns else t["name"]
            schema = t.get("inputSchema", {"type": "object"})

            def _make_handler(target: ZapService, method: str):
                async def _h(args: dict) -> Any:
                    # Each call opens its own WS — short-lived, no pool. The
                    # peer is on the same machine 99% of the time so
                    # latency is sub-ms even without keep-alive.
                    return await _zap_call(target.url, method, args)
                return _h

            register_tool(tool_name, schema, _make_handler(svc, t["name"]))
            n += 1
    logger.info("expanded MCP with %d neighbour tools across %d services", n, len(services))
    return n


async def _zap_call(url: str, method: str, params: dict, *, timeout: float = 30.0) -> Any:
    """Single-shot ZAP call to a peer. Establishes WS, sends MSG_REQUEST,
    waits for MSG_RESPONSE, closes."""
    import json
    import struct

    import websockets

    MAGIC = b"\x5a\x41\x50\x01"
    MSG_HANDSHAKE = 0x01
    MSG_REQUEST = 0x10
    MSG_RESPONSE = 0x11

    def encode(t: int, payload):
        body = json.dumps(payload).encode()
        return MAGIC + bytes([t]) + struct.pack(">I", len(body)) + body

    async with websockets.connect(url, open_timeout=timeout) as ws:
        await ws.send(encode(MSG_HANDSHAKE, {"clientId": "hanzo-mcp-bridge", "browser": "hanzo-mcp"}))
        # Drain the handshake_ok
        await asyncio.wait_for(ws.recv(), timeout=timeout)
        req_id = "bridge-1"
        await ws.send(encode(MSG_REQUEST, {"id": req_id, "method": method, "params": params}))
        while True:
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
            if not isinstance(raw, (bytes, bytearray)) or raw[:4] != MAGIC:
                continue
            t = raw[4]
            n = struct.unpack(">I", raw[5:9])[0]
            body = json.loads(raw[9:9 + n].decode()) if n else {}
            if t == MSG_RESPONSE and body.get("id") == req_id:
                if "error" in body and body["error"]:
                    err = body["error"]
                    raise RuntimeError(err.get("message") if isinstance(err, dict) else str(err))
                return body.get("result")
