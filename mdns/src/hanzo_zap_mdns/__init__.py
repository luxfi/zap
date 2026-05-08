"""mDNS publisher / browser for ZAP services.

Publishers (every hanzo-mcp instance) call ``publish(port, server_id, ...)``
once after binding their ZAP socket. Consumers (browser extensions,
hanzo-dev, anyone wanting to talk to a ZAP server) call ``browse(timeout=2)``
to get the live list — no port assumptions, no registry files.

Service definition:
    type:  _hanzo-zap._tcp.local.
    txt:   server_id, agent_label, version, capabilities, proto

Requires ``zeroconf`` (pip install zeroconf). Falls back gracefully if
the dependency is unavailable.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

SERVICE_TYPE = "_hanzo-zap._tcp.local."


@dataclass
class ZapService:
    server_id: str
    host: str
    port: int
    agent_label: str = ""
    version: str = ""
    capabilities: list[str] = None
    proto: str = "zap/1"

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}/"


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class _NoopPublisher:
    """Used when zeroconf isn't installed; publish() is a no-op."""

    def __init__(self, service: ZapService) -> None:
        self.service = service

    def close(self) -> None:
        pass


def publish(
    port: int,
    server_id: str,
    *,
    agent_label: str = "",
    version: str = "",
    capabilities: Optional[list[str]] = None,
    host: Optional[str] = None,
):
    """Advertise a ZAP service on the local network. Returns a publisher
    handle whose ``close()`` retracts the announcement."""
    service = ZapService(
        server_id=server_id,
        host=host or _local_ip(),
        port=port,
        agent_label=agent_label,
        version=version,
        capabilities=capabilities or [],
    )
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError:
        return _NoopPublisher(service)

    properties = {
        b"server_id": service.server_id.encode(),
        b"agent_label": service.agent_label.encode(),
        b"version": service.version.encode(),
        b"capabilities": ",".join(service.capabilities).encode(),
        b"proto": service.proto.encode(),
    }
    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=f"{service.server_id}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(service.host)],
        port=service.port,
        properties=properties,
        server=f"{service.server_id}.local.",
    )
    zc = Zeroconf()
    zc.register_service(info)

    class _Publisher:
        def __init__(self):
            self.service = service
            self._zc = zc
            self._info = info

        def close(self) -> None:
            try:
                self._zc.unregister_service(self._info)
            finally:
                self._zc.close()

    return _Publisher()


def browse(timeout: float = 2.0) -> list[ZapService]:
    """Return every live ZAP service on the LAN. Blocks up to ``timeout``."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
    except ImportError:
        return []

    found: list[ZapService] = []

    class Listener(ServiceListener):
        def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name, timeout=int(timeout * 1000))
            if info is None or not info.addresses:
                return
            host = socket.inet_ntoa(info.addresses[0])
            props = {
                k.decode(): (v.decode() if isinstance(v, (bytes, bytearray)) else "")
                for k, v in (info.properties or {}).items()
            }
            found.append(
                ZapService(
                    server_id=props.get("server_id", name.split(".")[0]),
                    host=host,
                    port=info.port or 0,
                    agent_label=props.get("agent_label", ""),
                    version=props.get("version", ""),
                    capabilities=[c for c in props.get("capabilities", "").split(",") if c],
                    proto=props.get("proto", "zap/1"),
                )
            )

        def remove_service(self, *_args, **_kwargs) -> None: ...
        def update_service(self, *_args, **_kwargs) -> None: ...

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, SERVICE_TYPE, Listener())
        import time as _t
        _t.sleep(timeout)
    finally:
        zc.close()
    return found


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "browse":
        for s in browse():
            print(f"{s.server_id:32s} {s.url:32s} agent={s.agent_label} ver={s.version}")
        sys.exit(0)

    print(f"usage: {sys.argv[0]} browse")
