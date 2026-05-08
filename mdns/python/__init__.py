"""@hanzo/zap-mdns — unified network discovery for ZAP services.

Exports:
    publish(...)        — advertise a ZAP service (any role)
    browse(...)         — list live services on the LAN

Roles (TXT key `role`):
    mcp         — model context protocol server
    browser     — browser extension/automation endpoint
    host        — generic host service (omnihost)
    gateway     — request gateway / reverse proxy
"""

from .zap_mdns import (
    publish,
    browse,
    ZapService,
    SERVICE_TYPE,
)

__all__ = ["publish", "browse", "ZapService", "SERVICE_TYPE"]
