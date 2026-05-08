#!/usr/bin/env python3
"""Native-messaging host that bridges the browser extension to mDNS.

Browsers (Chrome, Firefox, Edge) don't expose mDNS APIs to extensions. This
small stdio helper does the browse on the host and pipes results back as
length-prefixed JSON over stdin/stdout per the WebExtensions native-messaging
protocol.

Install:
    1. Build helper:   pyinstaller --onefile helper.py -n hanzo-zap-mdns-helper
    2. Copy binary:    /usr/local/bin/hanzo-zap-mdns-helper
    3. Drop manifest:  ~/Library/Application Support/Mozilla/NativeMessagingHosts/
                       (macOS Firefox) or platform equivalent
    4. Extension calls browser.runtime.sendNativeMessage('ai.hanzo.zap_mdns', {})

Protocol (per WebExtensions native-messaging spec):
    in:  4-byte LE length | UTF-8 JSON request
    out: 4-byte LE length | UTF-8 JSON response

Request:
    { "op": "browse", "timeout_ms"?: 2000 }
    { "op": "publish", "port": N, "server_id": "...", ... }   (host-side advertise)

Response:
    { "ok": true, "services": [ {role, server_id, host, port, ... }, ... ] }
"""

import json
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

try:
    from zap_mdns import browse, publish
except ImportError:
    # Allow the helper to ship as a single bundle; the python module path
    # may differ when packaged with pyinstaller.
    from python.zap_mdns import browse, publish  # type: ignore


def read_message():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    length = struct.unpack('<I', raw)[0]
    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode('utf-8'))


def send_message(obj):
    body = json.dumps(obj).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('<I', len(body)))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def handle(req: dict) -> dict:
    op = req.get('op')
    if op == 'browse':
        timeout = (req.get('timeout_ms') or 2000) / 1000.0
        services = browse(timeout=timeout)
        return {
            'ok': True,
            'services': [
                {
                    'server_id': s.server_id,
                    'host': s.host,
                    'port': s.port,
                    'url': s.url,
                    'agent_label': s.agent_label,
                    'version': s.version,
                    'capabilities': s.capabilities,
                    'proto': s.proto,
                }
                for s in services
            ],
        }
    if op == 'publish':
        # The extension can publish itself as a browser-role service so
        # other agents on the LAN can discover this Firefox/Chrome instance.
        port = int(req['port'])
        server_id = str(req['server_id'])
        publish(
            port=port,
            server_id=server_id,
            agent_label=req.get('agent_label', ''),
            version=req.get('version', ''),
            capabilities=req.get('capabilities', []),
        )
        return {'ok': True}
    return {'ok': False, 'error': f'unknown op: {op}'}


def main():
    while True:
        try:
            req = read_message()
        except Exception as e:
            send_message({'ok': False, 'error': f'read: {e}'})
            return
        if req is None:
            return  # browser closed channel
        try:
            resp = handle(req)
        except Exception as e:
            resp = {'ok': False, 'error': str(e)}
        send_message(resp)


if __name__ == '__main__':
    main()
