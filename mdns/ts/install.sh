#!/bin/bash
# Install the native-messaging helper for the Hanzo browser extension.
#
#   1. Copies helper.js + bonjour-service node_modules to ~/.hanzo/zap-mdns/
#   2. Drops a portable bash wrapper at ~/.hanzo/zap-mdns/helper
#   3. Registers the WebExtension native-messaging-host manifest at the
#      browser's per-OS NMH directory, scoped to hanzo-ai@hanzo.ai.
#
# Idempotent: re-running upgrades the helper without breaking existing
# extension installs.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOST_DIR="$HOME/.hanzo/zap-mdns"
NODE_DIR="$HOST_DIR/node"

mkdir -p "$NODE_DIR"
cp "$HERE/native-host.js" "$NODE_DIR/helper.js"
cat > "$NODE_DIR/package.json" <<JSON
{
  "name": "hanzo-zap-mdns-helper",
  "version": "0.1.0",
  "private": true,
  "dependencies": { "bonjour-service": "^1.2.1" }
}
JSON
( cd "$NODE_DIR" && npm install --silent --no-audit --no-fund )

# Portable wrapper: hunt for node across nvm + homebrew + PATH.
cat > "$HOST_DIR/helper" <<'WRAP'
#!/bin/bash
set -e
find_node() {
  for path in \
    "$(command -v node 2>/dev/null)" \
    /opt/homebrew/bin/node \
    /usr/local/bin/node \
    "$HOME"/.nvm/versions/node/*/bin/node; do
    [ -x "$path" ] && { echo "$path"; return 0; }
  done
  return 1
}
NODE=$(find_node) || { echo "node not found" >&2; exit 1; }
export NODE_PATH="$HOME/.hanzo/zap-mdns/node/node_modules"
exec "$NODE" "$HOME/.hanzo/zap-mdns/node/helper.js"
WRAP
chmod +x "$HOST_DIR/helper"

# Per-OS NMH manifest dir.
case "$(uname -s)" in
  Darwin)  NMH_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts" ;;
  Linux)   NMH_DIR="$HOME/.mozilla/native-messaging-hosts" ;;
  *)       echo "unsupported OS"; exit 1 ;;
esac
mkdir -p "$NMH_DIR"
cat > "$NMH_DIR/ai.hanzo.zap_mdns.json" <<JSON
{
  "name": "ai.hanzo.zap_mdns",
  "description": "Hanzo ZAP mDNS browser",
  "path": "$HOST_DIR/helper",
  "type": "stdio",
  "allowed_extensions": ["hanzo-ai@hanzo.ai"]
}
JSON

echo "installed:"
echo "  helper:   $HOST_DIR/helper"
echo "  manifest: $NMH_DIR/ai.hanzo.zap_mdns.json"
