#!/usr/bin/env node
/**
 * Native-messaging host for the Hanzo browser extension (HIP-0069).
 *
 * Bridges the extension's `runtime.sendNativeMessage('ai.hanzo.zap_mdns',
 * {op})` call into a bonjour-service mDNS browse. Local services are
 * rewritten to ws://127.0.0.1:port/ — Firefox extension contexts treat
 * non-loopback IPs as cross-origin even with <all_urls> host_perms.
 *
 * Install via the wrapper at ~/.hanzo/zap-mdns/helper which finds node
 * across the user's nvm/homebrew/PATH and exports NODE_PATH so this
 * script's `require('bonjour-service')` resolves under any spawn env.
 *
 * Logs to /tmp/hanzo-zap-mdns.log for diagnostics.
 */
const { Bonjour } = require('bonjour-service');
const fs = require('fs');
const os = require('os');

const LOG_FILE = '/tmp/hanzo-zap-mdns.log';
function log(msg) {
  try { fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} ${msg}\n`); }
  catch (_) { /* best-effort */ }
}
log(`helper started pid=${process.pid} node=${process.version}`);

// ---- IP discovery: identify "this host" addresses so we rewrite to loopback
function ourIPs() {
  const ips = new Set(['127.0.0.1', '::1']);
  const ifaces = os.networkInterfaces();
  for (const list of Object.values(ifaces)) {
    for (const it of list || []) ips.add(it.address);
  }
  return ips;
}
const OUR_IPS = ourIPs();

function loopbackUrl(host, port) {
  if (OUR_IPS.has(host)) return `ws://127.0.0.1:${port}/`;
  return `ws://${host}:${port}/`;
}

// ---- WebExtension native-messaging stdio framing: 4-byte LE length + utf-8 JSON
let _buf = Buffer.alloc(0);
const _pending = [], _waiters = [];
let _ended = false;

process.stdin.on('data', (chunk) => {
  _buf = Buffer.concat([_buf, chunk]);
  while (_buf.length >= 4) {
    const length = _buf.readUInt32LE(0);
    if (_buf.length < 4 + length) break;
    const body = _buf.subarray(4, 4 + length);
    _buf = _buf.subarray(4 + length);
    let req; try { req = JSON.parse(body.toString('utf-8')); } catch { req = null; }
    if (_waiters.length) _waiters.shift()(req); else _pending.push(req);
  }
});
process.stdin.on('end', () => {
  _ended = true;
  while (_waiters.length) _waiters.shift()(null);
});

function readMessage() {
  if (_pending.length) return Promise.resolve(_pending.shift());
  if (_ended) return Promise.resolve(null);
  return new Promise((r) => _waiters.push(r));
}
function writeMessage(obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([header, body]));
}

// ---- mDNS browse via bonjour-service
function browse(timeoutMs) {
  return new Promise((resolve) => {
    const bonjour = new Bonjour();
    const found = []; const seen = new Set();
    const browser = bonjour.find({ type: 'hanzo' }, (svc) => {
      const id = `${svc.name}-${svc.port}`;
      if (seen.has(id)) return;
      seen.add(id);
      const txt = svc.txt || {};
      const ipv4 = (svc.addresses || []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a))
                    || svc.host || '127.0.0.1';
      found.push({
        server_id: txt.server_id || svc.name,
        host: ipv4, port: svc.port,
        url: loopbackUrl(ipv4, svc.port),
        agent_label: txt.agent_label || '',
        version: txt.version || '',
        capabilities: (txt.capabilities || '').split(',').filter(Boolean),
      });
    });
    setTimeout(() => {
      try { browser.stop(); } catch {} try { bonjour.destroy(); } catch {}
      resolve(found);
    }, timeoutMs);
  });
}

async function handle(req) {
  log(`request: ${JSON.stringify(req)}`);
  const op = req && req.op;
  if (op === 'browse') {
    const services = await browse(req.timeout_ms || 2000);
    log(`browse → ${services.length} services: ${services.map(s => s.server_id).join(',')}`);
    return { ok: true, services };
  }
  return { ok: false, error: `unknown op: ${op}` };
}

(async () => {
  while (true) {
    const req = await readMessage();
    if (req === null) { log('helper exiting (stdin EOF)'); break; }
    let resp;
    try { resp = await handle(req); }
    catch (e) { resp = { ok: false, error: String(e) }; log(`error: ${e}`); }
    writeMessage(resp);
  }
})();
