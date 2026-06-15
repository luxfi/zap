// integration.test.ts — live cross-language proof: the TS ZapWebClient
// (built on the browser-global WebSocket) calls a Go zapweb echo server
// over a real socket. Exercises client.ts end to end (opcode stamping,
// correlation framing, reply parsing) against the Go dispatch path.
//
// Start the server first:  go run ./zapweb/cmd/echoserver
// Then:                    ZAPWEB_URL=ws://127.0.0.1:8089/zap node --test src/integration.test.ts
// Skips cleanly when no server is reachable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Builder, ZapWebClient } from "./index.ts";

const URL = process.env.ZAPWEB_URL ?? "ws://127.0.0.1:8089/zap";

async function dialWithRetry(url: string, attempts = 25, delayMs = 200): Promise<ZapWebClient | null> {
  for (let i = 0; i < attempts; i++) {
    try {
      return await ZapWebClient.dial(url);
    } catch {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return null;
}

test("zapweb live round-trip: TS client ↔ Go server", async (t) => {
  const c = await dialWithRetry(URL);
  if (!c) {
    t.skip(`no zapweb echo server at ${URL}`);
    return;
  }
  try {
    const b = new Builder(256);
    const ob = b.startObject(64);
    ob.setText(0, "hello");
    ob.finishAsRoot();
    const resp = await c.call("test.echo", b.finish());
    assert.ok(resp, "expected a reply");
    assert.equal(resp.root().text(0), "echo:hello");

    // concurrent calls correlate independently
    const [r1, r2] = await Promise.all([
      c.call("test.echo", build("alpha")),
      c.call("test.echo", build("omega")),
    ]);
    assert.equal(r1?.root().text(0), "echo:alpha");
    assert.equal(r2?.root().text(0), "echo:omega");
  } finally {
    c.close();
  }
});

function build(s: string): Uint8Array {
  const b = new Builder(256);
  const ob = b.startObject(64);
  ob.setText(0, s);
  ob.finishAsRoot();
  return b.finish();
}
