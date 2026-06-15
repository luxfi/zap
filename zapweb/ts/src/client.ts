// client.ts — the browser zapweb client. Mirrors ../../client.go: stamp
// the procedure opcode into the message flags, prepend the
// [reqID u32][flag u32] correlation header, send one binary WebSocket
// message, resolve the correlated reply. Uses the platform-global
// WebSocket (browsers + Node >= 22), so no dependency.

import { Message, procedureOpcode, stampOpcode } from "./zap.ts";

const REQ_FLAG_REQ = 1;
const REQ_FLAG_RESP = 2;
const FLAG_ERR = 3;
const CORR_HEADER = 8;

interface Pending {
  resolve: (m: Message | null) => void;
  reject: (e: Error) => void;
}

/** ZapWebClient speaks native ZAP to a zapweb.Handler over WebSocket. */
export class ZapWebClient {
  private ws: WebSocket;
  private reqID = 0;
  private pending = new Map<number, Pending>();

  private constructor(ws: WebSocket) {
    this.ws = ws;
    this.ws.binaryType = "arraybuffer";
    this.ws.onmessage = (ev: MessageEvent) => this.onMessage(ev);
    this.ws.onclose = () => this.failAll(new Error("zapweb: connection closed"));
  }

  /** dial opens a zapweb connection (ws:// or wss://). */
  static dial(url: string): Promise<ZapWebClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      ws.onopen = () => resolve(new ZapWebClient(ws));
      ws.onerror = () => reject(new Error("zapweb: dial failed: " + url));
    });
  }

  close(): void {
    this.ws.close(1000, "");
  }

  /**
   * call invokes procedure with the request message bytes (built by the
   * generated per-procedure encoder) and resolves the reply Message. A
   * dispatch-level server failure rejects; procedure-level status lives
   * inside the reply, identical to the native transport.
   */
  call(procedure: string, req: Uint8Array): Promise<Message | null> {
    let opcode: number;
    try {
      opcode = procedureOpcode(procedure);
    } catch (e) {
      return Promise.reject(e as Error);
    }
    const body = stampOpcode(req, opcode);
    const id = (++this.reqID) >>> 0;
    const frame = new Uint8Array(CORR_HEADER + body.length);
    const dv = new DataView(frame.buffer);
    dv.setUint32(0, id, true);
    dv.setUint32(4, REQ_FLAG_REQ, true);
    frame.set(body, CORR_HEADER);
    return new Promise<Message | null>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.ws.send(frame);
      } catch (e) {
        this.pending.delete(id);
        reject(e as Error);
      }
    });
  }

  private onMessage(ev: MessageEvent): void {
    const data = new Uint8Array(ev.data as ArrayBuffer);
    if (data.length < CORR_HEADER) return;
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const id = dv.getUint32(0, true);
    const flag = dv.getUint32(4, true);
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    const payload = data.subarray(CORR_HEADER);
    if (flag === FLAG_ERR) {
      p.reject(new Error("zapweb: " + new TextDecoder().decode(payload)));
      return;
    }
    if (flag === REQ_FLAG_RESP) {
      if (payload.length === 0) {
        p.resolve(null);
        return;
      }
      try {
        p.resolve(Message.parse(payload));
      } catch (e) {
        p.reject(e as Error);
      }
      return;
    }
    p.reject(new Error("zapweb: unexpected reply flag " + flag));
  }

  private failAll(err: Error): void {
    for (const [, p] of this.pending) p.reject(err);
    this.pending.clear();
  }
}
