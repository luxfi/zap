// zap.ts — faithful TypeScript port of the Go ZAP wire codec.
//
// Byte-identical to ../../../zap.go (reader) + ../../../builder.go
// (writer): a message built here parses on the Go server and a Go-built
// message parses here. Verified against golden vectors emitted by
// ../../golden_test.go (see zap.test.ts). This is the browser half of
// "one protocol" — the SPA speaks the same bytes as a native ZAP peer.
//
// Wire format (little-endian throughout):
//   Header (16B): "ZAP\0" | version u16 | flags u16 | rootOffset u32 | size u32
//   Scalars: written inline at object.offset + fieldOffset
//   Text/Bytes: an {relOffset u32, length u32} forward pointer at the
//     field; the payload is appended after the object's fixed section and
//     relOffset is patched to (payloadPos - fieldPos) on finish.

export const HEADER_SIZE = 16;
export const VERSION2 = 2;
export const ALIGNMENT = 8;
const MAGIC = [0x5a, 0x41, 0x50, 0x00]; // "ZAP\0"

const utf8 = new TextEncoder();
const utf8dec = new TextDecoder();

/** Builder constructs ZAP messages (mirrors Go Builder). */
export class Builder {
  private buf: Uint8Array;
  private view: DataView;
  private pos: number;
  private rootOffset = 0;

  constructor(capacity = 256) {
    if (capacity < HEADER_SIZE) capacity = 256;
    this.buf = new Uint8Array(capacity);
    this.view = new DataView(this.buf.buffer);
    this.buf[0] = MAGIC[0];
    this.buf[1] = MAGIC[1];
    this.buf[2] = MAGIC[2];
    this.buf[3] = MAGIC[3];
    this.view.setUint16(4, VERSION2, true);
    this.pos = HEADER_SIZE; // start after header
  }

  private grow(n: number): void {
    if (this.pos + n <= this.buf.length) return;
    let newCap = this.buf.length * 2;
    if (newCap < this.pos + n) newCap = this.pos + n;
    const nb = new Uint8Array(newCap);
    nb.set(this.buf.subarray(0, this.pos));
    this.buf = nb;
    this.view = new DataView(this.buf.buffer);
  }

  align(alignment: number): void {
    const padding = (alignment - (this.pos % alignment)) % alignment;
    this.grow(padding);
    for (let i = 0; i < padding; i++) this.buf[this.pos++] = 0;
  }

  startObject(dataSize: number): ObjectBuilder {
    this.align(ALIGNMENT);
    return new ObjectBuilder(this, this.pos, dataSize);
  }

  finish(): Uint8Array {
    this.view.setUint32(8, this.rootOffset >>> 0, true);
    this.view.setUint32(12, this.pos >>> 0, true);
    return this.buf.subarray(0, this.pos);
  }

  finishWithFlags(flags: number): Uint8Array {
    this.view.setUint16(6, flags & 0xffff, true);
    return this.finish();
  }

  // --- internals used by ObjectBuilder (the buffer/view can be
  //     reallocated by grow, so always reach them through the builder) ---

  /** ensureAbs grows + zero-fills so absolute position `end` is materialized. */
  _ensureAbs(end: number): void {
    if (end > this.pos) {
      this.grow(end - this.pos);
      for (let i = this.pos; i < end; i++) this.buf[i] = 0;
      this.pos = end;
    }
  }
  _append(data: Uint8Array): void {
    this.grow(data.length);
    this.buf.set(data, this.pos);
    this.pos += data.length;
  }
  _pos(): number { return this.pos; }
  _setByte(at: number, v: number): void { this.buf[at] = v & 0xff; }
  _setU16(at: number, v: number): void { this.view.setUint16(at, v & 0xffff, true); }
  _setU32(at: number, v: number): void { this.view.setUint32(at, v >>> 0, true); }
  _setU64(at: number, v: bigint): void { this.view.setBigUint64(at, v, true); }
  _setRoot(off: number): void { this.rootOffset = off; }
}

interface DeferredField { fieldOffset: number; data: Uint8Array; }

/** ObjectBuilder builds one ZAP object (mirrors Go ObjectBuilder). */
export class ObjectBuilder {
  private b: Builder;
  private startPos: number;
  private dataSize: number;
  private deferred: DeferredField[] = [];
  constructor(b: Builder, startPos: number, dataSize: number) {
    this.b = b;
    this.startPos = startPos;
    this.dataSize = dataSize;
  }

  private ensureField(endOffset: number): void {
    this.b._ensureAbs(this.startPos + endOffset);
  }

  setBool(fo: number, v: boolean): void { this.setUint8(fo, v ? 1 : 0); }
  setUint8(fo: number, v: number): void {
    this.ensureField(fo + 1);
    this.b._setByte(this.startPos + fo, v);
  }
  setUint16(fo: number, v: number): void {
    this.ensureField(fo + 2);
    this.b._setU16(this.startPos + fo, v);
  }
  setUint32(fo: number, v: number): void {
    this.ensureField(fo + 4);
    this.b._setU32(this.startPos + fo, v);
  }
  setUint64(fo: number, v: bigint): void {
    this.ensureField(fo + 8);
    this.b._setU64(this.startPos + fo, v);
  }
  setText(fo: number, v: string): void { this.setBytes(fo, utf8.encode(v)); }
  setBytes(fo: number, v: Uint8Array): void {
    this.ensureField(fo + 8); // {relOffset u32, length u32}
    if (v.length === 0) {
      this.b._setU32(this.startPos + fo, 0);
      this.b._setU32(this.startPos + fo + 4, 0);
      return;
    }
    this.deferred.push({ fieldOffset: fo, data: v.slice() });
    this.b._setU32(this.startPos + fo + 4, v.length); // length now; relOffset on finish
  }

  finish(): number {
    this.ensureField(this.dataSize); // materialize the whole fixed section
    for (const e of this.deferred) {
      const dataPos = this.b._pos();
      this.b._append(e.data);
      const fieldAbsPos = this.startPos + e.fieldOffset;
      this.b._setU32(fieldAbsPos, dataPos - fieldAbsPos); // relOffset
    }
    return this.startPos;
  }
  finishAsRoot(): number {
    const off = this.finish();
    this.b._setRoot(off);
    return off;
  }
}

/** Message is a zero-copy reader over ZAP bytes (mirrors Go Message). */
export class Message {
  readonly data: Uint8Array;
  private readonly view: DataView;
  private constructor(data: Uint8Array, view: DataView) {
    this.data = data;
    this.view = view;
  }

  static parse(input: Uint8Array): Message {
    if (input.length < HEADER_SIZE) throw new Error("zap: buffer too small");
    if (input[0] !== MAGIC[0] || input[1] !== MAGIC[1] || input[2] !== MAGIC[2] || input[3] !== MAGIC[3]) {
      throw new Error("zap: invalid magic");
    }
    const v = new DataView(input.buffer, input.byteOffset, input.byteLength);
    const version = v.getUint16(4, true);
    if (version !== 1 && version !== VERSION2) throw new Error("zap: unsupported version");
    const size = v.getUint32(12, true);
    if (size < HEADER_SIZE || size > input.length) throw new Error("zap: bad size");
    const data = input.subarray(0, size);
    return new Message(data, new DataView(data.buffer, data.byteOffset, data.byteLength));
  }

  /** wrap builds a Message over trusted, already-valid bytes (no checks). */
  static wrap(input: Uint8Array): Message {
    return new Message(input, new DataView(input.buffer, input.byteOffset, input.byteLength));
  }

  version(): number { return this.view.getUint16(4, true); }
  flags(): number { return this.view.getUint16(6, true); }
  size(): number { return this.data.length; }
  bytes(): Uint8Array { return this.data; }
  root(): ZapObject {
    return new ZapObject(this.data, this.view, this.view.getUint32(8, true));
  }
}

/** ZapObject is a zero-copy view into a ZAP struct (mirrors Go Object). */
export class ZapObject {
  private data: Uint8Array;
  private view: DataView;
  readonly offset: number;
  constructor(data: Uint8Array, view: DataView, offset: number) {
    this.data = data;
    this.view = view;
    this.offset = offset;
  }

  isNull(): boolean { return this.offset === 0; }

  bool(fo: number): boolean { return this.uint8(fo) !== 0; }
  uint8(fo: number): number {
    const pos = this.offset + fo;
    if (pos >= this.data.length) return 0;
    return this.data[pos];
  }
  uint16(fo: number): number {
    const pos = this.offset + fo;
    if (pos + 2 > this.data.length) return 0;
    return this.view.getUint16(pos, true);
  }
  uint32(fo: number): number {
    const pos = this.offset + fo;
    if (pos + 4 > this.data.length) return 0;
    return this.view.getUint32(pos, true);
  }
  uint64(fo: number): bigint {
    const pos = this.offset + fo;
    if (pos + 8 > this.data.length) return 0n;
    return this.view.getBigUint64(pos, true);
  }
  bytes(fo: number): Uint8Array | null {
    const pos = this.offset + fo;
    if (pos + 4 > this.data.length) return null;
    const relOffset = this.view.getUint32(pos, true);
    if (relOffset === 0) return null;
    const lenPos = pos + 4;
    if (lenPos + 4 > this.data.length) return null;
    const length = this.view.getUint32(lenPos, true);
    const absPos = pos + relOffset;
    if (absPos < HEADER_SIZE) return null;
    if (absPos + length > this.data.length) return null;
    return this.data.subarray(absPos, absPos + length);
  }
  text(fo: number): string {
    const b = this.bytes(fo);
    if (!b || b.length === 0) return "";
    return utf8dec.decode(b);
  }
}

/**
 * procedureOpcode hashes a procedure name to its uint16 opcode, byte-
 * identical to Go zapclient.ProcedureOpcode: FNV-1a-32, then
 * ((h % 254) + 1) << 8. The low byte stays 0.
 */
export function procedureOpcode(name: string): number {
  if (!name) throw new Error("zap: empty procedure name");
  let h = 0x811c9dc5; // FNV-1a 32 offset basis
  const bytes = utf8.encode(name);
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193); // 32-bit multiply by FNV prime
  }
  const hu = h >>> 0;
  const b = (hu % 254) + 1; // 1..254 (0 and 255 reserved)
  return (b << 8) & 0xffff;
}

/** stampOpcode returns msg bytes with the opcode written into flags[6:8]. */
export function stampOpcode(msg: Uint8Array, opcode: number): Uint8Array {
  const out = msg.slice();
  out[6] = opcode & 0xff;
  out[7] = (opcode >>> 8) & 0xff;
  return out;
}
