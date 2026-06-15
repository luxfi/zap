// zap.test.ts — cross-language "one protocol" proof. The hex strings are
// the AUTHORITATIVE wire bytes emitted by the Go codec in
// ../../golden_test.go (run `go test ./zapweb -run TestGoldenVectors -v`).
// These tests assert the TypeScript codec produces byte-identical output
// (encode) and reads Go-built messages correctly (decode), plus opcode
// parity with Go zapclient.ProcedureOpcode.
//
// Run offline, zero deps:  node --test src/
import { test } from "node:test";
import assert from "node:assert/strict";
import { Builder, Message, procedureOpcode } from "./zap.ts";

const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

// --- Golden vectors (from Go) ---------------------------------------
const G = {
  v1: "5a4150000200000010000000550000004000000005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000068656c6c6f",
  v2: "5a41500002000000100000005a0000004000000005000000000000000000000000000000000000000000000000000000250000000500000000000000000000000000000000000000000000000000000068656c6c6f776f726c64",
  v3: "5a4150000200000010000000180000000403020100000000",
  v4: "5a4150000200341210000000550000004000000005000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000068656c6c6f",
  v5: "5a41500002000000100000002200000001000000efbeadde08000000020000006869",
};
const OPCODE_TEST_ECHO = 44288;

// --- Encode: TS must produce byte-identical bytes -------------------

test("encode V1: text@0='hello', dataSize=64", () => {
  const b = new Builder(256);
  const ob = b.startObject(64);
  ob.setText(0, "hello");
  ob.finishAsRoot();
  assert.equal(hex(b.finish()), G.v1);
});

test("encode V2: text@0='hello', text@32='world'", () => {
  const b = new Builder(256);
  const ob = b.startObject(64);
  ob.setText(0, "hello");
  ob.setText(32, "world");
  ob.finishAsRoot();
  assert.equal(hex(b.finish()), G.v2);
});

test("encode V3: uint32@0=0x01020304, dataSize=8", () => {
  const b = new Builder(256);
  const ob = b.startObject(8);
  ob.setUint32(0, 0x01020304);
  ob.finishAsRoot();
  assert.equal(hex(b.finish()), G.v3);
});

test("encode V4: V1 with flags 0x1234", () => {
  const b = new Builder(256);
  const ob = b.startObject(64);
  ob.setText(0, "hello");
  ob.finishAsRoot();
  assert.equal(hex(b.finishWithFlags(0x1234)), G.v4);
});

test("encode V5: uint8@0, uint32@4, text@8, dataSize=16", () => {
  const b = new Builder(256);
  const ob = b.startObject(16);
  ob.setUint8(0, 1);
  ob.setUint32(4, 0xdeadbeef);
  ob.setText(8, "hi");
  ob.finishAsRoot();
  assert.equal(hex(b.finish()), G.v5);
});

// --- Decode: TS must read Go-built messages correctly --------------

test("decode V1", () => {
  const m = Message.parse(unhex(G.v1));
  assert.equal(m.root().text(0), "hello");
  assert.equal(m.flags(), 0);
});

test("decode V2", () => {
  const r = Message.parse(unhex(G.v2)).root();
  assert.equal(r.text(0), "hello");
  assert.equal(r.text(32), "world");
});

test("decode V3", () => {
  assert.equal(Message.parse(unhex(G.v3)).root().uint32(0), 0x01020304);
});

test("decode V4: flags carry through", () => {
  const m = Message.parse(unhex(G.v4));
  assert.equal(m.flags(), 0x1234);
  assert.equal(m.root().text(0), "hello");
});

test("decode V5: mixed scalars + text", () => {
  const r = Message.parse(unhex(G.v5)).root();
  assert.equal(r.uint8(0), 1);
  assert.equal(r.uint32(4), 0xdeadbeef);
  assert.equal(r.text(8), "hi");
});

// --- Round-trip + opcode parity ------------------------------------

test("encode→decode round-trip", () => {
  const b = new Builder(256);
  const ob = b.startObject(96);
  ob.setText(0, "satoshi.nakamoto@example.com");
  ob.setText(32, "liquidity");
  ob.setUint32(64, 8675309);
  ob.finishAsRoot();
  const r = Message.parse(unhex(hex(b.finish()))).root();
  assert.equal(r.text(0), "satoshi.nakamoto@example.com");
  assert.equal(r.text(32), "liquidity");
  assert.equal(r.uint32(64), 8675309);
});

test("opcode parity with Go ProcedureOpcode", () => {
  assert.equal(procedureOpcode("test.echo"), OPCODE_TEST_ECHO);
  // low byte stays zero (MsgType<<8 convention)
  assert.equal(procedureOpcode("bd.portfolio.Get") & 0xff, 0);
});
