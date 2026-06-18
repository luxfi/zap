// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Cross-wire conformance: this runtime (github.com/luxfi/zap) and the
// pure-stdlib baseline runtime (github.com/zap-proto/go) implement the SAME
// wire format. zap-proto/go is the canonical runtime this package is
// converging onto (see MIGRATION.md "ZAP runtime consolidation"). This test
// pins the contract from THIS side WITHOUT importing zap-proto/go, so neither
// repo takes a build dependency on the other yet.
//
// The proof meets the zap-proto/go side at a shared golden vector: both repos
// pin the byte-for-byte identical goldenV1Hex constant and assert their own
// Builder emits it / their own reader decodes it. Changing the wire on one
// side without the other is a wire break and MUST fail CI in both repos.
//
//	field @0  uint32 = 0xDEADBEEF
//	field @8  text   = "zap"
//	field @16 bytes  = 01 02 03 04
//	dataSize = 24
//
// luxfi/zap's default NewBuilder tags Version2 (the v3 platformvm TxKind
// discriminator schema). The shared golden vector is a Version1 header, so the
// luxfi encode side builds via NewBuilderV1 to meet zap-proto's default
// (Version1) byte-for-byte. The v2 default is asserted to differ ONLY at the
// version byte — the single documented header delta between the runtimes.
const (
	xwU32   = 0
	xwText  = 8
	xwBytes = 16
	xwSize  = 24

	// goldenV1Hex — SHARED VERBATIM with zap-proto/go's zap_crosswire_test.go.
	// 47-byte canonical ZAP buffer (Version1) for the layout above.
	goldenV1Hex = "5a41500001000000100000002f000000efbeadde0000000010000000030000000b000000040000007a617001020304"
)

func buildCanonicalV1(tb testing.TB) []byte {
	tb.Helper()
	b := NewBuilderV1(64)
	ob := b.StartObject(xwSize)
	ob.SetUint32(xwU32, 0xDEADBEEF)
	ob.SetText(xwText, "zap")
	ob.SetBytes(xwBytes, []byte{0x01, 0x02, 0x03, 0x04})
	ob.FinishAsRoot()
	return b.Finish()
}

func buildCanonicalV2(tb testing.TB) []byte {
	tb.Helper()
	b := NewBuilder(64) // default = Version2
	ob := b.StartObject(xwSize)
	ob.SetUint32(xwU32, 0xDEADBEEF)
	ob.SetText(xwText, "zap")
	ob.SetBytes(xwBytes, []byte{0x01, 0x02, 0x03, 0x04})
	ob.FinishAsRoot()
	return b.Finish()
}

// TestCrossWireGoldenEncodeV1 proves luxfi's Builder (v1 mode) emits exactly
// the shared golden vector — byte-for-byte identical to zap-proto/go's
// default NewBuilder output. This is the load-bearing "the two runtimes
// produce the same wire" assertion.
func TestCrossWireGoldenEncodeV1(t *testing.T) {
	got := buildCanonicalV1(t)
	want, err := hex.DecodeString(goldenV1Hex)
	if err != nil {
		t.Fatalf("decode goldenV1Hex: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("luxfi v1 encode != shared golden:\n got  %s\n want %s", hex.EncodeToString(got), goldenV1Hex)
	}
}

// TestCrossWireGoldenDecode proves luxfi's reader decodes the shared golden
// vector field-by-field — the "decode with the other" leg (the bytes are the
// canonical wire, identical to zap-proto's NewBuilder output).
func TestCrossWireGoldenDecode(t *testing.T) {
	buf, err := hex.DecodeString(goldenV1Hex)
	if err != nil {
		t.Fatalf("decode goldenV1Hex: %v", err)
	}
	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse(golden) failed: %v", err)
	}
	if msg.Version() != Version1 {
		t.Fatalf("golden Version = %d, want %d", msg.Version(), Version1)
	}
	r := msg.Root()
	if got := r.Uint32(xwU32); got != 0xDEADBEEF {
		t.Errorf("Uint32 = %#x, want 0xDEADBEEF", got)
	}
	if got := r.Text(xwText); got != "zap" {
		t.Errorf("Text = %q, want %q", got, "zap")
	}
	if got := r.Bytes(xwBytes); !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("Bytes = %v, want [1 2 3 4]", got)
	}
}

// TestCrossWireV2DiffersOnlyAtVersionByte proves the single documented header
// delta: luxfi's default NewBuilder (Version2) output equals the golden v1
// vector with ONLY byte 4 changed from 1 to 2. The data segment past the
// magic+version prefix is byte-identical. This is exactly the buffer zap-proto
// must (now) accept on read — verified on the zap-proto side by
// TestCrossWireAcceptsV2.
func TestCrossWireV2DiffersOnlyAtVersionByte(t *testing.T) {
	v1, err := hex.DecodeString(goldenV1Hex)
	if err != nil {
		t.Fatalf("decode goldenV1Hex: %v", err)
	}
	v2 := buildCanonicalV2(t)

	if len(v2) != len(v1) {
		t.Fatalf("v2 len %d != v1 len %d", len(v2), len(v1))
	}
	if v2[4] != byte(Version2) {
		t.Fatalf("v2 version byte = %d, want %d", v2[4], Version2)
	}
	// Reconstruct the expected v2 buffer: v1 with byte 4 := 2.
	wantV2 := append([]byte(nil), v1...)
	wantV2[4] = byte(Version2)
	if !bytes.Equal(v2, wantV2) {
		t.Fatalf("luxfi v2 encode differs from v1 in more than the version byte:\n v2 %s\n v1 %s", hex.EncodeToString(v2), goldenV1Hex)
	}
	// Data segment identity (past magic+version).
	if !bytes.Equal(v1[6:], v2[6:]) {
		t.Fatal("v1 and v2 data segments diverge past the version byte")
	}
}
