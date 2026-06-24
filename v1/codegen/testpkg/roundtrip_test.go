// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package lcwire is an in-tree compile-and-functional-test target for
// the ZAP v2 codegen. The lc_block_header_request_zap.go file in this
// directory is a verbatim output of `zapgen-all` for the LP-214
// LightClientBlockHeaderRequest schema declared in
// `../schemas/lp-214-light-client.json`.
//
// The tests in this file are the codegen's end-to-end functional
// gate: build a buffer via the emitted New constructor, wrap it via
// the emitted Wrap function, read back every field, and assert
// equality with what was set. This catches regressions in:
//   - Constructor field-write order vs offsets
//   - Wrap kind-discriminator check
//   - Scalar field accessors via zapv1.Read
//   - Byte-array field accessor (zero-copy slice + value-copy)
//
// If this test passes, the codegen's emitted files are functionally
// correct for the scalar + byte-array vocabulary. Other emitted
// schemas exercise the same code paths with different offsets and
// types — a passing test here is high-confidence for the whole batch.
package lcwire

import (
	"bytes"
	"encoding/binary"
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestRoundTrip_ScalarsAndBytes: build with a set of distinctive
// values for every field, parse back, assert each field equals what
// was set.
func TestRoundTrip_ScalarsAndBytes(t *testing.T) {
	t.Parallel()

	want := struct {
		Version          uint8
		ChainID          uint32
		BlockHeight      uint64
		CertMinTier      uint8
		RequestID        uint32
		BlockContentHash [32]byte
	}{
		Version:     0x01,
		ChainID:     7654321,            // arbitrary large chain ID fixture
		BlockHeight: 0xDEADBEEFCAFEF00D, // load-bearing pattern
		CertMinTier: 0x02,               // LP-217 PQ-strict
		RequestID:   0x99887766,
		BlockContentHash: [32]byte{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
			0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		},
	}

	view, buf := NewLightClientBlockHeaderRequest(
		want.Version,
		want.ChainID,
		want.BlockHeight,
		want.CertMinTier,
		want.RequestID,
		want.BlockContentHash,
	)
	if view.IsZero() {
		t.Fatal("NewLightClientBlockHeaderRequest returned zero view")
	}
	if len(buf) == 0 {
		t.Fatal("NewLightClientBlockHeaderRequest returned empty buffer")
	}

	// Verify the view reads back the same fields we wrote.
	checkScalarFields(t, view, want.Version, want.ChainID,
		want.BlockHeight, want.CertMinTier, want.RequestID)
	gotHash := LightClientBlockHeaderRequestBlockContentHash(view)
	if !bytes.Equal(gotHash[:], want.BlockContentHash[:]) {
		t.Errorf("BlockContentHash mismatch:\n got %x\nwant %x", gotHash[:], want.BlockContentHash[:])
	}

	// Now parse the buffer fresh via Wrap and verify the same.
	view2, err := WrapLightClientBlockHeaderRequest(buf)
	if err != nil {
		t.Fatalf("WrapLightClientBlockHeaderRequest: %v", err)
	}
	checkScalarFields(t, view2, want.Version, want.ChainID,
		want.BlockHeight, want.CertMinTier, want.RequestID)
	gotHash2 := LightClientBlockHeaderRequestBlockContentHash(view2)
	if !bytes.Equal(gotHash2[:], want.BlockContentHash[:]) {
		t.Errorf("BlockContentHash mismatch after Wrap:\n got %x\nwant %x", gotHash2[:], want.BlockContentHash[:])
	}
}

// TestWrap_KindMismatch: a buffer carrying a different kind byte at
// the root object offset returns a *SchemaError, not a
// misinterpreted view.
func TestWrap_KindMismatch(t *testing.T) {
	t.Parallel()
	// Build a valid LightClientBlockHeaderRequest then flip the kind
	// byte at the root object position. The ZAP header (zap.HeaderSize
	// = 16 bytes) carries the root offset at bytes 8..12 in little-
	// endian; the kind byte lives at buf[rootOff].
	_, buf := NewLightClientBlockHeaderRequest(
		0x01, 1, 1, 0x00, 0,
		[32]byte{},
	)
	rootOff := int(binary.LittleEndian.Uint32(buf[8:12]))
	if rootOff <= 0 || rootOff >= len(buf) {
		t.Fatalf("invalid rootOff %d in buffer of length %d", rootOff, len(buf))
	}
	if buf[rootOff] != byte(KindLightClientBlockHeaderRequest) {
		t.Fatalf("kind byte at rootOff %d = 0x%02x; expected 0x%02x",
			rootOff, buf[rootOff], byte(KindLightClientBlockHeaderRequest))
	}
	buf[rootOff] = 0xFF // bogus kind

	_, err := WrapLightClientBlockHeaderRequest(buf)
	if err == nil {
		t.Fatal("expected SchemaError on kind mismatch")
	}
	// Verify it's the typed error, not just any error.
	if _, ok := err.(*zapv1.SchemaError); !ok {
		t.Errorf("expected *zapv1.SchemaError, got %T: %v", err, err)
	}
}

// TestSchemaMetadata: the emitted schema marker's Kind/Size/Name
// methods return the constants declared in the JSON spec.
func TestSchemaMetadata(t *testing.T) {
	t.Parallel()
	var s LCBlockHeaderReqSchema
	if got := s.Kind(); got != KindLightClientBlockHeaderRequest {
		t.Errorf("Kind() = 0x%02x; want 0x%02x", got, KindLightClientBlockHeaderRequest)
	}
	if got := s.Size(); got != SizeLightClientBlockHeaderRequest {
		t.Errorf("Size() = %d; want %d", got, SizeLightClientBlockHeaderRequest)
	}
	if got, want := s.Name(), "LightClientBlockHeaderRequest"; got != want {
		t.Errorf("Name() = %q; want %q", got, want)
	}
}

// TestSchemaRegistered: the init function in the emitted file
// registered the schema with the package-level Registry.
func TestSchemaRegistered(t *testing.T) {
	t.Parallel()
	entry, ok := zapv1.DefaultRegistry.Lookup(KindLightClientBlockHeaderRequest)
	if !ok {
		t.Fatal("LCBlockHeaderReqSchema not registered in DefaultRegistry")
	}
	if entry.Name != "LightClientBlockHeaderRequest" {
		t.Errorf("registered name = %q; want %q",
			entry.Name, "LightClientBlockHeaderRequest")
	}
}

// checkScalarFields is the shared assertion helper for TestRoundTrip_*.
func checkScalarFields(t *testing.T, v zapv1.View[LCBlockHeaderReqSchema],
	wantVersion uint8, wantChainID uint32, wantBlockHeight uint64,
	wantCertMinTier uint8, wantRequestID uint32) {
	t.Helper()
	if got := zapv1.Read(v, LCBlockHeaderReqSchemaFields.Version); got != wantVersion {
		t.Errorf("Version = %d; want %d", got, wantVersion)
	}
	if got := zapv1.Read(v, LCBlockHeaderReqSchemaFields.ChainID); got != wantChainID {
		t.Errorf("ChainID = %d; want %d", got, wantChainID)
	}
	if got := zapv1.Read(v, LCBlockHeaderReqSchemaFields.BlockHeight); got != wantBlockHeight {
		t.Errorf("BlockHeight = 0x%x; want 0x%x", got, wantBlockHeight)
	}
	if got := zapv1.Read(v, LCBlockHeaderReqSchemaFields.CertMinTier); got != wantCertMinTier {
		t.Errorf("CertMinTier = %d; want %d", got, wantCertMinTier)
	}
	if got := zapv1.Read(v, LCBlockHeaderReqSchemaFields.RequestID); got != wantRequestID {
		t.Errorf("RequestID = %d; want %d", got, wantRequestID)
	}
}
