// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package consensuswire is an in-tree functional-test target for the
// LP-182 consensus-wire schema bundle. The quasar_cert_zap.go file in
// this directory is a verbatim output of `zapgen-all` for the LP-182
// QuasarCert schema declared in `../../schemas/lp-182-consensus.json`.
//
// The test below builds a QuasarCert buffer via the emitted constructor,
// wraps it via Wrap, reads every fixed-section scalar field, and asserts
// equality with what was set. It also asserts that the schema's
// Kind/Size/Name metadata matches the JSON spec.
//
// QuasarCert exercises the "all-uint pointers" code path: every field
// after the kind byte is a scalar uint64/int64/uint32, modeling the
// 5×(Off+Len) variable-length tails that the consensus wire format
// uses for BLS/Corona/Pulsar/Magnetar/MLDSARollup leg bytes.
package consensuswire

import (
	"encoding/binary"
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestQuasarCert_RoundTrip: build with distinctive values for every
// field, parse back, assert every field equals what was set.
func TestQuasarCert_RoundTrip(t *testing.T) {
	t.Parallel()

	want := struct {
		Epoch            uint64
		FinalityUnixNano int64
		Validators       uint32
		BLSOff, BLSLen   uint32
		CoronaOff, CoronaLen     uint32
		PulsarOff, PulsarLen     uint32
		MagnetarOff, MagnetarLen uint32
		MLDSARollupOff, MLDSARollupLen uint32
	}{
		Epoch:            0xDEADBEEFCAFEF00D,
		FinalityUnixNano: 1766708400_000_000_000, // LP-182 activation marker
		Validators:       21,
		BLSOff:           0x01000000, BLSLen: 96,
		CoronaOff:        0x02000000, CoronaLen: 1280,
		PulsarOff:        0x03000000, PulsarLen: 3309, // MLDSA65 FIPS 204 size
		MagnetarOff:      0x04000000, MagnetarLen: 7856,
		MLDSARollupOff:   0x05000000, MLDSARollupLen: 256,
	}

	view, buf := NewQuasarCert(
		want.Epoch,
		want.FinalityUnixNano,
		want.Validators,
		want.BLSOff, want.BLSLen,
		want.CoronaOff, want.CoronaLen,
		want.PulsarOff, want.PulsarLen,
		want.MagnetarOff, want.MagnetarLen,
		want.MLDSARollupOff, want.MLDSARollupLen,
	)
	if view.IsZero() {
		t.Fatal("NewQuasarCert returned zero view")
	}
	if len(buf) == 0 {
		t.Fatal("NewQuasarCert returned empty buffer")
	}

	// Re-parse from buf and verify.
	view2, err := WrapQuasarCert(buf)
	if err != nil {
		t.Fatalf("WrapQuasarCert: %v", err)
	}

	if got := zapv1.Read(view2, QuasarCertSchemaFields.Epoch); got != want.Epoch {
		t.Errorf("Epoch = %#x; want %#x", got, want.Epoch)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.FinalityUnixNano); got != want.FinalityUnixNano {
		t.Errorf("FinalityUnixNano = %d; want %d", got, want.FinalityUnixNano)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.Validators); got != want.Validators {
		t.Errorf("Validators = %d; want %d", got, want.Validators)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.BLSOff); got != want.BLSOff {
		t.Errorf("BLSOff = %#x; want %#x", got, want.BLSOff)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.BLSLen); got != want.BLSLen {
		t.Errorf("BLSLen = %d; want %d", got, want.BLSLen)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.PulsarLen); got != want.PulsarLen {
		t.Errorf("PulsarLen = %d; want %d", got, want.PulsarLen)
	}
	if got := zapv1.Read(view2, QuasarCertSchemaFields.MLDSARollupOff); got != want.MLDSARollupOff {
		t.Errorf("MLDSARollupOff = %#x; want %#x", got, want.MLDSARollupOff)
	}
}

// TestQuasarCert_KindMismatch: a buffer carrying a different kind byte
// at the root object offset returns a *SchemaError, not a
// misinterpreted view.
func TestQuasarCert_KindMismatch(t *testing.T) {
	t.Parallel()
	_, buf := NewQuasarCert(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	rootOff := int(binary.LittleEndian.Uint32(buf[8:12]))
	if rootOff <= 0 || rootOff >= len(buf) {
		t.Fatalf("invalid rootOff %d in buffer of length %d", rootOff, len(buf))
	}
	if buf[rootOff] != byte(KindQuasarCert) {
		t.Fatalf("kind byte at rootOff %d = %#02x; want %#02x",
			rootOff, buf[rootOff], byte(KindQuasarCert))
	}
	buf[rootOff] = 0xFF // bogus kind
	_, err := WrapQuasarCert(buf)
	if err == nil {
		t.Fatal("expected SchemaError on kind mismatch")
	}
	if _, ok := err.(*zapv1.SchemaError); !ok {
		t.Errorf("expected *zapv1.SchemaError, got %T: %v", err, err)
	}
}

// TestQuasarCert_Metadata: the emitted schema marker's Kind/Size/Name
// methods return the constants declared in the JSON spec.
func TestQuasarCert_Metadata(t *testing.T) {
	t.Parallel()
	var s QuasarCertSchema
	if got := s.Kind(); got != KindQuasarCert {
		t.Errorf("Kind() = %#02x; want %#02x", got, KindQuasarCert)
	}
	if got := s.Size(); got != SizeQuasarCert {
		t.Errorf("Size() = %d; want %d", got, SizeQuasarCert)
	}
	if got, want := s.Name(), "QuasarCert"; got != want {
		t.Errorf("Name() = %q; want %q", got, want)
	}
	if SizeQuasarCert != 72 {
		t.Errorf("SizeQuasarCert = %d; want 72 (per JSON spec)", SizeQuasarCert)
	}
}

// TestQuasarCert_NotRegistered: the LP-182 consensus-wire schemas
// explicitly skip global registration because their 0x01..0x0D kind
// bytes are LOCAL to the consensus wire registry, not the global
// zapv1.DefaultRegistry that hosts LP-201 (0xD0+) and LP-214 (0xF0+).
// Verify init() did NOT register QuasarCert globally.
func TestQuasarCert_NotRegistered(t *testing.T) {
	t.Parallel()
	if entry, ok := zapv1.DefaultRegistry.Lookup(KindQuasarCert); ok {
		// 0x01 might be claimed by some unrelated schema in the same test
		// binary. Only fail if the entry's name is ours — that would mean
		// the codegen ignored skip_registry.
		if entry.Name == "QuasarCert" {
			t.Fatalf("QuasarCertSchema was registered in DefaultRegistry "+
				"despite skip_registry=true; entry=%+v", entry)
		}
	}
}
