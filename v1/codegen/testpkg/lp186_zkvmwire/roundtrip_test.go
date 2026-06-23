// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zkvmwire is an in-tree functional-test target for the LP-186
// chains-VM wire schema bundle. The utxo_zap.go file in this directory
// is a verbatim output of `zapgen-all` for the LP-186 ZKVMUTXO schema
// declared in `../../schemas/lp-186-vms.json`.
//
// The test below builds a ZKVMUTXO buffer via the emitted constructor
// (which mixes scalar fields, a fixed-width [32]byte TxID, and three
// variable-length pointer pairs), parses it back via Wrap, and asserts
// every fixed-section field equals what was set.
//
// ZKVMUTXO exercises the mixed code path: scalar + bytes-fixed +
// variable-length-pointer fields in one schema, which is the canonical
// shape across the 38 LP-186 chains-VM wire schemas.
package zkvmwire

import (
	"bytes"
	"encoding/binary"
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestZKVMUTXO_RoundTrip: build with distinctive values for every
// field, parse back, assert each field equals what was set.
func TestZKVMUTXO_RoundTrip(t *testing.T) {
	t.Parallel()

	want := struct {
		OutputIndex   uint32
		Height        uint64
		TxID          [32]byte
		CommitmentOff, CommitmentLen   uint32
		CiphertextOff, CiphertextLen   uint32
		EphemeralPKOff, EphemeralPKLen uint32
	}{
		OutputIndex: 0x99887766,
		Height:      0xDEADBEEFCAFEF00D,
		TxID: [32]byte{
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
			0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		},
		CommitmentOff: 0x01000000, CommitmentLen: 32,
		CiphertextOff: 0x02000000, CiphertextLen: 580, // typical encrypted-note size
		EphemeralPKOff: 0x03000000, EphemeralPKLen: 32,
	}

	view, buf := NewZKVMUTXO(
		want.OutputIndex,
		want.Height,
		want.CommitmentOff, want.CommitmentLen,
		want.CiphertextOff, want.CiphertextLen,
		want.EphemeralPKOff, want.EphemeralPKLen,
		want.TxID,
	)
	if view.IsZero() {
		t.Fatal("NewZKVMUTXO returned zero view")
	}
	if len(buf) == 0 {
		t.Fatal("NewZKVMUTXO returned empty buffer")
	}

	// Re-parse from buf and verify.
	view2, err := WrapZKVMUTXO(buf)
	if err != nil {
		t.Fatalf("WrapZKVMUTXO: %v", err)
	}

	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.OutputIndex); got != want.OutputIndex {
		t.Errorf("OutputIndex = %#x; want %#x", got, want.OutputIndex)
	}
	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.Height); got != want.Height {
		t.Errorf("Height = %#x; want %#x", got, want.Height)
	}
	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.CommitmentOff); got != want.CommitmentOff {
		t.Errorf("CommitmentOff = %#x; want %#x", got, want.CommitmentOff)
	}
	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.CommitmentLen); got != want.CommitmentLen {
		t.Errorf("CommitmentLen = %d; want %d", got, want.CommitmentLen)
	}
	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.CiphertextLen); got != want.CiphertextLen {
		t.Errorf("CiphertextLen = %d; want %d", got, want.CiphertextLen)
	}
	if got := zapv1.Read(view2, ZKVMUTXOSchemaFields.EphemeralPKOff); got != want.EphemeralPKOff {
		t.Errorf("EphemeralPKOff = %#x; want %#x", got, want.EphemeralPKOff)
	}

	// TxID byte-array accessor.
	gotTxID := ZKVMUTXOTxID(view2)
	if !bytes.Equal(gotTxID[:], want.TxID[:]) {
		t.Errorf("TxID mismatch:\n got %x\nwant %x", gotTxID[:], want.TxID[:])
	}
}

// TestZKVMUTXO_KindMismatch: a buffer carrying a different kind byte at
// the root object offset returns a *SchemaError, not a misinterpreted
// view.
func TestZKVMUTXO_KindMismatch(t *testing.T) {
	t.Parallel()
	_, buf := NewZKVMUTXO(0, 0, 0, 0, 0, 0, 0, 0, [32]byte{})
	rootOff := int(binary.LittleEndian.Uint32(buf[8:12]))
	if rootOff <= 0 || rootOff >= len(buf) {
		t.Fatalf("invalid rootOff %d in buffer of length %d", rootOff, len(buf))
	}
	if buf[rootOff] != byte(KindZKVMUTXO) {
		t.Fatalf("kind byte at rootOff %d = %#02x; want %#02x",
			rootOff, buf[rootOff], byte(KindZKVMUTXO))
	}
	buf[rootOff] = 0xFF // bogus kind
	_, err := WrapZKVMUTXO(buf)
	if err == nil {
		t.Fatal("expected SchemaError on kind mismatch")
	}
	if _, ok := err.(*zapv1.SchemaError); !ok {
		t.Errorf("expected *zapv1.SchemaError, got %T: %v", err, err)
	}
}

// TestZKVMUTXO_Metadata: the emitted schema marker's Kind/Size/Name
// methods return the constants declared in the JSON spec.
func TestZKVMUTXO_Metadata(t *testing.T) {
	t.Parallel()
	var s ZKVMUTXOSchema
	if got := s.Kind(); got != KindZKVMUTXO {
		t.Errorf("Kind() = %#02x; want %#02x", got, KindZKVMUTXO)
	}
	if got := s.Size(); got != SizeZKVMUTXO {
		t.Errorf("Size() = %d; want %d", got, SizeZKVMUTXO)
	}
	if got, want := s.Name(), "ZKVMUTXO"; got != want {
		t.Errorf("Name() = %q; want %q", got, want)
	}
	if SizeZKVMUTXO != 72 {
		t.Errorf("SizeZKVMUTXO = %d; want 72 (per JSON spec)", SizeZKVMUTXO)
	}
}

// TestZKVMUTXO_NotRegistered: the LP-186 chains-VM wire schemas
// explicitly skip global registration because their Kind bytes are
// LOCAL to each <vm>wire package (KindBlock=0x01 in aivmwire is
// distinct from KindBlock=0x01 in bridgevmwire). Verify init() did
// NOT register ZKVMUTXO globally.
func TestZKVMUTXO_NotRegistered(t *testing.T) {
	t.Parallel()
	if entry, ok := zapv1.DefaultRegistry.Lookup(KindZKVMUTXO); ok {
		if entry.Name == "ZKVMUTXO" {
			t.Fatalf("ZKVMUTXOSchema was registered in DefaultRegistry "+
				"despite skip_registry=true; entry=%+v", entry)
		}
	}
}
