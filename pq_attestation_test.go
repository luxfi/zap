// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"errors"
	"testing"

	"github.com/luxfi/pq"
)

func TestAttestation_HasPQEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		att  *Attestation
		want bool
	}{
		{"nil", nil, false},
		{"empty", &Attestation{}, false},
		{"pub-only", &Attestation{PubKey: []byte{0x01}}, false},
		{"sig-only", &Attestation{Sig: []byte{0x01}}, false},
		{"both", &Attestation{PubKey: []byte{0x01}, Sig: []byte{0x02}}, true},
	} {
		got := tc.att.HasPQEvidence()
		if got != tc.want {
			t.Errorf("%s: HasPQEvidence() = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestTranscriptHash_Determinism pins same-inputs-same-output —
// required for verifier ↔ signer agreement on the digest.
func TestTranscriptHash_Determinism(t *testing.T) {
	ctx := &AttestationContext{
		TLSCertFingerprint: [32]byte{0x01, 0x02, 0x03},
		ChainID:            [32]byte{0xff, 0xfe, 0xfd},
		PeerMLKEMPub:       []byte("mlkem-pub-bytes"),
		Timestamp:          1700000000,
		Nonce:              [32]byte{0xde, 0xad, 0xbe, 0xef},
	}
	if TranscriptHash(ctx) != TranscriptHash(ctx) {
		t.Fatal("TranscriptHash is not deterministic")
	}
}

// TestTranscriptHash_FieldDistinction pins that changing ANY
// transcript field changes the digest — an attacker can't reuse
// a signature across different chains, sessions, or cert bindings.
func TestTranscriptHash_FieldDistinction(t *testing.T) {
	base := &AttestationContext{
		TLSCertFingerprint: [32]byte{0x01},
		ChainID:            [32]byte{0x02},
		PeerMLKEMPub:       []byte("a"),
		Timestamp:          1,
		Nonce:              [32]byte{0x03},
	}
	h0 := TranscriptHash(base)
	for _, mutate := range []func(*AttestationContext){
		func(c *AttestationContext) { c.TLSCertFingerprint[0] = 0xff },
		func(c *AttestationContext) { c.ChainID[0] = 0xff },
		func(c *AttestationContext) { c.PeerMLKEMPub = []byte("b") },
		func(c *AttestationContext) { c.Timestamp = 2 },
		func(c *AttestationContext) { c.Nonce[0] = 0xff },
	} {
		ctx := *base
		mutate(&ctx)
		if TranscriptHash(&ctx) == h0 {
			t.Errorf("TranscriptHash unchanged after mutation %+v", ctx)
		}
	}
}

// TestValidateMode_StrictPQ pins integration with pq.ValidateMode:
// the canonical strict-PQ gate refuses a missing attestation,
// calls the verifier when one is present, and propagates errors
// verbatim.
func TestValidateMode_StrictPQ(t *testing.T) {
	// Missing attestation → ErrClassicalAuthForbidden.
	if err := pq.ValidateMode(pq.ModeStrictPQ, (*Attestation)(nil), nil); !errors.Is(err, pq.ErrClassicalAuthForbidden) {
		t.Errorf("StrictPQ accepted nil attestation: %v", err)
	}
	// Present attestation + verifier returning nil → accept.
	verify := pq.Verify(func() error { return nil })
	att := &Attestation{PubKey: []byte("p"), Sig: []byte("s")}
	if err := pq.ValidateMode(pq.ModeStrictPQ, att, verify); err != nil {
		t.Errorf("StrictPQ refused valid attestation: %v", err)
	}
	// Present attestation + verifier returning error → propagate.
	want := errors.New("verifier failed")
	verifyErr := pq.Verify(func() error { return want })
	if err := pq.ValidateMode(pq.ModeStrictPQ, att, verifyErr); !errors.Is(err, want) {
		t.Errorf("verifier error not propagated: %v", err)
	}
}
