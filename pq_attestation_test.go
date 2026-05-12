// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"errors"
	"testing"
)

func TestSecurityProfile_StringAndPredicates(t *testing.T) {
	for _, tc := range []struct {
		profile          SecurityProfile
		wantString       string
		wantPostQuantum  bool
		wantPQAware      bool
	}{
		{ProfileClassical, "classical", false, false},
		{ProfileHybrid, "hybrid", false, true},
		{ProfileStrictPQ, "strict-pq", true, true},
		{SecurityProfile(99), "unknown", false, false},
	} {
		if tc.profile.String() != tc.wantString {
			t.Errorf("%d.String() = %q, want %q",
				tc.profile, tc.profile.String(), tc.wantString)
		}
		if tc.profile.IsPostQuantum() != tc.wantPostQuantum {
			t.Errorf("%s.IsPostQuantum() = %t, want %t",
				tc.profile, tc.profile.IsPostQuantum(), tc.wantPostQuantum)
		}
		if tc.profile.IsPQAware() != tc.wantPQAware {
			t.Errorf("%s.IsPQAware() = %t, want %t",
				tc.profile, tc.profile.IsPQAware(), tc.wantPQAware)
		}
	}
}

func TestProfileFromString(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    SecurityProfile
		wantErr bool
	}{
		{"classical", ProfileClassical, false},
		{"hybrid", ProfileHybrid, false},
		{"strict-pq", ProfileStrictPQ, false},
		{"", 0, true},
		{"PQ", 0, true},
		{"strict_pq", 0, true},
	} {
		got, err := ProfileFromString(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ProfileFromString(%q) err=%v, wantErr=%t",
				tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ProfileFromString(%q) = %s, want %s",
				tc.input, got, tc.want)
		}
	}
}

// TestTranscriptHash_Determinism pins that the same inputs always
// produce the same hash — required for verifier <-> signer
// agreement on the digest.
func TestTranscriptHash_Determinism(t *testing.T) {
	ctx := &AttestationContext{
		TLSCertFingerprint: [32]byte{0x01, 0x02, 0x03},
		ChainID:            [32]byte{0xff, 0xfe, 0xfd},
		PeerMLKEMPub:       []byte("mlkem-pub-bytes"),
		Timestamp:          1700000000,
		Nonce:              [32]byte{0xde, 0xad, 0xbe, 0xef},
	}
	h1 := TranscriptHash(ctx)
	h2 := TranscriptHash(ctx)
	if h1 != h2 {
		t.Fatal("TranscriptHash is not deterministic")
	}
}

// TestTranscriptHash_FieldDistinction pins that changing ANY
// transcript field changes the digest. This is the property an
// attacker can't bypass: they can't reuse a signature across
// different chains, different sessions, or different cert
// bindings.
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
		hm := TranscriptHash(&ctx)
		if hm == h0 {
			t.Errorf("TranscriptHash unchanged after mutation %+v", ctx)
		}
	}
}

func TestRequireAttestationForProfile_Classical(t *testing.T) {
	// Classical never refuses, never calls verifier.
	called := false
	verify := func(_, _, _ []byte) error { called = true; return nil }
	if err := RequireAttestationForProfile(ProfileClassical, nil, nil, verify); err != nil {
		t.Errorf("Classical refused nil attestation: %v", err)
	}
	if err := RequireAttestationForProfile(ProfileClassical,
		&Attestation{PubKey: []byte("x"), Sig: []byte("y")}, nil, verify); err != nil {
		t.Errorf("Classical refused attestation: %v", err)
	}
	if called {
		t.Error("Classical called the verifier (should never)")
	}
}

func TestRequireAttestationForProfile_StrictPQRefusesMissing(t *testing.T) {
	verify := func(_, _, _ []byte) error { return nil }
	err := RequireAttestationForProfile(ProfileStrictPQ, nil, nil, verify)
	if !errors.Is(err, ErrClassicalAuthForbidden) {
		t.Errorf("StrictPQ accepted nil attestation: err=%v", err)
	}
}

func TestRequireAttestationForProfile_HybridAcceptsMissing(t *testing.T) {
	verify := func(_, _, _ []byte) error { return nil }
	if err := RequireAttestationForProfile(ProfileHybrid, nil, nil, verify); err != nil {
		t.Errorf("Hybrid refused nil attestation: %v", err)
	}
}

func TestRequireAttestationForProfile_VerifierCalled(t *testing.T) {
	var seenPub, seenSig, seenHash []byte
	verify := func(p, s, h []byte) error {
		seenPub, seenSig, seenHash = p, s, h
		return nil
	}
	att := &Attestation{PubKey: []byte("pub"), Sig: []byte("sig")}
	ctx := &AttestationContext{TLSCertFingerprint: [32]byte{0x42}}
	expected := TranscriptHash(ctx)
	if err := RequireAttestationForProfile(ProfileStrictPQ, att, ctx, verify); err != nil {
		t.Fatalf("verifier returned err: %v", err)
	}
	if string(seenPub) != "pub" || string(seenSig) != "sig" {
		t.Errorf("verifier got pub=%q sig=%q", seenPub, seenSig)
	}
	if string(seenHash) != string(expected[:]) {
		t.Error("verifier got wrong transcript hash")
	}
}

func TestRequireAttestationForProfile_VerifierErrorPropagates(t *testing.T) {
	want := errors.New("verifier failed")
	verify := func(_, _, _ []byte) error { return want }
	att := &Attestation{PubKey: []byte("p"), Sig: []byte("s")}
	ctx := &AttestationContext{}
	if err := RequireAttestationForProfile(ProfileStrictPQ, att, ctx, verify); !errors.Is(err, want) {
		t.Errorf("verifier error not propagated: %v", err)
	}
}

func TestRequireAttestationForProfile_NilVerifier(t *testing.T) {
	att := &Attestation{PubKey: []byte("p"), Sig: []byte("s")}
	ctx := &AttestationContext{}
	if err := RequireAttestationForProfile(ProfileStrictPQ, att, ctx, nil); err == nil {
		t.Error("StrictPQ accepted nil verifier")
	}
}
