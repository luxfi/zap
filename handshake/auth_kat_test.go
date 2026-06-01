// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"testing"
)

// TestSignDeterministicProducesStableSig: identical inputs to
// SignDeterministic always produce identical signatures (FIPS 204
// §5.2 determinism property).
func TestSignDeterministicProducesStableSig(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x11, TranscriptLen))

	sig1, err := id.SignDeterministic(h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign 1: %v", err)
	}
	sig2, err := id.SignDeterministic(h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("SignDeterministic produced different sigs for identical inputs")
	}
	if err := id.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig1); err != nil {
		t.Fatalf("deterministic sig fails verify: %v", err)
	}
}

// TestSignDeterministicSensitivity: changing any input flips the
// signature bytes (basic diffusion).
func TestSignDeterministicSensitivity(t *testing.T) {
	id, _ := GenerateIdentity()
	h2a := bytesToArr32(bytesPattern(0x22, TranscriptLen))
	h2b := h2a
	h2b[0] ^= 0x01

	sigA, _ := id.SignDeterministic(h2a, RoleInitiator, SuiteX25519MLKEM)
	sigB, _ := id.SignDeterministic(h2b, RoleInitiator, SuiteX25519MLKEM)
	if bytes.Equal(sigA, sigB) {
		t.Fatal("transcript-perturbed sigs are identical — deterministic sign broken")
	}

	sigR, _ := id.SignDeterministic(h2a, RoleResponder, SuiteX25519MLKEM)
	if bytes.Equal(sigA, sigR) {
		t.Fatal("role-perturbed sigs are identical")
	}

	sigS, _ := id.SignDeterministic(h2a, RoleInitiator, 0x02)
	if bytes.Equal(sigA, sigS) {
		t.Fatal("suite-perturbed sigs are identical")
	}
}

// TestSignDeterministicSeparateKey: two different keys never produce
// the same deterministic signature on the same input.
func TestSignDeterministicSeparateKey(t *testing.T) {
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x33, TranscriptLen))

	sigA, _ := a.SignDeterministic(h2, RoleInitiator, SuiteX25519MLKEM)
	sigB, _ := b.SignDeterministic(h2, RoleInitiator, SuiteX25519MLKEM)
	if bytes.Equal(sigA, sigB) {
		t.Fatal("different keys produced identical deterministic sigs")
	}
	// Cross-verify must fail.
	if err := b.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sigA); err == nil {
		t.Fatal("cross-key verify succeeded — wrong-key sig accepted")
	}
}

// TestSignDeterministicRequiresPrivateKey: peer-only identity (no
// private key) must fail SignDeterministic with a clear error.
func TestSignDeterministicRequiresPrivateKey(t *testing.T) {
	id, _ := GenerateIdentity()
	peerOnly := &Identity{PublicKey: id.PublicKey}
	if _, err := peerOnly.SignDeterministic([TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM); err == nil {
		t.Fatal("SignDeterministic succeeded without private key")
	}
}
