// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"errors"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestIdentityIDStable confirms ID() = SHA3-256(PublicKey.Bytes()).
// Verifies the binding two ways: the helper-derived value and a
// hand-computed digest. Equality is the prerequisite for the §10.1
// client_id check inside Responder.runFull.
func TestIdentityIDStable(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	got := id.ID()
	want := sha3.Sum256(id.PublicBytes())
	if got != want {
		t.Fatal("Identity.ID() != SHA3-256(PublicBytes())")
	}
}

// TestIdentitySignVerifyHappyPath covers §6.4 sign + verify on
// matching (h2, role, suite) inputs.
func TestIdentitySignVerifyHappyPath(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))

	sig, err := id.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != MLDSA65SigLen {
		t.Fatalf("sig length %d, want %d", len(sig), MLDSA65SigLen)
	}
	if err := id.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestIdentityVerifyRejectsWrongRole covers the role-bound part of
// §6.4 sign_input: a signature minted for RoleInitiator must NOT
// verify under RoleResponder.
func TestIdentityVerifyRejectsWrongRole(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x20, TranscriptLen))
	sig, err := id.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := id.VerifyAuth(h2, RoleResponder, SuiteX25519MLKEM, sig); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("cross-role accepted: %v", err)
	}
}

// TestIdentityVerifyRejectsWrongSuite covers the suite-bound part of
// §6.4 sign_input.
func TestIdentityVerifyRejectsWrongSuite(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x30, TranscriptLen))
	sig, err := id.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := id.VerifyAuth(h2, RoleInitiator, 0x02, sig); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("cross-suite accepted: %v", err)
	}
}

// TestIdentityVerifyRejectsWrongTranscript: changing the transcript
// hash invalidates the signature — this is what catches the §7
// scheme-strip downgrade attack.
func TestIdentityVerifyRejectsWrongTranscript(t *testing.T) {
	id, _ := GenerateIdentity()
	h2a := bytesToArr32(bytesPattern(0x40, TranscriptLen))
	h2b := bytesToArr32(bytesPattern(0x41, TranscriptLen))
	sig, _ := id.Sign(nil, h2a, RoleInitiator, SuiteX25519MLKEM)
	if err := id.VerifyAuth(h2b, RoleInitiator, SuiteX25519MLKEM, sig); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("cross-transcript accepted: %v", err)
	}
}

// TestIdentityVerifyRejectsTamperedSig flips one byte of the
// signature and expects refusal.
func TestIdentityVerifyRejectsTamperedSig(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x50, TranscriptLen))
	sig, _ := id.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	sig[100] ^= 0xFF
	if err := id.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("tampered sig accepted: %v", err)
	}
}

// TestIdentityFromPublicBytesValidation: malformed inputs produce
// errors, not panics.
func TestIdentityFromPublicBytesValidation(t *testing.T) {
	if _, err := IdentityFromPublicBytes(nil); err == nil {
		t.Fatal("nil pubkey accepted")
	}
	if _, err := IdentityFromPublicBytes(make([]byte, 32)); err == nil {
		t.Fatal("wrong-size pubkey accepted")
	}
}

// TestIdentitySignWithoutPrivate: an Identity without a private key
// (peer-only) cannot Sign — returns a clear error.
func TestIdentitySignWithoutPrivate(t *testing.T) {
	id, _ := GenerateIdentity()
	peerOnly := &Identity{PublicKey: id.PublicKey}
	if _, err := peerOnly.Sign(nil, [TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM); err == nil {
		t.Fatal("Sign succeeded on peer-only identity")
	}
}

// TestIdentityVerifyAcrossKeys: a signature minted by one identity
// must NOT verify against a different identity's public key.
func TestIdentityVerifyAcrossKeys(t *testing.T) {
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x60, TranscriptLen))
	sig, _ := a.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	if err := b.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("cross-identity verify accepted: %v", err)
	}
}
