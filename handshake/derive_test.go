// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"testing"
)

// TestDeriveSessionDeterministic: same inputs MUST always produce
// the same outputs. KDF is a pure function — any non-determinism
// would mean we accidentally pulled randomness somewhere.
func TestDeriveSessionDeterministic(t *testing.T) {
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	m := bytesToArr32(bytesPattern(0x30, MLKEM768SharedLen))

	a := DeriveSession(h2, x, m)
	b := DeriveSession(h2, x, m)

	if a != b {
		t.Fatal("DeriveSession not deterministic on identical inputs")
	}
}

// TestDeriveSessionInputSensitivity: changing any input bit must
// flip every output. This is the diffusion property HKDF promises.
func TestDeriveSessionInputSensitivity(t *testing.T) {
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	m := bytesToArr32(bytesPattern(0x30, MLKEM768SharedLen))
	base := DeriveSession(h2, x, m)

	// Flip a bit in h2.
	h2b := h2
	h2b[0] ^= 0x01
	out := DeriveSession(h2b, x, m)
	if out.KInitToResp == base.KInitToResp || out.KRespToInit == base.KRespToInit {
		t.Fatal("KDF insensitive to H_2 perturbation")
	}

	// Flip a bit in x25519_shared.
	xb := x
	xb[0] ^= 0x01
	out = DeriveSession(h2, xb, m)
	if out.KInitToResp == base.KInitToResp {
		t.Fatal("KDF insensitive to X25519 perturbation")
	}

	// Flip a bit in mlkem_shared.
	mb := m
	mb[0] ^= 0x01
	out = DeriveSession(h2, x, mb)
	if out.KInitToResp == base.KInitToResp {
		t.Fatal("KDF insensitive to ML-KEM perturbation")
	}
}

// TestDeriveResumedDeterministic: same property for the resumption KDF.
func TestDeriveResumedDeterministic(t *testing.T) {
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	psk := bytesToArr32(bytesPattern(0x40, PSKKeyLen))

	a := DeriveResumed(h2, x, psk)
	b := DeriveResumed(h2, x, psk)
	if a != b {
		t.Fatal("DeriveResumed not deterministic")
	}
}

// TestDeriveResumedIsolation: DeriveSession and DeriveResumed are
// labelled differently (LblMLKEM vs LblResumption in IKM); the
// resulting keys must differ even when the second input slot is
// numerically the same 32 bytes.
//
// This prevents an attacker who recovers a resumption_psk from
// substituting it for an mlkem_shared (or vice-versa) in a parallel
// session.
func TestDeriveResumedIsolation(t *testing.T) {
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	same := bytesToArr32(bytesPattern(0x40, 32))

	full := DeriveSession(h2, x, same)
	resumed := DeriveResumed(h2, x, same)

	if full.KInitToResp == resumed.KInitToResp {
		t.Fatal("DeriveSession and DeriveResumed produce same key for same second input — label isolation broken")
	}
	if full.ResumptionPSK == resumed.ResumptionPSK {
		t.Fatal("resumption_psk leaks across full vs resumed derivations")
	}
}

// TestDeriveResumedTranscriptBinding: changing H_2 must flip outputs.
func TestDeriveResumedTranscriptBinding(t *testing.T) {
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	psk := bytesToArr32(bytesPattern(0x40, PSKKeyLen))

	h2a := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	h2b := h2a
	h2b[0] ^= 0xFF

	a := DeriveResumed(h2a, x, psk)
	b := DeriveResumed(h2b, x, psk)
	if a.KInitToResp == b.KInitToResp {
		t.Fatal("DeriveResumed insensitive to H_2_psk")
	}
}

// TestSessionKeysFieldsZeroed: SessionKeys.Zeroize wipes every field
// — used by the Initiator/Responder after handing the kept-alive
// copy to the Session.
func TestSessionKeysFieldsZeroed(t *testing.T) {
	k := SessionKeys{}
	for i := range k.KInitToResp {
		k.KInitToResp[i] = 0xFF
	}
	for i := range k.KRespToInit {
		k.KRespToInit[i] = 0xFF
	}
	for i := range k.SaltInitToResp {
		k.SaltInitToResp[i] = 0xFF
	}
	for i := range k.SaltRespToInit {
		k.SaltRespToInit[i] = 0xFF
	}
	for i := range k.ResumptionPSK {
		k.ResumptionPSK[i] = 0xFF
	}
	k.Zeroize()
	if k.KInitToResp != [AEADKeyLen]byte{} {
		t.Fatal("KInitToResp")
	}
	if k.KRespToInit != [AEADKeyLen]byte{} {
		t.Fatal("KRespToInit")
	}
	if k.SaltInitToResp != [NonceSaltLen]byte{} {
		t.Fatal("SaltInitToResp")
	}
	if k.SaltRespToInit != [NonceSaltLen]byte{} {
		t.Fatal("SaltRespToInit")
	}
	if k.ResumptionPSK != [PSKKeyLen]byte{} {
		t.Fatal("ResumptionPSK")
	}
}
