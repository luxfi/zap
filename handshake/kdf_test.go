// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// TestDeriveSessionMatchesHandHKDF runs DeriveSession against fixed
// inputs and cross-checks every output against a direct HKDF call
// over the same IKM. The two implementations must produce identical
// per-direction keys, salts, and resumption PSK.
func TestDeriveSessionMatchesHandHKDF(t *testing.T) {
	h2 := bytesToArr32(bytesPattern(0x11, TranscriptLen))
	xShared := bytesToArr32(bytesPattern(0x22, X25519SharedLen))
	mlkemShared := bytesToArr32(bytesPattern(0x33, MLKEM768SharedLen))

	got := DeriveSession(h2, xShared, mlkemShared)

	// Hand-compute the canonical IKM and PRK.
	ikm := make([]byte, 0)
	ikm = append(ikm, byte(len(LblX25519)))
	ikm = append(ikm, LblX25519...)
	ikm = append(ikm, byte(X25519SharedLen))
	ikm = append(ikm, xShared[:]...)
	ikm = append(ikm, byte(len(LblMLKEM)))
	ikm = append(ikm, LblMLKEM...)
	ikm = append(ikm, byte(MLKEM768SharedLen))
	ikm = append(ikm, mlkemShared[:]...)

	prk := hkdf.Extract(sha3.New256, ikm, h2[:])

	wantKI2R := readExpand(t, prk, LblSessionI2R, AEADKeyLen)
	wantKR2I := readExpand(t, prk, LblSessionR2I, AEADKeyLen)
	wantSaltI2R := readExpand(t, prk, LblSaltI2R, NonceSaltLen)
	wantSaltR2I := readExpand(t, prk, LblSaltR2I, NonceSaltLen)
	wantRPSK := readExpand(t, prk, LblResumption, PSKKeyLen)

	if !bytes.Equal(got.KInitToResp[:], wantKI2R) {
		t.Errorf("k_i2r mismatch:\n want %s\n got  %s",
			hex.EncodeToString(wantKI2R), hex.EncodeToString(got.KInitToResp[:]))
	}
	if !bytes.Equal(got.KRespToInit[:], wantKR2I) {
		t.Errorf("k_r2i mismatch:\n want %s\n got  %s",
			hex.EncodeToString(wantKR2I), hex.EncodeToString(got.KRespToInit[:]))
	}
	if !bytes.Equal(got.SaltInitToResp[:], wantSaltI2R) {
		t.Errorf("salt_i2r mismatch:\n want %s\n got  %s",
			hex.EncodeToString(wantSaltI2R), hex.EncodeToString(got.SaltInitToResp[:]))
	}
	if !bytes.Equal(got.SaltRespToInit[:], wantSaltR2I) {
		t.Errorf("salt_r2i mismatch:\n want %s\n got  %s",
			hex.EncodeToString(wantSaltR2I), hex.EncodeToString(got.SaltRespToInit[:]))
	}
	if !bytes.Equal(got.ResumptionPSK[:], wantRPSK) {
		t.Errorf("resumption_psk mismatch:\n want %s\n got  %s",
			hex.EncodeToString(wantRPSK), hex.EncodeToString(got.ResumptionPSK[:]))
	}
}

// TestRatchetDistinctKeys verifies §13 — successive epochs produce
// independent keys and salts. Reusing the same key would defeat
// forward secrecy of the rekey ratchet.
func TestRatchetDistinctKeys(t *testing.T) {
	var k0 [AEADKeyLen]byte
	for i := range k0 {
		k0[i] = byte(i)
	}
	k1, salt1 := Ratchet(k0, 0)
	k2, salt2 := Ratchet(k1, 1)

	if k0 == k1 || k1 == k2 {
		t.Fatal("ratcheted keys must differ from predecessor")
	}
	if salt1 == salt2 {
		t.Fatal("ratcheted salts must differ across epochs")
	}
	// Salt and key derived from the SAME k_n must differ — they use
	// distinct info bytes per §13.
	if bytes.Equal(k1[:NonceSaltLen], salt1[:]) {
		t.Fatal("ratcheted key prefix coincidentally matched salt — info bytes likely identical")
	}
}

// TestPSKIDStable confirms PSKID is a stable function of the PSK
// (no random injection) and 16 bytes long. PSKID is used as the
// dictionary key for the server store; instability would lose the
// entry between issuance and lookup.
func TestPSKIDStable(t *testing.T) {
	var psk [PSKKeyLen]byte
	for i := range psk {
		psk[i] = byte(0xC0 + i%16)
	}
	id1 := PSKID(psk)
	id2 := PSKID(psk)
	if id1 != id2 {
		t.Fatal("PSKID not stable")
	}
	// Ensure it's the first 16 bytes of SHA3-256(psk).
	full := sha3.Sum256(psk[:])
	var want [PSKIDLen]byte
	copy(want[:], full[:PSKIDLen])
	if id1 != want {
		t.Fatalf("PSKID derivation drift\n want %s\n got  %s",
			hex.EncodeToString(want[:]), hex.EncodeToString(id1[:]))
	}
}

// helpers

func bytesToArr32(b []byte) [32]byte {
	var a [32]byte
	copy(a[:], b)
	return a
}

func readExpand(t *testing.T, prk, info []byte, n int) []byte {
	t.Helper()
	r := hkdf.Expand(sha3.New256, prk, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("HKDF-Expand: %v", err)
	}
	return out
}
