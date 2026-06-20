// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"testing"
)

// TestMagicIsZPQ1 pins the §6.0 magic prefix to its exact ASCII
// bytes. Any change here invalidates every deployed peer — this is
// what protects against accidentally renaming the wire identifier.
func TestMagicIsZPQ1(t *testing.T) {
	want := []byte{'Z', 'P', 'Q', '1'}
	if !bytes.Equal(Magic[:], want) {
		t.Fatalf("Magic = %v, want %v", Magic, want)
	}
	if MagicLen != 4 {
		t.Fatalf("MagicLen = %d, want 4", MagicLen)
	}
}

// TestProtocolLabelString pins LblProtocol to "ZAP-PQ-v1". Bumping
// the protocol version (§18) requires changing this string AND the
// magic prefix — leaving them mismatched would let an old peer
// silently downgrade the new one.
func TestProtocolLabelString(t *testing.T) {
	if string(LblProtocol) != "ZAP-PQ-v1" {
		t.Fatalf("LblProtocol = %q, want %q", string(LblProtocol), "ZAP-PQ-v1")
	}
}

// TestSignContextString pins SignCtx to "lux-zap-pq-v1". This is the
// FIPS 204 ctx string baked into every AUTH signature; changing it
// would invalidate every cached identity and break cross-protocol
// replay resistance.
func TestSignContextString(t *testing.T) {
	if string(SignCtx) != "lux-zap-pq-v1" {
		t.Fatalf("SignCtx = %q, want %q", string(SignCtx), "lux-zap-pq-v1")
	}
}

// TestFrameTypeByteMapping pins each §6 frame type to its wire byte
// value. Renumbering would break every running peer.
func TestFrameTypeByteMapping(t *testing.T) {
	cases := []struct {
		t    FrameType
		want byte
	}{
		{FrameHello, 0x01},
		{FrameKEMInit, 0x02},
		{FrameKEMReply, 0x03},
		{FrameAuth, 0x04},
		{FrameData, 0x05},
		{FrameRekey, 0x06},
		{FrameAlert, 0x07},
		{FrameHelloPSK, 0x08},
	}
	for _, c := range cases {
		if byte(c.t) != c.want {
			t.Errorf("FrameType %d = 0x%02x, want 0x%02x", c.t, byte(c.t), c.want)
		}
	}
}

// TestProfileConstantsDistinct ensures the chain security profiles
// are unique values — a collision would conflate refusal semantics.
func TestProfileConstantsDistinct(t *testing.T) {
	seen := make(map[Profile]string)
	cases := []struct {
		p    Profile
		name string
	}{
		{ProfileStrictPQ, "StrictPQ"},
		{ProfilePermissive, "Permissive"},
		{ProfileFIPS, "FIPS"},
	}
	for _, c := range cases {
		if other, dup := seen[c.p]; dup {
			t.Errorf("Profile %s collides with %s at value %d", c.name, other, c.p)
		}
		seen[c.p] = c.name
	}
}

// TestPQModeConstantsDistinct: every PQMode value MUST map to a
// distinct wire byte.
func TestPQModeConstantsDistinct(t *testing.T) {
	seen := make(map[PQMode]string)
	cases := []struct {
		m    PQMode
		name string
	}{
		{PQModeClassicalPermitted, "ClassicalPermitted"},
		{PQModePQRequired, "PQRequired"},
		{PQModePQOnly, "PQOnly"},
	}
	for _, c := range cases {
		if other, dup := seen[c.m]; dup {
			t.Errorf("PQMode %s collides with %s at value %d", c.name, other, c.m)
		}
		seen[c.m] = c.name
	}
}

// TestCipherSuiteRegistryByteMapping pins the §3.2 reserved byte
// allocations.
func TestCipherSuiteRegistryByteMapping(t *testing.T) {
	if byte(SuiteX25519MLKEM) != 0x01 {
		t.Errorf("SuiteX25519MLKEM = 0x%02x, want 0x01", byte(SuiteX25519MLKEM))
	}
	if byte(SuiteReservedLo) != 0x00 {
		t.Errorf("SuiteReservedLo = 0x%02x, want 0x00", byte(SuiteReservedLo))
	}
	if byte(SuiteReservedHi) != 0xFF {
		t.Errorf("SuiteReservedHi = 0x%02x, want 0xFF", byte(SuiteReservedHi))
	}
}

// TestAuthRoleByteMapping: the §6.4 role bytes are ASCII 'I' / 'R'
// per spec.
func TestAuthRoleByteMapping(t *testing.T) {
	if byte(RoleInitiator) != 'I' {
		t.Errorf("RoleInitiator = 0x%02x, want 0x49 ('I')", byte(RoleInitiator))
	}
	if byte(RoleResponder) != 'R' {
		t.Errorf("RoleResponder = 0x%02x, want 0x52 ('R')", byte(RoleResponder))
	}
}

// TestKeyAndNonceSizes pins the lengths used by AES-256-GCM. A drift
// here would break interop with peers built against the spec.
func TestKeyAndNonceSizes(t *testing.T) {
	if AEADKeyLen != 32 {
		t.Fatalf("AEADKeyLen = %d, want 32", AEADKeyLen)
	}
	if AEADNonceLen != 12 {
		t.Fatalf("AEADNonceLen = %d, want 12", AEADNonceLen)
	}
	if AEADTagLen != 16 {
		t.Fatalf("AEADTagLen = %d, want 16", AEADTagLen)
	}
	if NonceSaltLen+NonceCtrLen != AEADNonceLen {
		t.Fatalf("salt + ctr (%d) must equal AEAD nonce length (%d)", NonceSaltLen+NonceCtrLen, AEADNonceLen)
	}
}

// TestSpecPubKeyAndSigLengths pins ML-KEM / ML-DSA / X25519 sizes
// against the FIPS 203/204 wire encodings.
func TestSpecPubKeyAndSigLengths(t *testing.T) {
	if X25519PubLen != 32 || X25519SecLen != 32 || X25519SharedLen != 32 {
		t.Fatal("X25519 sizes drifted")
	}
	if MLKEM768PubLen != 1184 || MLKEM768CTLen != 1088 || MLKEM768SharedLen != 32 {
		t.Fatal("ML-KEM-768 sizes drifted")
	}
	if MLDSA65PubLen != 1952 || MLDSA65SigLen != 3309 {
		t.Fatal("ML-DSA-65 sizes drifted")
	}
}
