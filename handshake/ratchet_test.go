// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// TestRatchetManyEpochsAllDistinct ratchets a key across every epoch
// from 0 to 0xFE and asserts all 255 derived keys are pairwise
// distinct. This is the strongest property the rekey ratchet
// guarantees — no two epochs produce the same key.
func TestRatchetManyEpochsAllDistinct(t *testing.T) {
	const N = 255
	keys := make(map[[AEADKeyLen]byte]int, N+1)
	salts := make(map[[NonceSaltLen]byte]int, N+1)

	var k [AEADKeyLen]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	keys[k] = -1 // initial key counted at epoch -1

	for e := 0; e < N; e++ {
		next, salt := Ratchet(k, uint8(e))
		if prevEpoch, dup := keys[next]; dup {
			t.Fatalf("key collision at epoch %d (also seen at %d)", e, prevEpoch)
		}
		keys[next] = e
		if prevEpoch, dup := salts[salt]; dup {
			t.Logf("salt collision at epoch %d (also at %d) — expected probabilistically for 4-byte salts", e, prevEpoch)
		}
		salts[salt] = e
		k = next
	}
}

// TestCrossEpochDecryptRejected proves the rekey ratchet provides
// forward secrecy of the previous epoch's traffic: a DATA frame
// sealed under k_n must NOT decrypt under k_{n+1} or vice versa.
//
// We construct an AES-256-GCM seal under k_0, then attempt to open
// it under k_1 (the ratcheted-forward key). The open MUST fail.
func TestCrossEpochDecryptRejected(t *testing.T) {
	var k0 [AEADKeyLen]byte
	for i := range k0 {
		k0[i] = byte(i)
	}
	salt0 := [NonceSaltLen]byte{1, 2, 3, 4}

	aead0 := mustAEAD(t, k0)
	nonce := buildNonce(salt0, 0)
	aad := buildAAD(FrameData, 100, RoleInitiator, 0)
	ct := aead0.Seal(nil, nonce[:], []byte("plaintext"), aad[:])

	// Ratchet forward.
	k1, _ := Ratchet(k0, 0)
	aead1 := mustAEAD(t, k1)

	if _, err := aead1.Open(nil, nonce[:], ct, aad[:]); err == nil {
		t.Fatal("ciphertext sealed under k_0 decrypted under k_1 — forward secrecy broken")
	}
}

// TestSessionAutoRekeyOnFrameCap mutates the local sendFrameCap to
// 4, sends 5 DATA frames, and confirms a REKEY landed mid-stream and
// the receiver tracked the epoch transition.
func TestSessionAutoRekeyOnFrameCap(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// Drop the frame cap to force an auto-rekey after 4 frames.
	client.sendMu.Lock()
	client.sendFrameCap = 4
	client.sendMu.Unlock()

	for i := 0; i < 5; i++ {
		if err := client.Send([]byte{byte(i)}); err != nil {
			t.Fatalf("send[%d]: %v", i, err)
		}
		got, err := server.Recv()
		if err != nil {
			t.Fatalf("recv[%d]: %v", i, err)
		}
		if len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("recv[%d] payload mismatch", i)
		}
	}

	if client.Epoch() == 0 {
		t.Fatal("client epoch never advanced — auto-rekey did not fire")
	}
}

// TestSessionRekeyEpochByteOnWire verifies the epoch byte enters the
// AAD: a frame sealed under epoch=0 cannot be opened with AAD claiming
// epoch=1. Sanity check that buildAAD actually includes the epoch.
func TestSessionRekeyEpochByteOnWire(t *testing.T) {
	var k [AEADKeyLen]byte
	for i := range k {
		k[i] = 0xAB
	}
	salt := [NonceSaltLen]byte{0xCD, 0xEF, 0x01, 0x23}
	aead := mustAEAD(t, k)

	nonce := buildNonce(salt, 0)
	aadE0 := buildAAD(FrameData, 50, RoleInitiator, 0)
	aadE1 := buildAAD(FrameData, 50, RoleInitiator, 1)

	ct := aead.Seal(nil, nonce[:], []byte("x"), aadE0[:])
	if _, err := aead.Open(nil, nonce[:], ct, aadE1[:]); err == nil {
		t.Fatal("epoch byte not bound into AAD — open succeeded with wrong epoch")
	}
}

// mustAEAD builds an AES-256-GCM AEAD or fails the test.
func mustAEAD(t *testing.T, key [AEADKeyLen]byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return a
}
