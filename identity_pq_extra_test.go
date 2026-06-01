// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/zap/handshake"
	"golang.org/x/crypto/sha3"
)

// TestVerifyRegistrationNilInputs covers defensive nil/empty input
// handling — every branch must return ErrRegistrationMalformed (or
// nil-deref panic if we forgot a guard).
func TestVerifyRegistrationNilInputs(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	if _, err := VerifyRegistration(nil, authority.PublicKey, ModeInitial); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("nil reg: %v", err)
	}
	good := makeValidReg(t, authority)
	if _, err := VerifyRegistration(good, nil, ModeInitial); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("nil authority: %v", err)
	}
}

// TestVerifyRegistrationFieldSizes: every fixed-size field must
// reject the wrong byte count.
func TestVerifyRegistrationFieldSizes(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	good := makeValidReg(t, authority)

	// Wrong VMPubKey length.
	bad := *good
	bad.VMPubKey = bad.VMPubKey[:len(bad.VMPubKey)-1]
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeInitial); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("short VMPubKey: %v", err)
	}

	// Wrong AuthoritySig length.
	bad = *good
	bad.AuthoritySig = []byte{0x01, 0x02}
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeInitial); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("short AuthoritySig: %v", err)
	}
}

// TestVerifyRegistrationVMIDMismatch: VMID must equal
// SHA3-256(VMPubKey); otherwise return ErrVMIdentityMismatch.
func TestVerifyRegistrationVMIDMismatch(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	good := makeValidReg(t, authority)
	bad := *good
	bad.VMID[0] ^= 0xFF
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeInitial); !errors.Is(err, handshake.ErrVMIdentityMismatch) {
		t.Fatalf("VMID mismatch: %v", err)
	}
}

// TestVerifyRegistrationRotationWrongSigner: a correct-LENGTH
// PrevVMSig signed by a third party (neither the chain authority nor
// the actual previous VM key) must be rejected. Covers the gap where
// only short / malformed sigs were previously exercised.
func TestVerifyRegistrationRotationWrongSigner(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	prev, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	imposter, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	newVM, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	vmPubBytes := newVM.PublicKey.Bytes()
	vmID := sha3.Sum256(vmPubBytes)
	payload := append(append([]byte{}, vmID[:]...), vmPubBytes...)

	authSig, _ := authority.SignCtx(rand.Reader, payload, handshake.SignCtx)
	// Sign with the IMPOSTER but claim PrevVMPubKey = prev's pubkey.
	imposterSig, _ := imposter.SignCtx(rand.Reader, payload, handshake.SignCtx)

	reg := &VMRegistration{
		VMID:         vmID,
		VMPubKey:     vmPubBytes,
		AuthoritySig: authSig,
		PrevVMSig:    imposterSig, // correct length, wrong signer
		PrevVMPubKey: prev.PublicKey.Bytes(),
	}
	if _, err := VerifyRegistration(reg, authority.PublicKey, ModeRotation); !errors.Is(err, handshake.ErrAuthoritySigFailed) {
		t.Fatalf("expected ErrAuthoritySigFailed for wrong-signer PrevVMSig, got %v", err)
	}
}

// TestVerifyRegistrationRotationMalformedPrev: when PrevVMSig is
// present, PrevVMPubKey size + sig size are validated and the sig
// must verify under the prev key.
func TestVerifyRegistrationRotationMalformedPrev(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	good := makeValidReg(t, authority)

	// Provide PrevVMSig but no PrevVMPubKey.
	bad := *good
	bad.PrevVMSig = make([]byte, handshake.MLDSA65SigLen)
	bad.PrevVMPubKey = nil
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeRotation); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("missing PrevVMPubKey: %v", err)
	}

	// Wrong PrevVMSig length.
	bad = *good
	bad.PrevVMSig = []byte{0xFF}
	bad.PrevVMPubKey = good.VMPubKey
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeRotation); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("short PrevVMSig: %v", err)
	}

	// PrevVMPubKey wrong length.
	bad = *good
	bad.PrevVMSig = make([]byte, handshake.MLDSA65SigLen)
	bad.PrevVMPubKey = []byte{0xAA}
	if _, err := VerifyRegistration(&bad, authority.PublicKey, ModeRotation); !errors.Is(err, ErrRegistrationMalformed) {
		t.Fatalf("short PrevVMPubKey: %v", err)
	}
}

// TestStaticVMRegistryConcurrentLookups races Add and Lookup from
// many goroutines. Under -race the map access must remain safe.
// (Note: StaticVMRegistry is intentionally not goroutine-safe for
// writes — the test only mixes Add at startup with Lookup later, the
// realistic operational pattern.)
func TestStaticVMRegistryConcurrentLookups(t *testing.T) {
	r := NewStaticVMRegistry()
	const N = 16
	for i := 0; i < N; i++ {
		var id [32]byte
		id[0] = byte(i)
		r.Add(&VMRegistration{VMID: id})
	}

	const G = 32
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				var id [32]byte
				id[0] = byte(i)
				if _, ok := r.Lookup(id); !ok {
					t.Errorf("Lookup miss for %d", i)
				}
			}
		}()
	}
	wg.Wait()
}

// ---------- helpers ----------

func makeValidReg(t *testing.T, authority *mldsa.PrivateKey) *VMRegistration {
	t.Helper()
	vm, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("vm key: %v", err)
	}
	pkBytes := vm.PublicKey.Bytes()
	id := sha3.Sum256(pkBytes)
	payload := append(append([]byte{}, id[:]...), pkBytes...)
	sig, err := authority.SignCtx(rand.Reader, payload, handshake.SignCtx)
	if err != nil {
		t.Fatalf("authority sign: %v", err)
	}
	return &VMRegistration{
		VMID:         id,
		VMPubKey:     pkBytes,
		AuthoritySig: sig,
	}
}
