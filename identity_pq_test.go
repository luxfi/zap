// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/zap/handshake"
	"golang.org/x/crypto/sha3"
)

// TestVerifyRegistration_Initial covers a non-rotation registration:
// chain-authority signature only, no PrevVMSig.
func TestVerifyRegistration_Initial(t *testing.T) {
	authority, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("authority key: %v", err)
	}
	vm, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("vm key: %v", err)
	}
	vmPubBytes := vm.PublicKey.Bytes()
	vmID := sha3.Sum256(vmPubBytes)

	payload := make([]byte, 0, 32+handshake.MLDSA65PubLen)
	payload = append(payload, vmID[:]...)
	payload = append(payload, vmPubBytes...)

	authSig, err := authority.SignCtx(rand.Reader, payload, handshake.SignCtx)
	if err != nil {
		t.Fatalf("authority sign: %v", err)
	}

	reg := &VMRegistration{
		VMID:         vmID,
		VMPubKey:     vmPubBytes,
		AuthoritySig: authSig,
	}
	pk, err := VerifyRegistration(reg, authority.PublicKey, ModeInitial)
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	if pk == nil {
		t.Fatal("nil verified pubkey")
	}
}

// TestVerifyRegistration_BadAuthoritySig covers ErrAuthoritySigFailed.
func TestVerifyRegistration_BadAuthoritySig(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	other, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	vm, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	vmPubBytes := vm.PublicKey.Bytes()
	vmID := sha3.Sum256(vmPubBytes)
	payload := append(append([]byte{}, vmID[:]...), vmPubBytes...)

	// signed by 'other' not 'authority'
	sig, _ := other.SignCtx(rand.Reader, payload, handshake.SignCtx)

	reg := &VMRegistration{VMID: vmID, VMPubKey: vmPubBytes, AuthoritySig: sig}
	if _, err := VerifyRegistration(reg, authority.PublicKey, ModeInitial); !errors.Is(err, handshake.ErrAuthoritySigFailed) {
		t.Fatalf("expected ErrAuthoritySigFailed, got %v", err)
	}
}

// TestVerifyRegistration_Rotation exercises the §10.2 rotation path
// where both the chain authority and the prior VM key must sign.
func TestVerifyRegistration_Rotation(t *testing.T) {
	authority, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	prev, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	newVM, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	vmPubBytes := newVM.PublicKey.Bytes()
	vmID := sha3.Sum256(vmPubBytes)
	payload := append(append([]byte{}, vmID[:]...), vmPubBytes...)

	authSig, _ := authority.SignCtx(rand.Reader, payload, handshake.SignCtx)
	prevSig, _ := prev.SignCtx(rand.Reader, payload, handshake.SignCtx)

	reg := &VMRegistration{
		VMID:         vmID,
		VMPubKey:     vmPubBytes,
		AuthoritySig: authSig,
		PrevVMSig:    prevSig,
		PrevVMPubKey: prev.PublicKey.Bytes(),
	}
	if _, err := VerifyRegistration(reg, authority.PublicKey, ModeRotation); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}

	// Stripping the previous-key signature under rotation must be
	// rejected — a chain-authority sig alone is not enough to replace
	// a VM key.
	reg.PrevVMSig = []byte{0x00}
	if _, err := VerifyRegistration(reg, authority.PublicKey, ModeRotation); err == nil {
		t.Fatal("malformed PrevVMSig accepted")
	}
}

// TestStaticVMRegistry covers basic Add/Lookup behaviour.
func TestStaticVMRegistry(t *testing.T) {
	r := NewStaticVMRegistry()
	var id [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	reg := &VMRegistration{VMID: id}
	r.Add(reg)
	got, ok := r.Lookup(id)
	if !ok || got != reg {
		t.Fatal("Lookup miss for registered VMID")
	}
	var missing [32]byte
	missing[0] = 0xFF
	if _, ok := r.Lookup(missing); ok {
		t.Fatal("Lookup hit for unregistered VMID")
	}
}
