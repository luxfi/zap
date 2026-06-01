// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"testing"
)

// TestHelloRoundTrip ensures Encode → Decode is the identity for a
// fully-populated HELLO. Catches accidental field reordering.
func TestHelloRoundTrip(t *testing.T) {
	pk := bytesPattern(0x77, MLDSA65PubLen)
	want := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		PQMode:            PQModePQOnly,
		ClientRandom:      bytesToArr16(bytesPattern(0x11, ClientRandLen)),
		TimestampNS:       0x1122334455667788,
		ClientID:          bytesToArr32(bytesPattern(0x22, IDLen)),
		OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
		StaticPKInitiator: pk,
	}
	body, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeHello(body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Suite != want.Suite || got.PQMode != want.PQMode ||
		got.ClientRandom != want.ClientRandom ||
		got.TimestampNS != want.TimestampNS ||
		got.ClientID != want.ClientID ||
		!bytes.Equal(got.StaticPKInitiator, want.StaticPKInitiator) {
		t.Fatalf("HELLO mismatch:\n want %+v\n got  %+v", want, got)
	}
	if len(got.OfferedSchemes) != 1 || got.OfferedSchemes[0] != SuiteX25519MLKEM {
		t.Fatalf("OfferedSchemes mismatch: %v", got.OfferedSchemes)
	}
}

func TestHelloRejectsSuiteNotInOffer(t *testing.T) {
	pk := bytesPattern(0x77, MLDSA65PubLen)
	h := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		OfferedSchemes:    []SuiteID{0xFE}, // does not include 0x01
		StaticPKInitiator: pk,
	}
	body, err := h.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeHello(body); err == nil {
		t.Fatal("DecodeHello accepted suite not in offered_schemes")
	}
}

func TestKEMInitRoundTrip(t *testing.T) {
	want := &KEMInitFrame{
		X25519EphPub: bytesToArr32(bytesPattern(0x10, X25519PubLen)),
	}
	for i := range want.MLKEMEphPub {
		want.MLKEMEphPub[i] = byte(i)
	}
	got, err := DecodeKEMInit(want.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.X25519EphPub != want.X25519EphPub || got.MLKEMEphPub != want.MLKEMEphPub {
		t.Fatal("KEM_INIT round-trip mismatch")
	}
}

func TestKEMReplyRoundTrip(t *testing.T) {
	pk := bytesPattern(0x33, MLDSA65PubLen)
	want := &KEMReplyFrame{
		X25519EphPub:      bytesToArr32(bytesPattern(0x20, X25519PubLen)),
		StaticPKResponder: pk,
	}
	for i := range want.MLKEMCiphertext {
		want.MLKEMCiphertext[i] = byte(i)
	}
	body, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeKEMReply(body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.X25519EphPub != want.X25519EphPub ||
		got.MLKEMCiphertext != want.MLKEMCiphertext ||
		!bytes.Equal(got.StaticPKResponder, want.StaticPKResponder) {
		t.Fatal("KEM_REPLY round-trip mismatch")
	}
}

func TestAuthRoundTrip(t *testing.T) {
	sig := bytesPattern(0x55, MLDSA65SigLen)
	want := &AuthFrame{Role: RoleInitiator, Signature: sig}
	body, err := want.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeAuth(body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Role != want.Role || !bytes.Equal(got.Signature, want.Signature) {
		t.Fatal("AUTH round-trip mismatch")
	}
}

func TestDataRoundTrip(t *testing.T) {
	want := &DataFrame{NonceCounter: 0xDEADBEEF, Ciphertext: bytesPattern(0x80, 137)}
	got, err := DecodeData(want.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.NonceCounter != want.NonceCounter || !bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Fatal("DATA round-trip mismatch")
	}
}

func TestAlertRoundTrip(t *testing.T) {
	want := &AlertFrame{Code: AlertAuthFailed, Detail: []byte("verifier returned false")}
	got, err := DecodeAlert(want.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Code != want.Code || !bytes.Equal(got.Detail, want.Detail) {
		t.Fatal("ALERT round-trip mismatch")
	}
}

func TestHelloPSKRoundTrip(t *testing.T) {
	want := &HelloPSKFrame{
		Suite:        SuiteX25519MLKEM,
		PQMode:       PQModePQOnly,
		ClientRandom: bytesToArr16(bytesPattern(0xC1, ClientRandLen)),
		TimestampNS:  0x99,
		PSKID:        bytesToArr16(bytesPattern(0xD1, PSKIDLen)),
		X25519EphPub: bytesToArr32(bytesPattern(0xE1, X25519PubLen)),
	}
	got, err := DecodeHelloPSK(want.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Suite != want.Suite || got.PQMode != want.PQMode ||
		got.ClientRandom != want.ClientRandom ||
		got.TimestampNS != want.TimestampNS ||
		got.PSKID != want.PSKID ||
		got.X25519EphPub != want.X25519EphPub {
		t.Fatal("HELLO_PSK round-trip mismatch")
	}
}

func bytesToArr16(b []byte) [16]byte {
	var a [16]byte
	copy(a[:], b)
	return a
}
