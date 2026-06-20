// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import "testing"

// All fuzz targets share the same shape:
//
//   - Random input bytes go through the corresponding Decode*.
//   - The decoder MUST NOT panic.
//   - On a successful decode the caller's behaviour is undefined for
//     truly random inputs — we don't re-encode and round-trip
//     because Decode* may accept inputs whose Encode is a different
//     canonical form (e.g. ALERT detail length is implicit).
//
// The seeds are representative valid frames so the fuzzer has a
// foothold; mutating from there explores the codec attack surface.

func FuzzDecodeHello(f *testing.F) {
	pk := bytesPattern(0x77, MLDSA65PubLen)
	seed := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		PQMode:            PQModePQOnly,
		OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
		StaticPKInitiator: pk,
	}
	if body, err := seed.Encode(); err == nil {
		f.Add(body)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 1))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeHello(body)
	})
}

func FuzzDecodeKEMInit(f *testing.F) {
	seed := &KEMInitFrame{}
	f.Add(seed.Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeKEMInit(body)
	})
}

func FuzzDecodeKEMReply(f *testing.F) {
	pk := bytesPattern(0x33, MLDSA65PubLen)
	seed := &KEMReplyFrame{StaticPKResponder: pk}
	if body, err := seed.Encode(); err == nil {
		f.Add(body)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeKEMReply(body)
	})
}

func FuzzDecodeAuth(f *testing.F) {
	sig := bytesPattern(0x55, MLDSA65SigLen)
	seed := &AuthFrame{Role: RoleInitiator, Signature: sig}
	if body, err := seed.Encode(); err == nil {
		f.Add(body)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeAuth(body)
	})
}

func FuzzDecodeData(f *testing.F) {
	seed := &DataFrame{NonceCounter: 7, Ciphertext: []byte("ct")}
	f.Add(seed.Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeData(body)
	})
}

func FuzzDecodeAlert(f *testing.F) {
	seed := &AlertFrame{Code: AlertAuthFailed, Detail: []byte("nope")}
	f.Add(seed.Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeAlert(body)
	})
}

func FuzzDecodeRekey(f *testing.F) {
	seed := &RekeyFrame{Reason: RekeyReasonExplicit}
	f.Add(seed.Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeRekey(body)
	})
}

func FuzzDecodeHelloPSK(f *testing.F) {
	seed := &HelloPSKFrame{Suite: SuiteX25519MLKEM, PQMode: PQModePQOnly}
	f.Add(seed.Encode())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeHelloPSK(body)
	})
}
