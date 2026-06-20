// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestTranscriptH0 verifies §7's H_0 definition by hand-computing the
// expected digest on a known-zero HELLO body and comparing to what
// the Transcript chain produces.
func TestTranscriptH0(t *testing.T) {
	hello := make([]byte, 64) // arbitrary fixed body
	for i := range hello {
		hello[i] = byte(i)
	}

	want := sha3.New256()
	_, _ = want.Write(LblProtocol)
	_, _ = want.Write([]byte{0x00})
	_, _ = want.Write([]byte{byte(SuiteX25519MLKEM)})
	_, _ = want.Write(hello)
	var expected [TranscriptLen]byte
	want.Sum(expected[:0])

	tr := NewTranscript(SuiteX25519MLKEM)
	tr.AbsorbHello(hello)
	got := tr.H0()
	if got != expected {
		t.Fatalf("H_0 mismatch\n want: %s\n got:  %s",
			hex.EncodeToString(expected[:]), hex.EncodeToString(got[:]))
	}
}

// TestTranscriptH1 verifies §7's chaining property:
//
//	H_1 = SHA3-256(H_0 ∥ KEM_INIT ∥ KEM_REPLY)
func TestTranscriptH1(t *testing.T) {
	hello := []byte("hello body")
	kemInit := []byte("kem init body")
	kemReply := []byte("kem reply body")

	tr := NewTranscript(SuiteX25519MLKEM)
	tr.AbsorbHello(hello)
	h0 := tr.H0()
	tr.AbsorbKEM(kemInit, kemReply)
	h1 := tr.H1()

	want := sha3.New256()
	_, _ = want.Write(h0[:])
	_, _ = want.Write(kemInit)
	_, _ = want.Write(kemReply)
	var expected [TranscriptLen]byte
	want.Sum(expected[:0])

	if h1 != expected {
		t.Fatalf("H_1 mismatch\n want: %s\n got:  %s",
			hex.EncodeToString(expected[:]), hex.EncodeToString(h1[:]))
	}
}

// TestTranscriptSchemeStrip verifies the scheme-strip defence:
// a single tampered byte in offered_schemes must produce a different
// H_2 from the legitimate transcript. This is the property that
// makes AUTH verify fail on wire tampering.
func TestTranscriptSchemeStrip(t *testing.T) {
	hello := []byte("body")
	init := []byte("init")
	reply := []byte("reply")
	pkI := make([]byte, MLDSA65PubLen)
	pkR := make([]byte, MLDSA65PubLen)
	for i := range pkR {
		pkR[i] = 0xAA
	}

	legit := NewTranscript(SuiteX25519MLKEM)
	legit.AbsorbHello(hello)
	legit.AbsorbKEM(init, reply)
	h2a := legit.FinishFull(pkI, pkR, []SuiteID{SuiteX25519MLKEM})

	tampered := NewTranscript(SuiteX25519MLKEM)
	tampered.AbsorbHello(hello)
	tampered.AbsorbKEM(init, reply)
	// attacker strips PQ and offers a phantom classical suite 0xFE
	h2b := tampered.FinishFull(pkI, pkR, []SuiteID{0xFE})

	if h2a == h2b {
		t.Fatal("H_2 must differ when offered_schemes differs (scheme strip undetectable)")
	}
}

// TestTranscriptStaticHandshakeKAT verifies §7's three-step chain
// against an independently-computed expected H_2 over fixed inputs.
// Two parallel paths (Transcript chain vs three direct SHA3 calls)
// must agree byte-for-byte; any divergence indicates a bug in the
// chain or its description in the spec.
func TestTranscriptStaticHandshakeKAT(t *testing.T) {
	suite := SuiteX25519MLKEM
	hello := bytesPattern(0xA0, 100)
	init := bytesPattern(0xB0, 1216)
	reply := bytesPattern(0xC0, 1184+1088+1952)
	pkI := bytesPattern(0xD0, MLDSA65PubLen)
	pkR := bytesPattern(0xE0, MLDSA65PubLen)
	schemes := []SuiteID{SuiteX25519MLKEM}

	// Path A: Transcript chain.
	tr := NewTranscript(suite)
	tr.AbsorbHello(hello)
	tr.AbsorbKEM(init, reply)
	gotH2 := tr.FinishFull(pkI, pkR, schemes)

	// Path B: hand-computed via three SHA3-256 calls.
	h := sha3.New256()
	_, _ = h.Write(LblProtocol)
	_, _ = h.Write([]byte{0x00, byte(suite)})
	_, _ = h.Write(hello)
	var h0 [TranscriptLen]byte
	h.Sum(h0[:0])

	h.Reset()
	_, _ = h.Write(h0[:])
	_, _ = h.Write(init)
	_, _ = h.Write(reply)
	var h1 [TranscriptLen]byte
	h.Sum(h1[:0])

	h.Reset()
	_, _ = h.Write(h1[:])
	_, _ = h.Write(pkI)
	_, _ = h.Write(pkR)
	// schemes re-encoded as u32 len ∥ bytes.
	_, _ = h.Write([]byte{0x00, 0x00, 0x00, 0x01, byte(SuiteX25519MLKEM)})
	var wantH2 [TranscriptLen]byte
	h.Sum(wantH2[:0])

	if gotH2 != wantH2 {
		t.Fatalf("H_2 chain != hand-computed\n chain: %s\n hand:  %s",
			hex.EncodeToString(gotH2[:]), hex.EncodeToString(wantH2[:]))
	}
}

// bytesPattern returns a deterministic byte slice of length n filled
// with (base + i) mod 256. Used for KAT fixtures.
func bytesPattern(base byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = base + byte(i)
	}
	return out
}
