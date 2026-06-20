// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/sha3"
)

// Transcript chains SHA3-256 over every handshake byte (§7).
//
// The state machine:
//
//	NewTranscript(suite)
//	AbsorbHello(helloBody)         -> commits H_0
//	AbsorbKEM(initBody, replyBody) -> commits H_1
//	FinishFull(pkI, pkR, schemes)  -> returns H_2          (full handshake)
//	  -- OR --
//	FinishPSK(serverEphX25519Pub)  -> returns H_2_psk      (resumed handshake)
//
// Each step replaces the internal SHA3-256 state with the digest of
// the previous chain ∥ new material. This matches the spec's
// definition of H_n as `SHA3-256(H_{n-1} ∥ <new bytes>)`.
//
// The encoded body of each frame is whatever is between the outer
// type/length fields — i.e. the slice the codec returns / consumes.
// Callers MUST feed exactly those bytes (not the outer envelope) so
// both sides agree on the transcript without re-running the codec.
type Transcript struct {
	state [TranscriptLen]byte
	suite SuiteID
	stage transcriptStage
	h     hash.Hash // reused SHA3-256 instance
}

type transcriptStage uint8

const (
	stageNew transcriptStage = iota // before AbsorbHello
	stageH0                         // after AbsorbHello
	stageH1                         // after AbsorbKEM
	stageH2                         // after FinishFull / FinishPSK
)

// NewTranscript creates a transcript pinned to the supplied suite. The
// suite byte does not enter the state at construction — it enters via
// the H_0 prefix in AbsorbHello so the resulting H_0 already binds it.
func NewTranscript(suite SuiteID) *Transcript {
	return &Transcript{suite: suite, h: sha3.New256()}
}

// AbsorbHello commits H_0 = SHA3-256(LBL_PROTOCOL ∥ 0x00 ∥ suite ∥ hello).
// The hello argument is the wire-encoded HELLO body (everything after
// the outer type ∥ length envelope), per §7.
func (t *Transcript) AbsorbHello(hello []byte) {
	t.h.Reset()
	_, _ = t.h.Write(LblProtocol)
	_, _ = t.h.Write([]byte{0x00})
	_, _ = t.h.Write([]byte{byte(t.suite)})
	_, _ = t.h.Write(hello)
	t.h.Sum(t.state[:0])
	t.stage = stageH0
}

// AbsorbKEM commits H_1 = SHA3-256(H_0 ∥ init ∥ reply).
//
// init = wire-encoded KEM_INIT body, reply = wire-encoded KEM_REPLY
// body. The two are folded in one digest call because the spec
// chains them inside a single SHA3 instance, not as two separate H_n
// steps.
func (t *Transcript) AbsorbKEM(init, reply []byte) {
	t.h.Reset()
	_, _ = t.h.Write(t.state[:])
	_, _ = t.h.Write(init)
	_, _ = t.h.Write(reply)
	t.h.Sum(t.state[:0])
	t.stage = stageH1
}

// FinishFull commits H_2 for the full handshake:
//
//	H_2 = SHA3-256(H_1 ∥ static_pk_I ∥ static_pk_R ∥ offered_schemes_encoded)
//
// offered_schemes_encoded is `u32(len) ∥ bytes(schemes)` — the same
// byte sequence already inside HELLO. It is re-mixed here so that any
// on-the-wire tamper with the scheme list under the magic-prefix layer
// (e.g. a downgrader stripping `0x01`) would compute a different H_2
// than what the signer signed — AUTH then fails, ALERT 0x03 fires.
func (t *Transcript) FinishFull(pkI, pkR []byte, schemes []SuiteID) [TranscriptLen]byte {
	t.h.Reset()
	_, _ = t.h.Write(t.state[:])
	_, _ = t.h.Write(pkI)
	_, _ = t.h.Write(pkR)
	// re-encode schemes identically to §6.1 / §7
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(schemes)))
	_, _ = t.h.Write(lp[:])
	for _, s := range schemes {
		_, _ = t.h.Write([]byte{byte(s)})
	}
	t.h.Sum(t.state[:0])
	t.stage = stageH2
	return t.state
}

// FinishPSK is the §7 resumption transcript:
//
//	H_2_psk = SHA3-256(H_0_psk ∥ x25519_pk_eph_responder)
//
// Where H_0_psk was committed by AbsorbHello over the HELLO_PSK body.
// The resumption path does NOT absorb KEM frames — possession of the
// resumption_psk is the authentication and ML-KEM is skipped.
func (t *Transcript) FinishPSK(serverEphX25519Pub []byte) [TranscriptLen]byte {
	t.h.Reset()
	_, _ = t.h.Write(t.state[:])
	_, _ = t.h.Write(serverEphX25519Pub)
	t.h.Sum(t.state[:0])
	t.stage = stageH2
	return t.state
}

// H0, H1, H2 return the most recently committed digest at each stage.
// They are introspection helpers for tests / KAT vectors; production
// code chains FinishFull or FinishPSK directly into the KDF.
func (t *Transcript) H0() [TranscriptLen]byte {
	if t.stage < stageH0 {
		return [TranscriptLen]byte{}
	}
	if t.stage == stageH0 {
		return t.state
	}
	// past H_0 — we no longer hold it. Tests should snapshot in stage.
	return [TranscriptLen]byte{}
}

func (t *Transcript) H1() [TranscriptLen]byte {
	if t.stage == stageH1 {
		return t.state
	}
	return [TranscriptLen]byte{}
}

func (t *Transcript) H2() [TranscriptLen]byte {
	if t.stage == stageH2 {
		return t.state
	}
	return [TranscriptLen]byte{}
}
