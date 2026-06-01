// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Failure-injection coverage for Initiator.runFull / runResume and
// Responder.runFull / runResume. A staged conn wrapper lets us fail
// the Nth write or stub a specific frame in the read stream, driving
// each error-return branch in the state machines.

package handshake

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nowPlus returns the current time plus d. Helper for ClientPSK.Until.
func nowPlus(d time.Duration) time.Time { return time.Now().Add(d) }

// staged lets a test drive a real loopback conn but intercept its
// Write calls. When `failAfter` writes have been observed, the
// (N+1)th Write returns `failErr` without touching the underlying
// conn. failAfter < 0 disables the gate.
type staged struct {
	net.Conn
	writes    atomic.Int64
	failAfter int64
	failErr   error
}

func (s *staged) Write(p []byte) (int, error) {
	n := s.writes.Add(1)
	if s.failAfter >= 0 && n > s.failAfter {
		return 0, s.failErr
	}
	return s.Conn.Write(p)
}

// TestCoverage_InitiatorWriteFailAtKEMInit fails the second write
// (KEM_INIT) — the magic + HELLO have been emitted, the responder
// will keep reading, and the initiator returns the staged error.
func TestCoverage_InitiatorWriteFailAtKEMInit(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	sid, _ := GenerateIdentity()

	// Start a tolerant responder on the server side; it will fail
	// somewhere (either on truncated read or on AUTH timeout) — we
	// only care about the initiator's error path.
	go func() {
		rs := &Responder{Local: sid, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
		_, _ = rs.Run(srvRaw)
	}()

	staged := &staged{Conn: cliRaw, failAfter: 1 /* magic ok, HELLO ok, fail at KEM_INIT (write #3 in spec but failAfter=2) */, failErr: errors.New("injected KEM_INIT")}
	staged.failAfter = 2 // magic + HELLO succeed; KEM_INIT fails
	init := &Initiator{Local: cid, Expected: &Identity{PublicKey: sid.PublicKey}, Profile: ProfilePermissive}
	_, err := init.Run(staged)
	if err == nil {
		t.Fatal("expected staged-write error")
	}
}

// TestCoverage_InitiatorReadKEMReplyEOF: server closes the conn
// after receiving KEM_INIT, so the initiator's expectFrame for
// KEM_REPLY returns EOF.
func TestCoverage_InitiatorReadKEMReplyEOF(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()

	go func() {
		// Drain magic + HELLO + KEM_INIT, then close.
		var magic [MagicLen]byte
		_, _ = io.ReadFull(srvRaw, magic[:])
		_, _, _ = readFrame(srvRaw)
		_, _, _ = readFrame(srvRaw)
		_ = srvRaw.Close()
	}()

	init := &Initiator{Local: cid, Profile: ProfilePermissive}
	_, err := init.Run(cliRaw)
	if err == nil {
		t.Fatal("expected EOF on KEM_REPLY")
	}
}

// TestCoverage_InitiatorReadAuthRWrongType: server replies with a
// valid KEM_REPLY but follows up with a non-AUTH frame.
func TestCoverage_InitiatorReadAuthRWrongType(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	sid, _ := GenerateIdentity()

	go func() {
		var magic [MagicLen]byte
		_, _ = io.ReadFull(srvRaw, magic[:])
		_, _, _ = readFrame(srvRaw) // HELLO
		_, _, _ = readFrame(srvRaw) // KEM_INIT
		// Send a fake KEM_REPLY with the right shape.
		reply := &KEMReplyFrame{StaticPKResponder: sid.PublicBytes()}
		body, _ := reply.Encode()
		_ = writeFrame(srvRaw, FrameKEMReply, body)
		// Then send a REKEY frame instead of AUTH.
		_ = writeFrame(srvRaw, FrameRekey, []byte{RekeyReasonExplicit})
		_ = srvRaw.Close()
	}()

	init := &Initiator{Local: cid, Profile: ProfilePermissive}
	_, err := init.Run(cliRaw)
	if err == nil {
		t.Fatal("expected error on non-AUTH after KEM_REPLY")
	}
}

// TestCoverage_ResponderReadKEMInitEOF: client emits magic + HELLO,
// then closes; responder's KEM_INIT read returns EOF.
func TestCoverage_ResponderReadKEMInitEOF(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	sid, _ := GenerateIdentity()

	go func() {
		cid, _ := GenerateIdentity()
		_, _ = cliRaw.Write(Magic[:])
		hello := &HelloFrame{
			Suite:             SuiteX25519MLKEM,
			PQMode:            PQModePQOnly,
			OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
			StaticPKInitiator: cid.PublicBytes(),
			ClientID:          cid.ID(),
			TimestampNS:       nowNS(),
		}
		body, _ := hello.Encode()
		_ = writeFrame(cliRaw, FrameHello, body)
		_ = cliRaw.Close()
	}()

	rs := &Responder{Local: sid, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(srvRaw)
	if err == nil {
		t.Fatal("expected EOF on KEM_INIT")
	}
}

// TestCoverage_ResponderReadAuthIEOF: client gets through HELLO,
// KEM_INIT, reads KEM_REPLY+AUTH(R), then closes without sending
// AUTH(I).
func TestCoverage_ResponderReadAuthIEOF(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	sid, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rs := &Responder{Local: sid, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		_, _ = rs.Run(srvRaw) // we expect this to fail
	}()

	// Drive the initiator manually up to AUTH(R), then close without sending AUTH(I).
	init := &Initiator{Local: cid, Expected: &Identity{PublicKey: sid.PublicKey}, Profile: ProfileStrictPQ}
	staged := &staged{Conn: cliRaw, failAfter: 3 /* magic, HELLO, KEM_INIT ok; fail at AUTH(I) */, failErr: errors.New("close before AUTH(I)")}
	_, _ = init.Run(staged)
	_ = cliRaw.Close()
	wg.Wait()
}

// TestCoverage_InitiatorBadResponderID: server presents a static_pk
// that doesn't match the pinned Expected identity.
func TestCoverage_InitiatorBadResponderID(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	sid, _ := GenerateIdentity()
	other, _ := GenerateIdentity()

	go func() {
		rs := &Responder{Local: sid, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
		_, _ = rs.Run(srvRaw)
	}()

	init := &Initiator{Local: cid, Expected: &Identity{PublicKey: other.PublicKey}, Profile: ProfilePermissive}
	_, err := init.Run(cliRaw)
	if !errors.Is(err, ErrVMIdentityMismatch) {
		t.Fatalf("expected ErrVMIdentityMismatch, got %v", err)
	}
}

// TestCoverage_InitiatorResumeWriteFailAtHelloPSK: with a Resume PSK
// set, fail the second write (HELLO_PSK after magic).
func TestCoverage_InitiatorResumeWriteFailAtHelloPSK(t *testing.T) {
	cliRaw, _ := loopbackPair(t)
	cid, _ := GenerateIdentity()
	psk := &ClientPSK{ID: [PSKIDLen]byte{1}, PSK: bytesToArr32(bytesPattern(0xAA, PSKKeyLen)), Until: nowPlus(time.Hour)}

	staged := &staged{Conn: cliRaw, failAfter: 0 /* magic OK; HELLO_PSK fails */, failErr: errors.New("inject")}
	staged.failAfter = 1

	init := &Initiator{Local: cid, Profile: ProfilePermissive, Resume: psk}
	_, err := init.Run(staged)
	if err == nil {
		t.Fatal("expected staged-write error in resume path")
	}
}

// TestCoverage_InitiatorResumeReadEOF: with a Resume PSK, server
// closes after reading HELLO_PSK so the resume reply read fails.
func TestCoverage_InitiatorResumeReadEOF(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	psk := &ClientPSK{ID: [PSKIDLen]byte{1}, PSK: bytesToArr32(bytesPattern(0xBB, PSKKeyLen)), Until: nowPlus(time.Hour)}

	go func() {
		var magic [MagicLen]byte
		_, _ = io.ReadFull(srvRaw, magic[:])
		_, _, _ = readFrame(srvRaw) // HELLO_PSK
		_ = srvRaw.Close()
	}()

	init := &Initiator{Local: cid, Profile: ProfilePermissive, Resume: psk}
	_, err := init.Run(cliRaw)
	if err == nil {
		t.Fatal("expected resume-reply EOF")
	}
}

// TestCoverage_ResponderResumeFlowWithFreshStore: drive runResume
// with a fresh PSKStore that has the PSK pre-issued, exercising the
// happy path in responder.runResume that's underrepresented today.
func TestCoverage_ResponderResumeFlowWithFreshStore(t *testing.T) {
	cliRaw, srvRaw := loopbackPair(t)
	cid, _ := GenerateIdentity()
	sid, _ := GenerateIdentity()
	store := NewPSKStore()

	// Full handshake to issue a PSK on the store.
	psk := runHandshakeAndIssuePSK(t, cid, sid, store)
	if psk == nil {
		t.Fatal("first handshake produced no PSK")
	}

	// New conns for the resumed handshake.
	cliRaw2, srvRaw2 := loopbackPair(t)
	_ = cliRaw
	_ = srvRaw

	var wg sync.WaitGroup
	wg.Add(2)
	var cErr, sErr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: sid, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache(), PSKStore: store}
		_, sErr = rs.Run(srvRaw2)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: cid, Expected: &Identity{PublicKey: sid.PublicKey}, Profile: ProfileStrictPQ, Resume: psk}
		_, cErr = init.Run(cliRaw2)
	}()
	wg.Wait()
	if cErr != nil || sErr != nil {
		t.Fatalf("resumed handshake: c=%v s=%v", cErr, sErr)
	}
}
