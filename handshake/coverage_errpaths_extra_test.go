// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// More targeted coverage of Initiator / Responder error paths.

package handshake

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// TestCoverage_InitiatorReceivesAlertAfterKEMInit: server sends an
// ALERT instead of KEM_REPLY after the initiator's KEM_INIT. The
// initiator must surface the typed sentinel.
func TestCoverage_InitiatorReceivesAlertAfterKEMInit(t *testing.T) {
	cliConn, srvConn := loopbackPair(t)
	cid, _ := GenerateIdentity()

	go func() {
		// Read magic + HELLO + KEM_INIT, then send ALERT.
		var magic [MagicLen]byte
		_, _ = io.ReadFull(srvConn, magic[:])
		_, _, _ = readFrame(srvConn) // HELLO
		_, _, _ = readFrame(srvConn) // KEM_INIT
		a := &AlertFrame{Code: AlertUnsupportedSuite, Detail: []byte("nope")}
		_ = writeFrame(srvConn, FrameAlert, a.Encode())
		_ = srvConn.Close()
	}()

	init := &Initiator{Local: cid, Profile: ProfilePermissive}
	_, err := init.Run(cliConn)
	if !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("expected ErrUnsupportedSuite via ALERT, got %v", err)
	}
}

// TestCoverage_InitiatorMalformedKEMReply: server sends a frame of
// the right type (KEM_REPLY) but with a bad-length body.
func TestCoverage_InitiatorMalformedKEMReply(t *testing.T) {
	cliConn, srvConn := loopbackPair(t)
	cid, _ := GenerateIdentity()

	go func() {
		var magic [MagicLen]byte
		_, _ = io.ReadFull(srvConn, magic[:])
		_, _, _ = readFrame(srvConn)
		_, _, _ = readFrame(srvConn)
		// KEM_REPLY with body of length 5 (way too short).
		_ = writeFrame(srvConn, FrameKEMReply, []byte{0x01, 0x02, 0x03, 0x04, 0x05})
		_ = srvConn.Close()
	}()

	init := &Initiator{Local: cid, Profile: ProfilePermissive}
	_, err := init.Run(cliConn)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
}

// TestCoverage_ResponderHelloDecodeError: client sends magic +
// FrameHello with truncated body.
func TestCoverage_ResponderHelloDecodeError(t *testing.T) {
	cliConn, srvConn := loopbackPair(t)
	sid, _ := GenerateIdentity()

	go func() {
		_, _ = cliConn.Write(Magic[:])
		// HELLO body is too short; decoder fails.
		_ = writeFrame(cliConn, FrameHello, []byte{0x01, 0x02})
		_, _ = io.ReadAll(cliConn) // drain ALERT before close
	}()

	rs := &Responder{Local: sid, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(srvConn)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
}

// TestCoverage_SessionRecvIOError: the underlying conn returns an
// error mid-DATA; Session.Recv returns that error.
func TestCoverage_SessionRecvIOError(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// Close the server's underlying conn from the client side: this
	// causes the client's next Recv to fail with EOF.
	_ = server.rw.(net.Conn).Close()
	_, err := client.Recv()
	if err == nil {
		t.Fatal("Recv after peer close should error")
	}
}

// TestCoverage_NeedsRekeyByBytes pushes sendBytes past the cap and
// asserts needsRekeyLocked returns true via the bytes-cap branch.
func TestCoverage_NeedsRekeyByBytes(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	client.sendMu.Lock()
	client.sendBytesCap = 8 // tiny
	client.sendMu.Unlock()

	if err := client.Send([]byte("12345678910")); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Drain receiver so REKEY ratchet completes without blocking.
	_, _ = server.Recv()
	if client.Epoch() == 0 {
		t.Fatal("expected auto-rekey from bytes-cap")
	}
}

// TestCoverage_DecodeHelloSuiteNotIncluded drives the §6.1 invariant
// check (HELLO body where suite isn't in offered_schemes).
func TestCoverage_DecodeHelloSuiteNotIncluded(t *testing.T) {
	// Manually construct a HELLO body with suite=0x01 but
	// offered_schemes = [0x02]. DecodeHello must reject.
	hello := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		OfferedSchemes:    []SuiteID{0x02},
		StaticPKInitiator: bytesPattern(0x11, MLDSA65PubLen),
	}
	body, _ := hello.Encode() // Encode allows it; Decode catches it.
	if body == nil {
		// Encode rejected it — that's also fine.
		return
	}
	if _, err := DecodeHello(body); err == nil {
		t.Fatal("Decode should reject when suite not in offered_schemes")
	}
}

// TestCoverage_WriteAlertForNil: writeAlertFor with nil error returns nil.
func TestCoverage_WriteAlertForNil(t *testing.T) {
	var buf bytes.Buffer
	if err := writeAlertFor(&buf, nil); err != nil {
		t.Fatalf("writeAlertFor(nil) = %v, want nil", err)
	}
	if buf.Len() != 0 {
		t.Fatal("nil error should not emit anything")
	}
}
