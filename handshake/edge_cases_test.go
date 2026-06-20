// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// TestSessionEmptyPayload: a zero-length DATA frame should round-trip.
// AES-GCM seals an empty plaintext to a 16-byte tag-only ciphertext,
// AAD still binds direction + length so reflection / tamper still work.
func TestSessionEmptyPayload(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	if err := client.Send(nil); err != nil {
		t.Fatalf("send nil: %v", err)
	}
	got, err := server.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got))
	}
}

// TestSessionSendAfterClose: Send / Recv on a closed Session must
// fail fast with ErrSessionClosed rather than touching the wire.
func TestSessionSendAfterClose(t *testing.T) {
	client, server := pqPair(t)
	server.Close()

	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := client.Send([]byte("x")); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Send after Close returned %v, want ErrSessionClosed", err)
	}
	if _, err := client.Recv(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Recv after Close returned %v, want ErrSessionClosed", err)
	}
}

// TestSessionDoubleClose: Close is idempotent — second invocation
// is a no-op and returns nil.
func TestSessionDoubleClose(t *testing.T) {
	client, server := pqPair(t)
	defer server.Close()

	if err := client.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close should be nil, got %v", err)
	}
}

// TestInitiatorRequiresPrivateKey: an Initiator with a peer-only
// Identity (no private key) must fail Run with a clear error before
// touching the wire.
func TestInitiatorRequiresPrivateKey(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	_ = serverConn

	full, _ := GenerateIdentity()
	peerOnly := &Identity{PublicKey: full.PublicKey}

	init := &Initiator{Local: peerOnly}
	_, err := init.Run(clientConn)
	if err == nil {
		t.Fatal("Initiator.Run accepted Identity with no private key")
	}
}

// TestResponderRequiresPrivateKey: same property for the responder.
func TestResponderRequiresPrivateKey(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	_ = clientConn

	full, _ := GenerateIdentity()
	peerOnly := &Identity{PublicKey: full.PublicKey}

	rs := &Responder{Local: peerOnly}
	_, err := rs.Run(serverConn)
	if err == nil {
		t.Fatal("Responder.Run accepted Identity with no private key")
	}
}

// TestInitiatorDefaultSuite: when Suite is left zero, Initiator must
// pick SuiteX25519MLKEM (the only callable v1 suite) and complete
// the handshake against a default responder.
func TestInitiatorDefaultSuite(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var cSess, sSess *Session
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		sSess, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		// Note: Suite, OfferedSchemes, PQMode all left zero.
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
		cSess, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: c=%v s=%v", cerr, serr)
	}
	_ = cSess.Close()
	_ = sSess.Close()
}

// TestInitiatorRejectsInvalidSuite: Suite explicitly set to a
// reserved byte must fail before writing the magic prefix.
func TestInitiatorRejectsInvalidSuite(t *testing.T) {
	clientConn, _ := loopbackPair(t)
	id, _ := GenerateIdentity()
	init := &Initiator{Local: id, Suite: 0xFE}
	_, err := init.Run(clientConn)
	if !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("expected ErrUnsupportedSuite, got %v", err)
	}
}

// TestNewTranscriptReservedSuite: Transcript accepts any byte value
// since the constructor doesn't gate; the suite enters H_0 directly
// so a reserved suite would simply produce a transcript no one else
// can reproduce — undesirable but not unsafe at the transcript layer.
// We document the property: H_0 differs for different suite bytes.
func TestNewTranscriptReservedSuite(t *testing.T) {
	hello := []byte("h")
	tA := NewTranscript(SuiteX25519MLKEM)
	tA.AbsorbHello(hello)
	tB := NewTranscript(SuiteReservedHi)
	tB.AbsorbHello(hello)
	if tA.H0() == tB.H0() {
		t.Fatal("H_0 must differ across suites")
	}
}

// TestSessionLargePayload sends a payload that is a single frame's
// worth of plaintext (no chunking). Confirms big sizes still round-
// trip through the AEAD path.
func TestSessionLargePayload(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	plain := bytes.Repeat([]byte{0xA5}, 1<<15) // 32 KiB

	done := make(chan error, 1)
	go func() {
		got, err := server.Recv()
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, plain) {
			done <- errfmt("payload mismatch (len=%d)", len(got))
			return
		}
		done <- nil
	}()
	if err := client.Send(plain); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("recv: %v", err)
	}
}

// TestSuiteIDIsValid: the enum guard rejects reserved + unknown IDs
// and admits exactly SuiteX25519MLKEM in v1.
func TestSuiteIDIsValid(t *testing.T) {
	for b := 0; b <= 0xFF; b++ {
		s := SuiteID(b)
		got := s.IsValid()
		want := s == SuiteX25519MLKEM
		if got != want {
			t.Fatalf("SuiteID(0x%02x).IsValid() = %v, want %v", b, got, want)
		}
	}
}

// TestPQModeWireValues verifies the §6.1 wire byte mapping for each
// PQMode value. The byte is set by the initiator and inspected by
// the responder; any drift here breaks downgrade detection.
func TestPQModeWireValues(t *testing.T) {
	cases := []struct {
		m    PQMode
		want byte
	}{
		{PQModeClassicalPermitted, 0x00},
		{PQModePQRequired, 0x01},
		{PQModePQOnly, 0x02},
	}
	for _, c := range cases {
		if byte(c.m) != c.want {
			t.Errorf("PQMode %d encoded as 0x%02x, want 0x%02x", c.m, byte(c.m), c.want)
		}
	}
}

// TestAuthRoleLabel covers §6.4 AuthRole → label mapping.
func TestAuthRoleLabel(t *testing.T) {
	if !bytes.Equal(RoleInitiator.Label(), LblAuthI) {
		t.Fatal("RoleInitiator.Label mismatch")
	}
	if !bytes.Equal(RoleResponder.Label(), LblAuthR) {
		t.Fatal("RoleResponder.Label mismatch")
	}
	if r := AuthRole(0x00); r.Label() != nil {
		t.Fatal("unknown role should return nil label")
	}
}
