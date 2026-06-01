// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestResponderRejectsBadMagic feeds 4 garbage bytes; Responder.Run
// MUST return ErrMagicMismatch without consuming further bytes.
func TestResponderRejectsBadMagic(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	serverID, _ := GenerateIdentity()

	go func() {
		_, _ = clientConn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	}()
	rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
	_, err := rs.Run(serverConn)
	if !errors.Is(err, ErrMagicMismatch) {
		t.Fatalf("expected ErrMagicMismatch, got %v", err)
	}
}

// TestResponderRejectsUnknownSuite hand-builds a HELLO with
// ciphersuite=0xFE (reserved-range) and verifies the responder
// answers ErrUnsupportedSuite.
func TestResponderRejectsUnknownSuite(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	hello := &HelloFrame{
		Suite:             0xFE,
		PQMode:            PQModePQOnly,
		ClientRandom:      bytesToArr16(bytesPattern(0x01, ClientRandLen)),
		TimestampNS:       nowNS(),
		ClientID:          clientID.ID(),
		OfferedSchemes:    []SuiteID{0xFE},
		StaticPKInitiator: clientID.PublicBytes(),
	}
	body, err := hello.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	go func() {
		_, _ = clientConn.Write(Magic[:])
		_, _ = clientConn.Write(encodeOuter(FrameHello, body))
		// Read the ALERT back (or any response) so the server can finish.
		_, _ = io.ReadAll(clientConn)
	}()

	rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
	_, err = rs.Run(serverConn)
	if !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("expected ErrUnsupportedSuite, got %v", err)
	}
}

// TestResponderRejectsClientIDBindingMismatch covers §6.1 / §10.1:
// a HELLO whose client_id != SHA3-256(static_pk_initiator) is a UKS
// attempt — refuse with ErrAuthFailed.
func TestResponderRejectsClientIDBindingMismatch(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	hello := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		PQMode:            PQModePQOnly,
		ClientRandom:      bytesToArr16(bytesPattern(0x02, ClientRandLen)),
		TimestampNS:       nowNS(),
		ClientID:          bytesToArr32(bytesPattern(0xFF, IDLen)), // garbage
		OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
		StaticPKInitiator: clientID.PublicBytes(),
	}
	body, _ := hello.Encode()

	go func() {
		_, _ = clientConn.Write(Magic[:])
		_, _ = clientConn.Write(encodeOuter(FrameHello, body))
		_, _ = io.ReadAll(clientConn)
	}()

	rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
	_, err := rs.Run(serverConn)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed for client_id binding, got %v", err)
	}
}

// TestResponderRejectsWrongAuthRole: server sends AUTH(R), initiator
// signs and emits AUTH but with Role=R instead of Role=I. Responder
// must refuse with ErrAuthFailed.
func TestResponderRejectsWrongAuthRole(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		_, serverErr = rs.Run(serverConn)
	}()

	// Run the initiator up to the point where it would normally
	// sign AUTH(I); inject a tampered AUTH frame instead. Easiest:
	// run a normal Initiator inside a wrapping conn that swaps the
	// AUTH role byte on egress.
	swap := &roleSwapConn{Conn: clientConn}
	init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
	_, _ = init.Run(swap)
	wg.Wait()

	if !errors.Is(serverErr, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed for wrong-role AUTH, got %v", serverErr)
	}
}

// TestOversizeFrameRejected: an incoming envelope whose length field
// exceeds MaxFrameBody must be rejected by readFrame without
// allocating the body.
func TestOversizeFrameRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(FrameData))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(MaxFrameBody+1))
	buf.Write(lp[:])
	// No body bytes — readFrame should bail on the length check.

	_, _, err := readFrame(&buf)
	if err == nil {
		t.Fatal("oversize frame accepted")
	}
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
}

// TestAlertMidHandshakePropagated covers §6.7: when the server sends
// an ALERT mid-handshake, the initiator's Run returns the typed
// sentinel rather than a raw IO error.
func TestAlertMidHandshakePropagated(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	clientID, _ := GenerateIdentity()

	go func() {
		// Drain magic + first frame, then write ALERT 0x0B.
		var magic [MagicLen]byte
		_, _ = io.ReadFull(serverConn, magic[:])
		_, _, _ = readFrame(serverConn) // HELLO
		a := &AlertFrame{Code: AlertPolicyRefused, Detail: []byte("test")}
		_ = writeFrame(serverConn, FrameAlert, a.Encode())
		_ = serverConn.Close()
	}()

	init := &Initiator{Local: clientID, Profile: ProfilePermissive}
	_, err := init.Run(clientConn)
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("expected ErrPolicyRefused via ALERT, got %v", err)
	}
}

// TestEpochExhaustionRejected forces the local epoch to 0xFF and
// asserts the next Rekey returns ErrEpochExhausted instead of
// wrapping.
func TestEpochExhaustionRejected(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	client.sendMu.Lock()
	client.sendEpoch = 0xFF
	client.sendMu.Unlock()

	if err := client.Rekey(); !errors.Is(err, ErrEpochExhausted) {
		t.Fatalf("expected ErrEpochExhausted at epoch 0xFF, got %v", err)
	}
}

// ---------- helpers ----------

// roleSwapConn wraps net.Conn so any AUTH frame written through it
// has its inner role byte flipped from RoleInitiator → RoleResponder.
//
// writeFrame emits header + body as a single Write call (one Write
// per frame). The swap is applied in-place to that buffer: if the
// first byte is FrameAuth (0x04) and the buffer is at least 6 bytes
// (header + role byte), overwrite the role byte at offset 5.
type roleSwapConn struct {
	net.Conn
}

func (c *roleSwapConn) Write(p []byte) (int, error) {
	if len(p) >= 6 && FrameType(p[0]) == FrameAuth {
		out := append([]byte(nil), p...)
		out[5] = byte(RoleResponder)
		return c.Conn.Write(out)
	}
	return c.Conn.Write(p)
}

// nowNS returns the current unix nanoseconds as a uint64.
func nowNS() uint64 { return uint64(time.Now().UnixNano()) }
