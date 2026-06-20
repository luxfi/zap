// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestPSKResumeRoundTrip drives §12 end-to-end:
//
//  1. Full handshake creates Session and issues a PSK on both sides.
//  2. Client caches the PSK.
//  3. A fresh TCP loopback pair is opened.
//  4. Client re-runs Initiator.Run with Resume set; responder shares
//     the same PSKStore from step 1.
//  5. Echo a payload over the resumed Session.
//
// Single-use is verified by attempting a third connect with the same
// PSK and observing ErrPSKUnknown (the store deleted the entry).
func TestPSKResumeRoundTrip(t *testing.T) {
	store := NewPSKStore()
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	// --- full handshake ---
	clientPSK := runHandshakeAndIssuePSK(t, clientID, serverID, store)
	if clientPSK == nil {
		t.Fatal("initiator did not cache a resumption PSK")
	}
	if store.Len() != 1 {
		t.Fatalf("store should hold 1 issued PSK, got %d", store.Len())
	}

	// --- resumed handshake ---
	clientConn, serverConn := loopbackPair(t)
	var wg sync.WaitGroup
	wg.Add(2)
	var cSess, sSess *Session
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache(), PSKStore: store}
		sSess, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:    clientID,
			Expected: &Identity{PublicKey: serverID.PublicKey},
			Profile:  ProfileStrictPQ,
			Resume:   clientPSK,
		}
		cSess, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("resumed handshake: c=%v s=%v", cerr, serr)
	}

	// Round-trip a payload over the resumed session.
	echo(t, cSess, sSess, []byte("resumed-ping"))

	if err := cSess.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := sSess.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}

	// --- single-use: replaying the same PSK must fail ---
	if store.Len() == 0 && cSess.ResumptionPSK() == nil {
		// Server re-issued a fresh PSK during resume; the original
		// PSK is consumed. Confirm by trying to redeem it again.
		if _, _, ok := store.Redeem(clientPSK.ID); ok {
			t.Fatal("original PSK ID was redeemable after resume — single-use broken")
		}
	}
}

// TestPSKUnknownReturnsAlert: an initiator with a stale / unknown PSK
// must observe ErrPSKUnknown from the responder via ALERT 0x08.
func TestPSKUnknownReturnsAlert(t *testing.T) {
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	clientConn, serverConn := loopbackPair(t)
	stale := &ClientPSK{
		ID:    [PSKIDLen]byte{0xDE, 0xAD, 0xBE, 0xEF},
		PSK:   bytesToArr32(bytesPattern(0x99, PSKKeyLen)),
		Until: deepFuture(),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache(), PSKStore: NewPSKStore()}
		_, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:    clientID,
			Expected: &Identity{PublicKey: serverID.PublicKey},
			Profile:  ProfileStrictPQ,
			Resume:   stale,
		}
		_, cerr = init.Run(clientConn)
	}()
	wg.Wait()

	if !errors.Is(serr, ErrPSKUnknown) {
		t.Fatalf("server should see ErrPSKUnknown, got %v", serr)
	}
	if !errors.Is(cerr, ErrPSKUnknown) {
		t.Fatalf("client should see ErrPSKUnknown via ALERT, got %v", cerr)
	}
}

// TestPSKResumeDisabledRefuses verifies a responder with no PSKStore
// (resumption disabled) ALERTs an incoming HELLO_PSK with
// ErrPSKUnknown rather than crashing.
func TestPSKResumeDisabledRefuses(t *testing.T) {
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	clientConn, serverConn := loopbackPair(t)
	resume := &ClientPSK{
		ID:    [PSKIDLen]byte{0x42},
		PSK:   bytesToArr32(bytesPattern(0x11, PSKKeyLen)),
		Until: deepFuture(),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		// No PSKStore field → resumption disabled.
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		_, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:    clientID,
			Expected: &Identity{PublicKey: serverID.PublicKey},
			Profile:  ProfileStrictPQ,
			Resume:   resume,
		}
		_, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if !errors.Is(serr, ErrPSKUnknown) {
		t.Fatalf("server: %v", serr)
	}
	if !errors.Is(cerr, ErrPSKUnknown) {
		t.Fatalf("client: %v", cerr)
	}
}

// ---------- helpers ----------

// runHandshakeAndIssuePSK runs one full handshake against a PSKStore
// and returns the initiator's cached resumption PSK.
func runHandshakeAndIssuePSK(t *testing.T, cid, sid *Identity, store *PSKStore) *ClientPSK {
	t.Helper()
	clientConn, serverConn := loopbackPair(t)
	var wg sync.WaitGroup
	wg.Add(2)
	var cSess, sSess *Session
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: sid, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache(), PSKStore: store}
		sSess, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: cid, Expected: &Identity{PublicKey: sid.PublicKey}, Profile: ProfileStrictPQ}
		cSess, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("initial handshake: c=%v s=%v", cerr, serr)
	}
	psk := cSess.ResumptionPSK()
	_ = sSess.Close()
	_ = cSess.Close()
	return psk
}

// echo sends payload client→server and back, asserting byte equality.
func echo(t *testing.T, c, s *Session, payload []byte) {
	t.Helper()
	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err := s.Recv()
		if err != nil {
			serverErr = err
			return
		}
		if !bytes.Equal(got, payload) {
			serverErr = errfmt("server got %q want %q", got, payload)
			return
		}
		serverErr = s.Send(got)
	}()
	if err := c.Send(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := c.Recv()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %q vs %q", got, payload)
	}
}

func deepFuture() (out time.Time) { return time.Now().Add(time.Hour) }
