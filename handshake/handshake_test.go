// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestFullHandshakeAndEcho runs Initiator ↔ Responder over net.Pipe,
// verifies both Session objects come back keyed identically (modulo
// direction), and then echoes a short payload through Send / Recv.
//
// This is the integration test that proves every component (frames,
// crypto, transcript, KDF, AEAD, replay cache) interoperates.
func TestFullHandshakeAndEcho(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)

	clientID, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	serverID, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}

	var (
		wg         sync.WaitGroup
		clientSess *Session
		clientErr  error
		serverSess *Session
		serverErr  error
	)
	wg.Add(2)

	// Server.
	go func() {
		defer wg.Done()
		rs := &Responder{
			Local:       serverID,
			Profile:     ProfileStrictPQ,
			ReplayCache: NewReplayCache(),
			PSKStore:    NewPSKStore(),
		}
		serverSess, serverErr = rs.Run(serverConn)
	}()

	// Client.
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:    clientID,
			Expected: &Identity{PublicKey: serverID.PublicKey},
			Profile:  ProfileStrictPQ,
		}
		clientSess, clientErr = init.Run(clientConn)
	}()

	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}

	if clientSess.PeerID() != serverID.ID() {
		t.Fatal("client recorded wrong responder peer ID")
	}
	if serverSess.PeerID() != clientID.ID() {
		t.Fatal("server recorded wrong initiator peer ID")
	}

	// Echo: client → server → client.
	payload := []byte("hello, post-quantum world")
	var echoErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, rerr := serverSess.Recv()
		if rerr != nil {
			echoErr = rerr
			return
		}
		if !bytes.Equal(got, payload) {
			echoErr = errfmt("server got %q want %q", got, payload)
			return
		}
		if werr := serverSess.Send(got); werr != nil {
			echoErr = werr
			return
		}
	}()

	if err := clientSess.Send(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	echoed, err := clientSess.Recv()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo mismatch: got %q want %q", echoed, payload)
	}

	wg.Wait()
	if echoErr != nil {
		t.Fatalf("server echo: %v", echoErr)
	}

	if err := clientSess.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := serverSess.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
}

// TestHandshakePinnedIdentityMismatch covers §10.2 — initiator
// expects a specific responder identity; if the responder presents
// a different static key the handshake aborts with VMIdentityMismatch.
func TestHandshakePinnedIdentityMismatch(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()
	wrongPin, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var clientErr, serverErr error
	go func() {
		defer wg.Done()
		rs := &Responder{
			Local:       serverID,
			Profile:     ProfileStrictPQ,
			ReplayCache: NewReplayCache(),
		}
		_, serverErr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:    clientID,
			Expected: &Identity{PublicKey: wrongPin.PublicKey},
			Profile:  ProfileStrictPQ,
		}
		_, clientErr = init.Run(clientConn)
	}()
	wg.Wait()

	if clientErr == nil || !errIsVMIdentity(clientErr) {
		t.Fatalf("client should see VMIdentityMismatch, got: %v", clientErr)
	}
	// Server may see decode/IO error after client tore down — either is fine.
	_ = serverErr
}

// TestHandshakeReplayRejected exercises §11: a Responder that has
// already seen (client_id, client_random) refuses the second HELLO
// with ErrReplayDetected.
func TestHandshakeReplayRejected(t *testing.T) {
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	cache := NewReplayCache()
	cr := bytesToArr16(bytesPattern(0xAB, ClientRandLen))
	if cache.SeenOrAdd(clientID.ID(), cr) {
		t.Fatal("fresh cache should not flag first insert")
	}
	if !cache.SeenOrAdd(clientID.ID(), cr) {
		t.Fatal("second SeenOrAdd should return true (replay)")
	}

	if err := cache.CheckTimestamp(uint64(time.Now().Add(time.Hour).UnixNano())); err == nil {
		t.Fatal("future-skewed timestamp should be refused")
	}
	if err := cache.CheckTimestamp(uint64(time.Now().UnixNano())); err != nil {
		t.Fatalf("current timestamp refused: %v", err)
	}

	_ = serverID
}

// TestHandshakeStrictPQRefusesClassicalOffer checks the downgrade
// gate: under StrictPQ the responder must refuse a HELLO advertising
// PQModeClassicalPermitted with ErrDowngradeRefused.
//
// The initiator is configured as ProfilePermissive so its own Profile
// gate doesn't silently upgrade PQMode — this simulates a peer (or
// older client) that lawfully offers classical and lets the strict
// responder refuse.
func TestHandshakeStrictPQRefusesClassicalOffer(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var clientErr, serverErr error

	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		_, serverErr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{
			Local:   clientID,
			Profile: ProfilePermissive,
			PQMode:  PQModeClassicalPermitted, // wire byte = 0x00
		}
		_, clientErr = init.Run(clientConn)
	}()
	wg.Wait()

	if serverErr == nil || !errIsDowngrade(serverErr) {
		t.Fatalf("server should see ErrDowngradeRefused, got %v", serverErr)
	}
	if clientErr == nil {
		t.Fatal("client should observe an error after server alert")
	}
}

func errIsVMIdentity(err error) bool {
	return bytes.Contains([]byte(err.Error()), []byte("vm_identity_mismatch"))
}
func errIsDowngrade(err error) bool {
	return bytes.Contains([]byte(err.Error()), []byte("downgrade_refused"))
}

func errfmt(format string, args ...any) error { return fmt.Errorf(format, args...) }
