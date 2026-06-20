// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"sync"
	"testing"
)

// TestSessionRekeyRoundTrip drives a manual rekey on the sender and
// confirms the receiver tracks the epoch transition transparently.
func TestSessionRekeyRoundTrip(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var clientSess, serverSess *Session
	var clientErr, serverErr error

	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		serverSess, serverErr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
		clientSess, clientErr = init.Run(clientConn)
	}()
	wg.Wait()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", clientErr, serverErr)
	}

	// Round 1 — baseline payload before any rekey.
	round := func(plain []byte, expectClientEpoch uint8) {
		t.Helper()
		var rerr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := serverSess.Recv()
			if err != nil {
				rerr = err
				return
			}
			if !bytes.Equal(got, plain) {
				rerr = errfmt("server got %q want %q", got, plain)
				return
			}
			rerr = serverSess.Send(got)
		}()
		if err := clientSess.Send(plain); err != nil {
			t.Fatalf("client send: %v", err)
		}
		echoed, err := clientSess.Recv()
		if err != nil {
			t.Fatalf("client recv: %v", err)
		}
		wg.Wait()
		if rerr != nil {
			t.Fatalf("server echo: %v", rerr)
		}
		if !bytes.Equal(echoed, plain) {
			t.Fatalf("echo mismatch")
		}
		if clientSess.Epoch() != expectClientEpoch {
			t.Fatalf("client epoch %d, want %d", clientSess.Epoch(), expectClientEpoch)
		}
	}

	round([]byte("ping"), 0)

	// Trigger explicit rekey on the client.
	if err := clientSess.Rekey(); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	round([]byte("ping-2"), 1)

	// And again — confirm the ratchet advances repeatedly.
	if err := clientSess.Rekey(); err != nil {
		t.Fatalf("rekey 2: %v", err)
	}
	round([]byte("ping-3"), 2)

	_ = clientSess.Close()
	_ = serverSess.Close()
}
