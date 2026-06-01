// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"sync"
	"testing"
)

// TestSessionCloseZeroesKeys verifies §10.4 best-effort zeroisation
// of the per-direction AEAD keys when a Session is closed. We snap
// the keys before Close, observe non-zero, then assert post-Close
// returns the zeroed state.
//
// This does NOT guarantee the bytes are zeroed everywhere in the
// process memory — a runtime-copied slice header may still hold
// stale bytes — but it does guarantee the Session's own state is
// scrubbed, which is the structural property the spec requires.
func TestSessionCloseZeroesKeys(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var clientSess, serverSess *Session
	var cerr, serr error

	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		serverSess, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
		clientSess, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: c=%v s=%v", cerr, serr)
	}

	// Pre-close keys are non-zero (high probability — random derivation).
	beforeSend := clientSess.sendKey
	beforeRecv := clientSess.recvKey
	if beforeSend == [AEADKeyLen]byte{} || beforeRecv == [AEADKeyLen]byte{} {
		t.Fatal("client keys unexpectedly all-zero pre-close")
	}

	if err := clientSess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if clientSess.sendKey != [AEADKeyLen]byte{} {
		t.Fatal("sendKey not zeroed on close")
	}
	if clientSess.recvKey != [AEADKeyLen]byte{} {
		t.Fatal("recvKey not zeroed on close")
	}
	if clientSess.sendSalt != [NonceSaltLen]byte{} {
		t.Fatal("sendSalt not zeroed on close")
	}
	if clientSess.recvSalt != [NonceSaltLen]byte{} {
		t.Fatal("recvSalt not zeroed on close")
	}

	_ = serverSess.Close()
}

// TestSessionKeysZeroize covers the standalone helper used by
// DeriveSession's caller.
func TestSessionKeysZeroize(t *testing.T) {
	k := SessionKeys{}
	for i := range k.KInitToResp {
		k.KInitToResp[i] = byte(i + 1)
	}
	for i := range k.ResumptionPSK {
		k.ResumptionPSK[i] = byte(i + 1)
	}
	k.Zeroize()
	if k.KInitToResp != [AEADKeyLen]byte{} {
		t.Fatal("KInitToResp not zeroed")
	}
	if k.ResumptionPSK != [PSKKeyLen]byte{} {
		t.Fatal("ResumptionPSK not zeroed")
	}
}
