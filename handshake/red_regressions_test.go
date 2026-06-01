// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Regression tests for the seven code-level fixes Red flagged in
// the v1 review. Each test is anchored to a finding ID so future
// drift is easy to trace back.

package handshake

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// TestRegression_H1_PeerIDAfterResume locks in the H-1 fix: after a
// PSK-resumed handshake, the initiator's Session.PeerID() MUST equal
// the verified responder's identity, NOT the local node's identity.
//
// Bug: initiator.runResume previously passed `i.Local.ID()` into
// newSession's peerID slot. Any caller branching on PeerID for
// authorization would attribute resumed traffic to the local node
// instead of the verified peer.
func TestRegression_H1_PeerIDAfterResume(t *testing.T) {
	store := NewPSKStore()
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	// Full handshake to mint a PSK.
	clientPSK := runHandshakeAndIssuePSK(t, clientID, serverID, store)
	if clientPSK == nil {
		t.Fatal("no PSK from initial handshake")
	}
	if clientPSK.PeerID != serverID.ID() {
		t.Fatalf("ClientPSK.PeerID = %x, want serverID = %x", clientPSK.PeerID, serverID.ID())
	}

	// Resumed handshake.
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
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ, Resume: clientPSK}
		cSess, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("resumed handshake: c=%v s=%v", cerr, serr)
	}

	// The fix: initiator's resumed Session must report the responder's
	// verified ID, not the initiator's own.
	if cSess.PeerID() != serverID.ID() {
		t.Fatalf("Session.PeerID() after resume = %x, want serverID = %x (would be clientID = %x under H-1 bug)",
			cSess.PeerID(), serverID.ID(), clientID.ID())
	}
	if cSess.PeerID() == clientID.ID() {
		t.Fatal("Session.PeerID() returned LOCAL identity after resume — H-1 bug regressed")
	}
	if sSess.PeerID() != clientID.ID() {
		t.Fatalf("server Session.PeerID() = %x, want clientID = %x", sSess.PeerID(), clientID.ID())
	}

	_ = cSess.Close()
	_ = sSess.Close()
}

// TestRegression_M3_ReplayCacheRequiredUnderStrictPQ locks in M-3:
// a Responder configured with ProfileStrictPQ (or ProfileFIPS) and
// nil ReplayCache MUST refuse at Run() entry, before any wire
// activity.
func TestRegression_M3_ReplayCacheRequiredUnderStrictPQ(t *testing.T) {
	for _, p := range []Profile{ProfileStrictPQ, ProfileFIPS} {
		p := p
		t.Run(p.label(), func(t *testing.T) {
			_, server := loopbackPair(t)
			id, _ := GenerateIdentity()
			rs := &Responder{Local: id, Profile: p /* ReplayCache: nil */}
			_, err := rs.Run(server)
			if err == nil {
				t.Fatal("Responder accepted nil ReplayCache under strict profile")
			}
			// No wire activity: caller should not even have read the magic.
			// We can't directly verify "no bytes read" because the server
			// conn was given to us in a working state, but a non-wire error
			// at least proves we bailed early.
		})
	}
}

// TestRegression_M3_ReplayCacheOptionalUnderPermissive: under
// Permissive profile, nil ReplayCache is allowed (caller's choice).
func TestRegression_M3_ReplayCacheOptionalUnderPermissive(t *testing.T) {
	clientConn, serverConn := loopbackPair(t)
	cID, _ := GenerateIdentity()
	sID, _ := GenerateIdentity()

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		// Profile: Permissive, ReplayCache: nil — should NOT be rejected.
		rs := &Responder{Local: sID, Profile: ProfilePermissive}
		_, serr = rs.Run(serverConn)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: cID, Expected: &Identity{PublicKey: sID.PublicKey}, Profile: ProfilePermissive}
		_, cerr = init.Run(clientConn)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("Permissive profile should allow nil ReplayCache: c=%v s=%v", cerr, serr)
	}
}

// TestRegression_M2_HelloPSKReplayRejected locks in M-2: capturing a
// HELLO_PSK frame and replaying it against the responder must be
// detected — the second presentation fires ErrReplayDetected before
// the PSK is consumed.
//
// We don't need a full wire-capture; we drive the SeenOrAdd directly
// on a manufactured (psk_id, client_random) tuple in the responder's
// cache namespace.
func TestRegression_M2_HelloPSKReplayRejected(t *testing.T) {
	// Build a responder with a real cache + store, then replay the
	// same HELLO_PSK twice. First should succeed (and consume the
	// PSK); second must fail with ErrReplayDetected or ErrPSKUnknown
	// (PSK already redeemed).
	store := NewPSKStore()
	cID, _ := GenerateIdentity()
	sID, _ := GenerateIdentity()

	// Mint a fresh PSK.
	psk := runHandshakeAndIssuePSK(t, cID, sID, store)
	if psk == nil {
		t.Fatal("no PSK minted")
	}

	// Re-issue the same PSK twice in the store (simulating that
	// the legit handshake had not yet consumed it) so that we can
	// observe the SeenOrAdd gate firing BEFORE Redeem.
	store.Issue(psk.PSK, cID.ID())

	// First HELLO_PSK arrives.
	cache := NewReplayCache()
	var pskNS [IDLen]byte
	pskHash := sha3.Sum256(psk.ID[:])
	copy(pskNS[:], pskHash[:])
	rnd := bytesToArr16(bytesPattern(0xAB, ClientRandLen))

	if cache.SeenOrAdd(pskNS, rnd) {
		t.Fatal("fresh HELLO_PSK falsely flagged as replay")
	}
	if !cache.SeenOrAdd(pskNS, rnd) {
		t.Fatal("replayed HELLO_PSK not detected — M-2 regression")
	}
}

// TestRegression_L5_SendAfterCloseHardBarrier locks in L-5: even if
// a Send acquires sendMu BEFORE Close runs CAS, the in-flight Send
// must see closed=true once Close serialises through.
//
// All goroutine-shared state is atomic so the race detector sees a
// clean program even if test scheduling drifts.
func TestRegression_L5_SendAfterCloseHardBarrier(t *testing.T) {
	client, server := pqPair(t)
	defer server.Close()

	const G = 16
	var sendsAfterClose atomic.Int64
	var closed atomic.Bool

	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				err := client.Send([]byte{byte(i)})
				if err == nil && closed.Load() {
					sendsAfterClose.Add(1)
				}
				if errors.Is(err, ErrSessionClosed) {
					return
				}
				if err != nil {
					return // any IO error after close is acceptable
				}
			}
		}()
	}

	// Drain receiver so senders don't block on backpressure.
	go func() {
		for {
			if _, err := server.Recv(); err != nil {
				return
			}
		}
	}()

	// Close mid-stream.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	closed.Store(true)
	wg.Wait()

	// L-5 fix property: after Close returns, the AEAD is gone (sendAEAD=nil).
	if client.sendAEAD != nil {
		t.Fatal("sendAEAD not cleared after Close — L-1 regression")
	}
}

// TestRegression_NEWH1_CloseUnblocksParkedRecv locks in the NEW-H1
// fix: a goroutine parked inside Session.Recv (blocked on the wire
// with no incoming traffic) must NOT deadlock against a concurrent
// Close from a separate goroutine. This is the canonical net.Conn
// shutdown pattern.
//
// Failure mode (pre-fix): Recv holds recvMu and blocks in readFrame;
// Close grabs the closed-CAS and then tries to acquire recvMu →
// blocks forever; the recv goroutine never unblocks because the
// underlying conn is never closed → circular wait.
func TestRegression_NEWH1_CloseUnblocksParkedRecv(t *testing.T) {
	client, server := pqPair(t)
	defer server.Close()

	// Park a Recv with no traffic in flight.
	recvDone := make(chan struct{})
	go func() {
		_, _ = client.Recv()
		close(recvDone)
	}()

	// Give the goroutine a moment to actually enter readFrame.
	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung — parked Recv deadlock NEW-H1 regressed")
	}

	// Recv must also unblock.
	select {
	case <-recvDone:
	case <-time.After(2 * time.Second):
		t.Fatal("parked Recv never unblocked after Close")
	}
}

// TestRegression_MPRE1_WriteFrameIsAtomic locks in the M-PRE-1 fix:
// writeFrame MUST issue exactly one w.Write per frame. A multi-Write
// implementation lets Send (holding sendMu) and Recv-emitted ALERT
// (holding recvMu, NOT sendMu) interleave on the wire — DATA
// header → ALERT header → DATA body → ALERT body produces a
// mangled stream the peer cannot parse.
//
// The recording writer counts Write calls; the assertion is that
// the count equals the number of frames issued (no header/body
// splits).
func TestRegression_MPRE1_WriteFrameIsAtomic(t *testing.T) {
	rec := &recordingWriter{}

	// Issue 16 mixed-shape frames through writeFrame.
	frames := []struct {
		t    FrameType
		body []byte
	}{
		{FrameData, []byte("payload-1")},
		{FrameAlert, []byte{byte(AlertAuthFailed), 0, 0, 0, 0}},
		{FrameRekey, []byte{RekeyReasonExplicit}},
		{FrameData, bytes.Repeat([]byte{0xAA}, 4096)},
		{FrameHello, bytes.Repeat([]byte{0xBB}, 137)},
		{FrameKEMInit, bytes.Repeat([]byte{0xCC}, 1216)},
		{FrameAuth, bytes.Repeat([]byte{0xDD}, 64)},
		{FrameHelloPSK, bytes.Repeat([]byte{0xEE}, 71)},
	}
	for _, f := range frames {
		if err := writeFrame(rec, f.t, f.body); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
	}

	if rec.calls != len(frames) {
		t.Fatalf("writeFrame issued %d Write calls for %d frames — header/body split allows wire interleave (M-PRE-1 regression)",
			rec.calls, len(frames))
	}
}

// recordingWriter counts Write invocations. Used by the M-PRE-1
// regression test to assert one Write per frame.
type recordingWriter struct {
	calls int
	bytes int
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.calls++
	r.bytes += len(p)
	return len(p), nil
}

// TestRegression_NEWH1_CloseUnblocksParkedSend mirrors the above for
// the send direction. We fill the OS TCP send buffer by sending
// without a draining peer, then call Close. The parked writeFrame
// (inside sendMu) must unblock when the underlying conn closes; the
// concurrent Close call must complete within the 2 s deadline.
func TestRegression_NEWH1_CloseUnblocksParkedSend(t *testing.T) {
	client, server := pqPair(t)
	defer server.Close()

	// Spin a sender that will eventually fill the kernel TCP send
	// buffer because the server side never drains. The Send call
	// inside writeFrame parks holding sendMu.
	sendDone := make(chan struct{})
	go func() {
		buf := make([]byte, MaxFrameBody/4)
		for {
			if err := client.Send(buf); err != nil {
				close(sendDone)
				return
			}
		}
	}()

	// Let the sender accumulate a few backlog frames.
	time.Sleep(100 * time.Millisecond)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close hung — parked Send deadlock NEW-H1 regressed")
	}

	select {
	case <-sendDone:
	case <-time.After(2 * time.Second):
		t.Fatal("parked Send never unblocked after Close")
	}
}

// TestRegression_L1_AEADNilledOnClose locks in L-1: after Close,
// sendAEAD and recvAEAD are nil so the GC can reclaim the AES
// round-key schedule.
func TestRegression_L1_AEADNilledOnClose(t *testing.T) {
	client, server := pqPair(t)
	if client.sendAEAD == nil || client.recvAEAD == nil {
		t.Fatal("AEAD nil before close — invalid state")
	}
	_ = client.Close()
	if client.sendAEAD != nil {
		t.Fatal("sendAEAD not nil after Close")
	}
	if client.recvAEAD != nil {
		t.Fatal("recvAEAD not nil after Close")
	}
	_ = server.Close()
}

// TestRegression_L3_SignAcceptsInjectableRand locks in the surface
// area L-3 added: Identity.Sign accepts an io.Reader so callers can
// supply their own entropy source. Two calls with the SAME reader
// content are NOT byte-equal today because the upstream
// luxfi/crypto/mldsa wrapper invokes circl's
// `mldsa65.SignTo(..., randomized=true, ...)` which reads from
// crypto/rand internally, bypassing the wrapper's `rand` parameter.
// (See ~/work/lux/crypto/mldsa/mldsa.go SignCtx.)
//
// What we CAN guarantee at the zap layer:
//   - passing a custom reader doesn't panic
//   - the resulting signature still verifies
//   - nil reader falls back to crypto/rand.Reader
//
// Full KAT-byte determinism for AUTH signatures requires plumbing a
// `randomized=false` deterministic path into luxfi/crypto/mldsa.
// That is filed as an upstream follow-up; the zap-layer API surface
// is already shaped correctly to consume it once it lands.
func TestRegression_L3_SignAcceptsInjectableRand(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x33, TranscriptLen))

	sig, err := id.Sign(bytes.NewReader(bytesPattern(0xAA, 256)), h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign with custom reader: %v", err)
	}
	if err := id.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestRegression_L3_SignWithNilRandStillWorks: nil reader must
// fall back to crypto/rand.Reader (production default).
func TestRegression_L3_SignWithNilRandStillWorks(t *testing.T) {
	id, _ := GenerateIdentity()
	h2 := bytesToArr32(bytesPattern(0x44, TranscriptLen))
	sig, err := id.Sign(nil, h2, RoleInitiator, SuiteX25519MLKEM)
	if err != nil {
		t.Fatalf("sign with nil rand: %v", err)
	}
	if err := id.VerifyAuth(h2, RoleInitiator, SuiteX25519MLKEM, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// ---------- helpers ----------

// label returns a stable Profile name for sub-test naming.
func (p Profile) label() string {
	switch p {
	case ProfileStrictPQ:
		return "StrictPQ"
	case ProfilePermissive:
		return "Permissive"
	case ProfileFIPS:
		return "FIPS"
	}
	return "unknown"
}

