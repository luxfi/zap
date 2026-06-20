// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
)

// TestStressSequentialHandshakes runs N back-to-back full handshakes
// between the same two identities, asserting each completes and the
// session can echo a small payload. Catches resource leaks (goroutine
// or fd) and any state accidentally carried across Run() invocations.
//
// The replay cache MUST allow distinct (client_id, client_random)
// tuples across runs — client_random is fresh on each handshake, so
// no replay should ever fire.
func TestStressSequentialHandshakes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress in -short")
	}
	const N = 32

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()
	cache := NewReplayCache()

	goroutinesBefore := runtime.NumGoroutine()

	for i := 0; i < N; i++ {
		clientConn, serverConn := loopbackPair(t)
		var wg sync.WaitGroup
		wg.Add(2)
		var cSess, sSess *Session
		var cerr, serr error
		go func() {
			defer wg.Done()
			rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: cache}
			sSess, serr = rs.Run(serverConn)
		}()
		go func() {
			defer wg.Done()
			init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
			cSess, cerr = init.Run(clientConn)
		}()
		wg.Wait()
		if cerr != nil || serr != nil {
			t.Fatalf("iteration %d: c=%v s=%v", i, cerr, serr)
		}
		echoOnce(t, cSess, sSess, []byte("ping"), i)
		_ = cSess.Close()
		_ = sSess.Close()
	}

	// Replay cache should hold exactly N entries (none collided).
	if cache.Len() != N {
		t.Fatalf("replay cache holds %d, want %d", cache.Len(), N)
	}

	// Give any deferred goroutines a tick to wind down, then check
	// we did not leak goroutines per handshake.
	runtime.Gosched()
	goroutinesAfter := runtime.NumGoroutine()
	// Some slack for the test harness — net package may keep its
	// own background goroutines. We allow ≤ 4 extra; growth
	// proportional to N would indicate a leak.
	if delta := goroutinesAfter - goroutinesBefore; delta > 4 {
		t.Fatalf("goroutine leak: %d → %d (delta %d) over %d handshakes",
			goroutinesBefore, goroutinesAfter, delta, N)
	}
}

// TestStressLargePayloadRoundTrip drives a payload near MaxFrameBody
// through a single Send/Recv. Catches any size-related off-by-one in
// frame envelope or AEAD seal sizing.
func TestStressLargePayloadRoundTrip(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	const payloadSize = 1 << 20 // 1 MiB
	plain := make([]byte, payloadSize)
	for i := range plain {
		plain[i] = byte(i)
	}

	done := make(chan error, 1)
	go func() {
		got, err := server.Recv()
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, plain) {
			done <- errfmt("payload mismatch")
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

// echoOnce is a single-frame echo helper used by stress loops.
func echoOnce(t *testing.T, c, s *Session, payload []byte, iter int) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		got, err := s.Recv()
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, payload) {
			done <- errfmt("iter %d: server got %q want %q", iter, got, payload)
			return
		}
		done <- s.Send(got)
	}()
	if err := c.Send(payload); err != nil {
		t.Fatalf("iter %d client send: %v", iter, err)
	}
	got, err := c.Recv()
	if err != nil {
		t.Fatalf("iter %d client recv: %v", iter, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("iter %d server: %v", iter, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("iter %d echo mismatch", iter)
	}
}
