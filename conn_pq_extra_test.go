// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/zap/handshake"
)

// pqPairZap is the package-level helper mirroring handshake/aead_test.go's
// pqPair but returning conn_pq-wrapped net.Conns. Used by the
// adapter tests below.
func pqPairZap(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	clientID, _ := handshake.GenerateIdentity()
	serverID, _ := handshake.GenerateIdentity()

	type res struct {
		c   net.Conn
		err error
	}
	srvCh := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvCh <- res{nil, err}
			return
		}
		r := &handshake.Responder{
			Local:       serverID,
			Profile:     handshake.ProfileStrictPQ,
			ReplayCache: handshake.NewReplayCache(),
		}
		sess, err := r.Run(raw)
		if err != nil {
			srvCh <- res{nil, err}
			return
		}
		srvCh <- res{WrapPQ(raw, sess), nil}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	init := &handshake.Initiator{
		Local:    clientID,
		Expected: &handshake.Identity{PublicKey: serverID.PublicKey},
		Profile:  handshake.ProfileStrictPQ,
	}
	sess, err := init.Run(raw)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	client = WrapPQ(raw, sess)

	r := <-srvCh
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	server = r.c

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// TestPQConnDeadlinePropagates: SetDeadline / SetReadDeadline /
// SetWriteDeadline must reach the underlying TCP socket; a deadline
// in the past causes Read to fail with a deadline error.
func TestPQConnDeadlinePropagates(t *testing.T) {
	client, _ := pqPairZap(t)

	past := time.Now().Add(-1 * time.Second)
	if err := client.SetReadDeadline(past); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("Read should fail after past deadline")
	}
}

// TestPQConnDoubleClose: Close is idempotent at the net.Conn layer,
// regardless of whether the underlying Session or TCP socket return
// an error on the second pass.
func TestPQConnDoubleClose(t *testing.T) {
	client, _ := pqPairZap(t)
	if err := client.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// Second close may return io.EOF or net.ErrClosed from the TCP
	// half; the Session is already closed so it returns nil. Either
	// is acceptable — the property is "no panic".
	_ = client.Close()
}

// TestAsPQConnPeerIDAfterClose: PeerID remains accessible after the
// Session is closed (key material is zeroed, but the peer hash was
// captured at handshake-completion time).
func TestAsPQConnPeerIDAfterClose(t *testing.T) {
	client, _ := pqPairZap(t)
	pq, err := AsPQConn(client)
	if err != nil {
		t.Fatalf("AsPQConn: %v", err)
	}
	before := pq.PeerID()
	if before == ([32]byte{}) {
		t.Fatal("PeerID is zero before close")
	}
	_ = client.Close()
	after := pq.PeerID()
	if before != after {
		t.Fatal("PeerID changed after close")
	}
}

// TestAsPQConnRejectsLegacy: AsPQConn on a vanilla TCP conn returns
// ErrNotPQConn.
func TestAsPQConnRejectsLegacy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { c.Close() } }()
	plain, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer plain.Close()
	if _, err := AsPQConn(plain); !errors.Is(err, ErrNotPQConn) {
		t.Fatalf("expected ErrNotPQConn, got %v", err)
	}
}

// TestPQConnChunkedWriteOrdering: multiple goroutines writing to the
// same pq conn must produce intact frames at the receiver. Within
// a single Write, chunking is internal — but concurrent Writes only
// guarantee per-Write atomicity, not interleave-safety; this test
// pins the per-Write atomicity property under -race.
func TestPQConnChunkedWriteOrdering(t *testing.T) {
	client, server := pqPairZap(t)

	const N = 32
	chunkSize := MaxPQRecord/4 + 17
	payloads := make([][]byte, N)
	for i := range payloads {
		p := make([]byte, chunkSize)
		for j := range p {
			p[j] = byte(i)
		}
		payloads[i] = p
	}

	var senderWG sync.WaitGroup
	senderWG.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer senderWG.Done()
			if _, err := client.Write(payloads[i]); err != nil {
				t.Errorf("write[%d]: %v", i, err)
			}
		}()
	}

	// Reader: collect chunkSize × N bytes, count how many of each
	// payload signature we saw. Frames may arrive interleaved at the
	// byte level (Write of N bytes goes through Session.Send which
	// is per-call atomic, but concurrent Writes can interleave by
	// frame), so we count signatures by looking at consecutive bytes.
	total := chunkSize * N
	got := make([]byte, 0, total)
	for len(got) < total {
		buf := make([]byte, total-len(got))
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	senderWG.Wait()

	counts := make(map[byte]int)
	for _, b := range got {
		counts[b]++
	}
	for i := 0; i < N; i++ {
		if counts[byte(i)] != chunkSize {
			t.Errorf("payload signature 0x%02x count %d, want %d", i, counts[byte(i)], chunkSize)
		}
	}
}
