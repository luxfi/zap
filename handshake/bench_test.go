// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"net"
	"sync"
	"testing"
)

// BenchmarkHandshake measures full Initiator ↔ Responder handshake
// over TCP loopback. The ML-KEM-768 + ML-DSA-65 work plus AES init
// dominates; numbers should land in the low millisecond range.
func BenchmarkHandshake(b *testing.B) {
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		type acc struct {
			c   net.Conn
			err error
		}
		ch := make(chan acc, 1)
		go func() {
			c, err := ln.Accept()
			ch <- acc{c, err}
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		r := <-ch
		if r.err != nil {
			b.Fatalf("accept: %v", r.err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		var cerr, serr error
		var cs, ss *Session
		go func() {
			defer wg.Done()
			rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
			ss, serr = rs.Run(r.c)
		}()
		go func() {
			defer wg.Done()
			init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
			cs, cerr = init.Run(raw)
		}()
		wg.Wait()
		if cerr != nil || serr != nil {
			b.Fatalf("handshake: c=%v s=%v", cerr, serr)
		}
		_ = cs.Close()
		_ = ss.Close()
	}
}

// BenchmarkSessionSend64B measures the per-frame Send cost for a
// 64-byte payload. Most ZAP frames are short control messages; this
// is the steady-state cost they pay.
func BenchmarkSessionSend64B(b *testing.B) {
	client, server := benchPair(b)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 64)

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for i := 0; i < b.N; i++ {
			_, _ = server.Recv()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.Send(payload); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
	b.StopTimer()
	<-drained
}

// BenchmarkSessionSend4K measures the per-frame Send cost for a 4 KiB
// payload — the size band most application messages fall into.
func BenchmarkSessionSend4K(b *testing.B) {
	client, server := benchPair(b)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 4096)

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for i := 0; i < b.N; i++ {
			_, _ = server.Recv()
		}
	}()

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.Send(payload); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
	b.StopTimer()
	<-drained
}

// BenchmarkSessionRecv64B mirrors Send64B from the receiver side.
func BenchmarkSessionRecv64B(b *testing.B) {
	client, server := benchPair(b)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 64)
	go func() {
		for i := 0; i < b.N; i++ {
			if err := client.Send(payload); err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := server.Recv(); err != nil {
			b.Fatalf("recv: %v", err)
		}
	}
}

// BenchmarkDeriveSession isolates §8 cost — pure HKDF-Extract +
// 5×HKDF-Expand over SHA3-256. Should be dominated by SHA3 state
// init and small-input absorbs.
func BenchmarkDeriveSession(b *testing.B) {
	h2 := bytesToArr32(bytesPattern(0x10, TranscriptLen))
	x := bytesToArr32(bytesPattern(0x20, X25519SharedLen))
	m := bytesToArr32(bytesPattern(0x30, MLKEM768SharedLen))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DeriveSession(h2, x, m)
	}
}

// BenchmarkRatchet isolates §13 cost — two HKDF-Expand calls.
func BenchmarkRatchet(b *testing.B) {
	var k [AEADKeyLen]byte
	for i := range k {
		k[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Ratchet(k, uint8(i))
	}
}

// BenchmarkTranscriptFull walks the entire §7 chain over realistic
// frame sizes — HELLO (~2 KiB), KEM_INIT (1.2 KiB), KEM_REPLY (~4
// KiB), plus the final pkI/pkR/schemes mix-in.
func BenchmarkTranscriptFull(b *testing.B) {
	hello := bytesPattern(0xA0, 2014)
	init := bytesPattern(0xB0, 1216)
	reply := bytesPattern(0xC0, 4224)
	pkI := bytesPattern(0xD0, MLDSA65PubLen)
	pkR := bytesPattern(0xE0, MLDSA65PubLen)
	schemes := []SuiteID{SuiteX25519MLKEM}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := NewTranscript(SuiteX25519MLKEM)
		tr.AbsorbHello(hello)
		tr.AbsorbKEM(init, reply)
		_ = tr.FinishFull(pkI, pkR, schemes)
	}
}

// BenchmarkPSKStoreIssue measures cold-cache PSK issuance — what a
// busy responder pays per handshake.
func BenchmarkPSKStoreIssue(b *testing.B) {
	store := NewPSKStore()
	var psk [PSKKeyLen]byte
	var cid [IDLen]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		psk[0] = byte(i)
		cid[0] = byte(i >> 8)
		_ = store.Issue(psk, cid)
	}
}

// BenchmarkReplayCacheSeenOrAdd measures the steady-state cost of a
// fresh-key insert (the common case during a healthy handshake).
func BenchmarkReplayCacheSeenOrAdd(b *testing.B) {
	c := NewReplayCache()
	var id [IDLen]byte
	var rnd [ClientRandLen]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id[0] = byte(i)
		id[1] = byte(i >> 8)
		rnd[0] = byte(i >> 16)
		rnd[1] = byte(i >> 24)
		_ = c.SeenOrAdd(id, rnd)
	}
}

// ---------- helpers ----------

// benchPair: handshake → return both Sessions, no t.Helper plumbing.
func benchPair(b *testing.B) (client, server *Session) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		b.Fatalf("accept: %v", r.err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		server, serr = rs.Run(r.c)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
		client, cerr = init.Run(raw)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		b.Fatalf("handshake: c=%v s=%v", cerr, serr)
	}
	return
}
