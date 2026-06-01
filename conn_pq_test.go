// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/luxfi/zap/handshake"
)

// TestWrapPQStreamRoundTrip drives a full ZAP-PQ handshake over TCP
// loopback, wraps both ends with WrapPQ, and verifies byte streams
// flow correctly under the net.Conn façade — including chunking
// across multiple Send/Recv frames when the payload exceeds
// MaxPQRecord.
func TestWrapPQStreamRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	clientID, err := handshake.GenerateIdentity()
	if err != nil {
		t.Fatalf("client id: %v", err)
	}
	serverID, err := handshake.GenerateIdentity()
	if err != nil {
		t.Fatalf("server id: %v", err)
	}

	type serverResult struct {
		conn net.Conn
		err  error
	}
	srvCh := make(chan serverResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- serverResult{nil, err}
			return
		}
		r := &handshake.Responder{
			Local:       serverID,
			Profile:     handshake.ProfileStrictPQ,
			ReplayCache: handshake.NewReplayCache(),
		}
		sess, err := r.Run(c)
		if err != nil {
			srvCh <- serverResult{nil, err}
			return
		}
		srvCh <- serverResult{WrapPQ(c, sess), nil}
	}()

	tcp, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	init := &handshake.Initiator{
		Local:    clientID,
		Expected: &handshake.Identity{PublicKey: serverID.PublicKey},
		Profile:  handshake.ProfileStrictPQ,
	}
	sess, err := init.Run(tcp)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	clientPQ := WrapPQ(tcp, sess)
	defer clientPQ.Close()

	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("server: %v", sr.err)
	}
	serverPQ := sr.conn
	defer serverPQ.Close()

	// Round-trip a payload that spans two DATA frames.
	payload := bytes.Repeat([]byte("ABCDEFGH"), MaxPQRecord/8+128)

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(serverPQ, buf); err != nil {
			serverErr = err
			return
		}
		if !bytes.Equal(buf, payload) {
			serverErr = io.ErrUnexpectedEOF
			return
		}
		if _, err := serverPQ.Write(buf); err != nil {
			serverErr = err
		}
	}()

	if _, err := clientPQ.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientPQ, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server side: %v", serverErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echoed payload differs")
	}

	// AsPQConn must accept the wrapper and return the verified peer ID.
	pq, err := AsPQConn(clientPQ)
	if err != nil {
		t.Fatalf("AsPQConn: %v", err)
	}
	if pq.PeerID() != serverID.ID() {
		t.Fatal("PeerID mismatch")
	}
	// And reject a plain conn.
	if _, err := AsPQConn(&net.TCPConn{}); err == nil {
		t.Fatal("AsPQConn accepted non-pq conn")
	}
}
