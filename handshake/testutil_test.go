// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"net"
	"testing"
)

// loopbackPair returns a connected (client, server) TCP socket pair
// bound to 127.0.0.1:auto. Used by the integration tests because
// net.Pipe is unbuffered and deadlocks on the multi-frame
// AUTH/ALERT cross-write that ZAP-PQ-v1 performs legitimately
// (TCP buffers absorb it in production).
//
// Both sockets are registered for cleanup on test exit.
func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	server = r.c
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}
