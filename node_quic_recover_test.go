// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap_test

import (
	"context"
	"testing"
	"time"

	zap "github.com/luxfi/zap"
)

// buildTypedMsg builds a one-field message tagged msgType so the dispatcher
// routes it to that handler. Mirrors buildEchoMessage but with a caller-
// chosen type.
func buildTypedMsg(t *testing.T, msgType uint16, v uint64) *zap.Message {
	t.Helper()
	b := zap.NewBuilder(64)
	o := b.StartObject(16)
	o.SetUint64(0, v)
	o.FinishAsRoot()
	msg, err := zap.Parse(b.FinishWithFlags(msgType << 8))
	if err != nil {
		t.Fatalf("build typed msg: %v", err)
	}
	return msg
}

// TestQUICHandlerPanicDoesNotCrashNode proves the recover() guard also
// covers the QUIC transport's per-Call stream dispatch (handleCallStream).
// A handler that panics over QUIC must not unwind into the stream goroutine
// and crash the node: safeHandle recovers, the panicking Call fails/closes,
// and a subsequent valid Call to a different handler on the SAME server node
// still succeeds.
func TestQUICHandlerPanicDoesNotCrashNode(t *testing.T) {
	const (
		qmtPanic uint16 = 0x93
		qmtEcho  uint16 = 0x94
	)
	srvAddr, srv, cli := newQUICTestPair(t, "qsrv-panic", "qcli-panic")
	defer srv.Stop()
	defer cli.Stop()

	srv.Handle(qmtPanic, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		panic("quic handler blew up")
	})
	srv.Handle(qmtEcho, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		return buildTypedMsg(t, qmtEcho, msg.Root().Uint64(0)+1), nil
	})

	if err := cli.ConnectDirect(srvAddr); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	waitForPeer(t, srv, "qcli-panic", 2*time.Second)
	waitForPeer(t, cli, "qsrv-panic", 2*time.Second)

	// 1. Fire the panic-inducing Call over QUIC. The stream is torn down on
	//    recover; the Call errors or times out. Process MUST stay up.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	_, err := cli.Call(ctx1, "qsrv-panic", buildTypedMsg(t, qmtPanic, 1))
	cancel1()
	if err == nil {
		t.Log("QUIC panic Call returned nil error; node-survival is the real assertion")
	} else {
		t.Logf("QUIC panic Call errored as expected: %v", err)
	}

	// 2. THE PROOF: the server node survived. A valid echo Call on the same
	//    node over a fresh QUIC stream still works.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	resp, err := cli.Call(ctx2, "qsrv-panic", buildTypedMsg(t, qmtEcho, 41))
	if err != nil {
		t.Fatalf("echo Call after QUIC handler panic failed — node did not survive: %v", err)
	}
	if got := resp.Root().Uint64(0); got != 42 {
		t.Errorf("echo returned %d want 42 (node alive but handler misbehaved)", got)
	}
}
