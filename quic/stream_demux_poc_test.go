// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"

	zapquic "github.com/luxfi/zap/quic"
)

// TestUnifiedTransport_ThreeClassStreamDemux is the executable core of
// LP-202 §5.2 (three-class stream demultiplexing) and §6.1 (PQ channel).
//
// It brings up one QUIC-PQ connection and demonstrates that a single
// UDP port can carry the three unified-transport stream classes ---
//
//	'R' (RPC)  |  'C' (consensus-P2P)  |  'Z' (ZAP-native)
//
// --- multiplexed on that one connection, each routed to its own class
// dispatcher by a one-byte class prefix (LP-202 §5.2, the only new byte
// on the wire), and that the connection is really post-quantum
// (X25519MLKEM768, IANA 0x11EC).
//
// This is a PoC for the SPEC; it exercises only luxfi/zap and touches
// nothing in luxd's consensus or proposer VM.
func TestUnifiedTransport_ThreeClassStreamDemux(t *testing.T) {
	// LP-202 §5.2 class tags. These are the first byte of the first
	// frame on every stream; the class dispatcher routes on them.
	const (
		classRPC       = byte('R') // 0x52 — Class R: /ext/* RPC
		classConsensus = byte('C') // 0x43 — Class C: Avalanche/Simplex P2P
		classZAP       = byte('Z') // 0x5A — Class Z: native ZAP services
	)

	// classLabel is the demux target: each class has a distinct handler,
	// so a response proves the stream reached the correct dispatcher.
	classLabel := func(tag byte) (string, bool) {
		switch tag {
		case classRPC:
			return "rpc", true
		case classConsensus:
			return "consensus", true
		case classZAP:
			return "zap", true
		default:
			return "", false
		}
	}

	srv, cli, closeAll := withServerAndClient(t, defaultServerTLS(t), defaultClientTLS(), false)
	defer closeAll()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ---- server: accept the connection, then demux each per-Call stream
	serveErr := make(chan error, 1)
	go func() {
		conn, err := srv.Accept(ctx)
		if err != nil {
			serveErr <- fmt.Errorf("server Accept: %w", err)
			return
		}
		// Assert the *server side* really negotiated the hybrid PQ group.
		if cs := conn.ConnectionState(); cs.CurveID != tls.X25519MLKEM768 {
			serveErr <- fmt.Errorf("server curveID = 0x%x, want 0x11ec", uint16(cs.CurveID))
			return
		}
		serveErr <- nil

		// Per-Call stream accept loop: peek the 1-byte class tag on the
		// first frame, route to the class dispatcher, echo a tagged reply.
		for {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return // conn torn down — normal at end of test
			}
			go func(s *zapquic.Stream) {
				defer s.Close()
				req, err := s.ReadFrame()
				if err != nil || len(req) == 0 {
					return
				}
				tag, body := req[0], req[1:]
				label, ok := classLabel(tag)
				if !ok {
					// Structurally-unknown class: refuse (fail closed).
					_ = s.WriteFrame([]byte("ERR:unknown-class"))
					return
				}
				// Reply proves WHICH dispatcher handled the stream.
				reply := append([]byte(label+":"), body...)
				reply = append([]byte{tag}, reply...) // echo class tag back
				_ = s.WriteFrame(reply)
			}(s)
		}
	}()

	// ---- client: dial (PQ) and drive one stream per class concurrently
	conn, err := cli.Dial(ctx, srv.Addr().String())
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer conn.Close()

	if cs := conn.ConnectionState(); cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("client curveID = 0x%x, want 0x11ec (X25519MLKEM768)", uint16(cs.CurveID))
	}
	if serr := <-serveErr; serr != nil {
		t.Fatalf("%v", serr)
	}

	cases := []struct {
		tag       byte
		wantLabel string
		payload   string
	}{
		{classRPC, "rpc", "eth_blockNumber"},
		{classConsensus, "consensus", "PushQuery"},
		{classZAP, "zap", "rpcdb.Get"},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(cases))
	for _, tc := range cases {
		wg.Add(1)
		go func(tag byte, wantLabel, payload string) {
			defer wg.Done()
			s, err := conn.OpenStream(ctx)
			if err != nil {
				errs <- fmt.Errorf("OpenStream(%c): %w", tag, err)
				return
			}
			defer s.Close()

			// LP-202 §5.2 wire: [class tag][class-native payload].
			frame := append([]byte{tag}, []byte(payload)...)
			if err := s.WriteFrame(frame); err != nil {
				errs <- fmt.Errorf("WriteFrame(%c): %w", tag, err)
				return
			}
			resp, err := s.ReadFrame()
			if err != nil {
				errs <- fmt.Errorf("ReadFrame(%c): %w", tag, err)
				return
			}
			// Verify: (1) the reply echoes our class tag (demux was
			// symmetric), and (2) it carries the correct class label
			// (the RIGHT dispatcher handled it) and our payload.
			if len(resp) == 0 || resp[0] != tag {
				errs <- fmt.Errorf("class %c: reply tag = %v, want %c", tag, resp, tag)
				return
			}
			want := string(tag) + wantLabel + ":" + payload
			if string(resp) != want {
				errs <- fmt.Errorf("class %c: got %q, want %q", tag, string(resp), want)
				return
			}
			errs <- nil
		}(tc.tag, tc.wantLabel, tc.payload)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("demux: %v", e)
		}
	}

	t.Logf("LP-202 PoC OK: 3 classes (R/C/Z) demuxed on one QUIC-PQ conn, "+
		"CurveID=0x%x (X25519MLKEM768)", uint16(conn.ConnectionState().CurveID))
}
