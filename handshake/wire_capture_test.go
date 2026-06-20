// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestWireDerivedTranscript runs a real Initiator ↔ Responder handshake
// through tee'd net.Conns, captures every byte each side writes, then
// independently re-derives H_2 from the captured stream using only the
// spec §7 recipe (three SHA3-256 calls). The resulting hash must
// match what NewTranscript / AbsorbHello / AbsorbKEM / FinishFull
// computes over the same bytes — proving the wire emission code and
// the transcript builder agree on what "the bytes" actually are.
func TestWireDerivedTranscript(t *testing.T) {
	clientID, _ := GenerateIdentity()
	serverID, _ := GenerateIdentity()

	rawClient, rawServer := loopbackPair(t)
	clientCap := &captureConn{Conn: rawClient}
	serverCap := &captureConn{Conn: rawServer}

	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		rs := &Responder{Local: serverID, Profile: ProfileStrictPQ, ReplayCache: NewReplayCache()}
		_, serr = rs.Run(serverCap)
	}()
	go func() {
		defer wg.Done()
		init := &Initiator{Local: clientID, Expected: &Identity{PublicKey: serverID.PublicKey}, Profile: ProfileStrictPQ}
		_, cerr = init.Run(clientCap)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: c=%v s=%v", cerr, serr)
	}

	// The initiator wrote: MAGIC ∥ HELLO_frame ∥ KEM_INIT_frame ∥ AUTH_frame.
	// The responder wrote: KEM_REPLY_frame ∥ AUTH_frame.
	clientBytes := clientCap.written.Bytes()
	serverBytes := serverCap.written.Bytes()

	// Strip magic.
	if !bytes.HasPrefix(clientBytes, Magic[:]) {
		t.Fatal("client did not write magic prefix")
	}
	clientBytes = clientBytes[MagicLen:]

	helloBody := mustReadFrameBody(t, &clientBytes, FrameHello)
	kemInitBody := mustReadFrameBody(t, &clientBytes, FrameKEMInit)

	kemReplyBody := mustReadFrameBody(t, &serverBytes, FrameKEMReply)

	// Decode just enough to recover pkI / pkR / schemes for FinishFull.
	hello, err := DecodeHello(helloBody)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	reply, err := DecodeKEMReply(kemReplyBody)
	if err != nil {
		t.Fatalf("DecodeKEMReply: %v", err)
	}

	// Path A: feed the captured bytes into the Transcript builder.
	tr := NewTranscript(hello.Suite)
	tr.AbsorbHello(helloBody)
	tr.AbsorbKEM(kemInitBody, kemReplyBody)
	h2Builder := tr.FinishFull(hello.StaticPKInitiator, reply.StaticPKResponder, hello.OfferedSchemes)

	// Path B: hand-compute H_2 via three SHA3-256 calls per §7.
	h := sha3.New256()
	h.Write(LblProtocol)
	h.Write([]byte{0x00, byte(hello.Suite)})
	h.Write(helloBody)
	var h0 [TranscriptLen]byte
	h.Sum(h0[:0])

	h.Reset()
	h.Write(h0[:])
	h.Write(kemInitBody)
	h.Write(kemReplyBody)
	var h1 [TranscriptLen]byte
	h.Sum(h1[:0])

	h.Reset()
	h.Write(h1[:])
	h.Write(hello.StaticPKInitiator)
	h.Write(reply.StaticPKResponder)
	// schemes re-encoded as u32 len ∥ bytes.
	lp := []byte{0, 0, 0, byte(len(hello.OfferedSchemes))}
	h.Write(lp)
	for _, s := range hello.OfferedSchemes {
		h.Write([]byte{byte(s)})
	}
	var h2Hand [TranscriptLen]byte
	h.Sum(h2Hand[:0])

	if h2Builder != h2Hand {
		t.Fatalf("Transcript builder disagrees with §7 hand-computation:\n builder: %x\n hand:    %x", h2Builder, h2Hand)
	}
}

// captureConn wraps net.Conn and copies every byte written into a
// buffer. Reads pass through unmodified. Used to snapshot a real
// handshake's wire output for cross-checking.
type captureConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.written.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// mustReadFrameBody peels the §5 outer envelope from the head of
// buf, asserts the type matches want, advances buf past the frame,
// and returns the body bytes.
func mustReadFrameBody(t *testing.T, buf *[]byte, want FrameType) []byte {
	t.Helper()
	r := bytes.NewReader(*buf)
	got, body, err := readFrame(r)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if got != want {
		t.Fatalf("got frame type 0x%02x, want 0x%02x", byte(got), byte(want))
	}
	// Advance buf past the consumed bytes.
	consumed := len(*buf) - r.Len()
	*buf = (*buf)[consumed:]
	return body
}

// suppress unused import on platforms that strip helpers.
var _ = io.EOF
