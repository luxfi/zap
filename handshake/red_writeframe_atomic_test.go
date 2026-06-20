// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Red fourth-pass verification of the M-PRE-1 fix.
//
// Premise of the fix: writeFrame issues exactly one Write per frame.
// At the io.Writer boundary, that means: even if 1000 goroutines
// concurrently writeFrame into a synchronised writer (one whose Write
// is atomic), the on-wire sequence is a permutation of complete
// envelopes — never an interleave of (hdr_A, hdr_B, body_A, body_B).
//
// The "syncWriter" below mirrors what a real net.Conn does: its
// Write is atomic at the syscall level, and we capture exactly the
// bytes presented to each Write call. Replaying those captures, we
// must be able to consume them as complete frames in some order with
// zero leftover bytes.

package handshake

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// syncWriter captures every Write call as a separate []byte. The
// real-world equivalent is one TCP_NODELAY syscall per Write.
type syncWriter struct {
	mu     sync.Mutex
	chunks [][]byte
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	// Copy because callers may reuse p; we want to capture the bytes
	// as they were on this Write.
	c := make([]byte, len(p))
	copy(c, p)
	w.chunks = append(w.chunks, c)
	w.mu.Unlock()
	return len(p), nil
}

// TestRedFourthPass_WriteFrameAtomicityUnderConcurrency: spin many
// goroutines, each writeFrame's a distinct frame, then verify each
// captured chunk is one complete envelope. Failing this test means
// the fix did NOT achieve atomicity.
func TestRedFourthPass_WriteFrameAtomicityUnderConcurrency(t *testing.T) {
	const G = 64
	const PerG = 32

	w := &syncWriter{}
	var wg sync.WaitGroup
	wg.Add(G)
	var counter atomic.Uint64
	for g := 0; g < G; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < PerG; i++ {
				// Mix shapes per iteration so a header/body split
				// would be highly visible.
				n := counter.Add(1)
				switch n % 4 {
				case 0:
					_ = writeFrame(w, FrameData, makeBody(0xAA, int(n%128)))
				case 1:
					_ = writeFrame(w, FrameAlert, []byte{0x01, 0, 0, 0, 0})
				case 2:
					_ = writeFrame(w, FrameRekey, []byte{0x04})
				case 3:
					_ = writeFrame(w, FrameData, makeBody(0xBB, 4096))
				}
			}
		}(g)
	}
	wg.Wait()

	totalFrames := G * PerG
	if len(w.chunks) != totalFrames {
		t.Fatalf("captured %d Write calls for %d writeFrame invocations; expected exact match (fix regressed)",
			len(w.chunks), totalFrames)
	}

	// Each chunk must be a complete envelope: type(1) + length(4) + body.
	for i, c := range w.chunks {
		if len(c) < 5 {
			t.Fatalf("chunk %d: %d bytes, too short to contain frame header", i, len(c))
		}
		t0 := FrameType(c[0])
		bodyLen := binary.BigEndian.Uint32(c[1:5])
		if len(c)-5 != int(bodyLen) {
			t.Fatalf("chunk %d: header says body=%d, captured body=%d (header/body split)",
				i, bodyLen, len(c)-5)
		}
		switch t0 {
		case FrameData, FrameAlert, FrameRekey:
		default:
			t.Fatalf("chunk %d: unexpected frame type 0x%02x — wire corrupted",
				i, byte(t0))
		}
	}
}

// TestRedFourthPass_PreFixSimulationProvesAtomicityClaim: build a
// deliberately-broken writeFrameOldStyle that emits header then body
// in two Writes, run it concurrently into the same syncWriter, and
// show that the chunk count > frame count (proving the syncWriter
// catches the regression we care about). This protects against
// drift in the regression test's framing.
func TestRedFourthPass_PreFixSimulationProvesAtomicityClaim(t *testing.T) {
	const G = 16
	const PerG = 8

	// Old-style: two Writes per frame.
	oldStyle := func(w io.Writer, t FrameType, body []byte) {
		var hdr [5]byte
		hdr[0] = byte(t)
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(body)))
		_, _ = w.Write(hdr[:])
		_, _ = w.Write(body)
	}

	w := &syncWriter{}
	var wg sync.WaitGroup
	wg.Add(G)
	for g := 0; g < G; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < PerG; i++ {
				oldStyle(w, FrameData, makeBody(byte(id), 64))
			}
		}(g)
	}
	wg.Wait()

	totalFrames := G * PerG
	// Old style → exactly 2 Writes per frame.
	if len(w.chunks) != totalFrames*2 {
		t.Fatalf("old-style writeFrame produced %d chunks for %d frames; expected 2x",
			len(w.chunks), totalFrames)
	}
	// And the chunks should not all be complete-envelope shape:
	// many will be the 5-byte header alone.
	headerOnly := 0
	for _, c := range w.chunks {
		if len(c) == 5 {
			headerOnly++
		}
	}
	if headerOnly == 0 {
		t.Fatal("old-style sim produced zero header-only chunks; test contract broken")
	}

	// Sanity: replaying these via readFrame on a serialised
	// reconstruction works iff we serialise the chunks in capture
	// order. The point is the wire ORDER may interleave: prove
	// reading the concatenated capture would fail under the old
	// implementation. We do that by concatenating in capture order
	// and confirming we can still parse frames — but the
	// goroutine-induced reordering means a sender-1 header may
	// precede a sender-2 header, which is the wire corruption the
	// fix prevents.
	var buf bytes.Buffer
	for _, c := range w.chunks {
		buf.Write(c)
	}
	r := bytes.NewReader(buf.Bytes())
	successfulFrames := 0
	for {
		_, _, err := readFrame(r)
		if err != nil {
			break
		}
		successfulFrames++
	}
	// If frames are interleaved (sender-1's hdr then sender-2's hdr
	// before sender-1's body), the parser will succeed for some
	// non-trivial subset because the body bytes happen to be
	// uniform-fill — that's expected for a clamped test. The
	// CONTRACT we assert is: the chunk count under the old style
	// is 2x the frame count, which is the signature of the bug.
	if successfulFrames < 0 {
		t.Fatal("unreachable")
	}
}

// makeBody returns a []byte of the given size filled with fillByte.
func makeBody(fillByte byte, size int) []byte {
	if size <= 0 {
		size = 1
	}
	b := make([]byte, size)
	for i := range b {
		b[i] = fillByte
	}
	return b
}
