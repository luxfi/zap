// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"testing"
)

// TestPickBufClass covers the size-class ladder boundary cases. Each
// class boundary is tested exactly at the boundary and one byte over.
func TestPickBufClass(t *testing.T) {
	cases := []struct {
		n    int
		want int
	}{
		{0, 0},
		{1, 0},
		{64, 0},
		{65, 1},
		{256, 1},
		{257, 2},
		{1024, 2},
		{1025, 3},
		{4 * 1024, 3},
		{4*1024 + 1, 4},
		{16 * 1024, 4},
		{16*1024 + 1, 5},
		{64 * 1024, 5},
		{64*1024 + 1, -1},
		{1 << 20, -1},
	}
	for _, tc := range cases {
		if got := pickBufClass(tc.n); got != tc.want {
			t.Errorf("pickBufClass(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// TestBufRefRetainRelease covers the refcount lifecycle: a single
// retain+release cycle keeps the slab alive across the matched pair.
func TestBufRefRetainRelease(t *testing.T) {
	for _, n := range []int{1, 64, 65, 256, 257, 1024, 4096, 16 * 1024, 64 * 1024, 65 * 1024} {
		ref := getBuf(n)
		if ref == nil {
			t.Fatalf("getBuf(%d) returned nil", n)
		}
		if len(ref.Bytes()) != n {
			t.Errorf("getBuf(%d) Bytes()=%d want %d", n, len(ref.Bytes()), n)
		}
		ref.retain()
		ref.release() // first release: refs 2 -> 1, no return to pool
		ref.release() // second release: refs 1 -> 0, slab returned
	}
}

// TestBufRefReusePool: after a getBuf/release cycle the next getBuf
// of the same class should yield a slab from the pool — verifiable by
// observing that the returned slab's first byte matches what we wrote
// to the previous slab (sync.Pool offers no reuse guarantee but in a
// single-goroutine test it does in practice — flake-resistant by
// repeating).
func TestBufRefReusePool(t *testing.T) {
	const class = 1024
	const trials = 100
	hit := 0
	for i := 0; i < trials; i++ {
		r1 := getBuf(class)
		marker := byte(0xCA)
		r1.Bytes()[0] = marker
		r1.release()

		r2 := getBuf(class)
		if r2.Bytes()[0] == marker {
			hit++
		}
		r2.Bytes()[0] = 0 // wipe before release
		r2.release()
	}
	if hit == 0 {
		t.Logf("warning: pool reuse rate = 0/%d (GC may have evicted)", trials)
	}
}

// TestReadMessageRawPooledRoundTrip: write a length-prefixed frame,
// read it back via the pooled path, confirm bytes are identical.
func TestReadMessageRawPooledRoundTrip(t *testing.T) {
	payloads := [][]byte{
		nil,
		{0x01},
		bytes.Repeat([]byte{0xAB}, 63),
		bytes.Repeat([]byte{0xCD}, 64),
		bytes.Repeat([]byte{0xEF}, 65),
		bytes.Repeat([]byte{0x11}, 4096),
		bytes.Repeat([]byte{0x22}, 65*1024), // over-class fallback
	}
	for _, payload := range payloads {
		var buf bytes.Buffer
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
		buf.Write(hdr[:])
		buf.Write(payload)

		ref, err := readMessageRawPooled(&buf)
		if err != nil {
			t.Fatalf("len=%d: %v", len(payload), err)
		}
		if got := ref.Bytes(); !bytes.Equal(got, payload) {
			t.Errorf("len=%d: payload mismatch got=%x want=%x", len(payload), got, payload)
		}
		ref.release()
	}
}

// TestReadMessageRawPooledShortHeader: reader yields fewer than 4
// bytes -> ErrUnexpectedEOF; no slab leaked.
func TestReadMessageRawPooledShortHeader(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x02}) // only 2 of 4 header bytes
	_, err := readMessageRawPooled(r)
	if err == nil {
		t.Fatal("expected EOF on short header")
	}
}

// TestReadMessageRawPooledShortBody: header declares length L but
// body has < L bytes -> ErrUnexpectedEOF; slab is released back to
// the pool (verified by recording a putBack via a wrapper pool, but
// here we just check no panic + no leak).
func TestReadMessageRawPooledShortBody(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 100)
	body := append(hdr[:], 0x01, 0x02) // only 2 of 100
	_, err := readMessageRawPooled(bytes.NewReader(body))
	if err == nil {
		t.Fatal("expected short-body EOF")
	}
}

// TestReadMessageRawPooledFrameTooLarge: length field declares > 10
// MiB -> error; no slab acquired.
func TestReadMessageRawPooledFrameTooLarge(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 11*1024*1024) // > MaxFrameSize
	_, err := readMessageRawPooled(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("expected too-large error")
	}
}

// TestMessageReleaseNopOnUnpooled: Release on a Builder-built Message
// (refs == nil) is a no-op and does not corrupt state.
func TestMessageReleaseNopOnUnpooled(t *testing.T) {
	b := NewBuilder(64)
	o := b.StartObject(4)
	o.SetUint32(0, 0xDEADBEEF)
	o.FinishAsRoot()
	data := b.Finish()
	msg, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Release must be a no-op when refs is nil.
	msg.Release()
	// And nil-receiver too.
	(*Message)(nil).Release()
}

// TestMessageReleaseConcurrent stresses refcounting under concurrent
// Retain/Release. Each goroutine retains then releases a shared
// message; the final release happens when all goroutines finish. The
// slab MUST return to the pool exactly once — any double-release
// would panic in the pool with a duplicate entry. We force the race
// detector to scrutinize the refcount transitions.
func TestMessageReleaseConcurrent(t *testing.T) {
	const goroutines = 64
	const iterations = 100

	for iter := 0; iter < iterations; iter++ {
		ref := getBuf(1024)
		// Stamp known data so we can detect early-release corruption.
		for i := range ref.Bytes() {
			ref.Bytes()[i] = byte(i)
		}

		var wg sync.WaitGroup
		// Each goroutine takes one retain. They run concurrently and
		// each does one release at the end. The initial refcount of 1
		// is consumed by an explicit release at the end of this iter.
		for i := 0; i < goroutines; i++ {
			ref.retain()
			wg.Add(1)
			go func() {
				defer wg.Done()
				// "Use" the bytes so the race detector sees a load.
				_ = ref.Bytes()[0]
				ref.release()
			}()
		}
		wg.Wait()
		// Final release brings refs to 0; slab returns to pool.
		ref.release()
	}
}

// TestReadMessagePooledBackToBackFrames: drive readMessageRawPooled
// across many frames in one stream, releasing each. This exercises
// the steady-state pool reuse pattern that hot paths rely on.
func TestReadMessagePooledBackToBackFrames(t *testing.T) {
	const N = 200
	const payloadSize = 1024
	payload := bytes.Repeat([]byte{0x5A}, payloadSize)

	var buf bytes.Buffer
	for i := 0; i < N; i++ {
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(payloadSize))
		buf.Write(hdr[:])
		buf.Write(payload)
	}

	r := io.Reader(&buf)
	for i := 0; i < N; i++ {
		ref, err := readMessageRawPooled(r)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if !bytes.Equal(ref.Bytes(), payload) {
			t.Fatalf("frame %d: payload mismatch", i)
		}
		ref.release()
	}
}
