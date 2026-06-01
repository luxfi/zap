// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage for IO-error and ALERT-injection paths inside
// Initiator/Responder runFull/runResume and Session error branches.
// These use failing readers/writers to drive the otherwise-unreachable
// "wire IO failed" branches in the state machines.

package handshake

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

// failingRW returns a configurable error on Read or Write at a
// specific byte offset.
type failingRW struct {
	mu        sync.Mutex
	written   int
	failAt    int
	failErr   error
	underlying io.ReadWriter
}

func (f *failingRW) Read(p []byte) (int, error) {
	if f.underlying == nil {
		return 0, io.EOF
	}
	return f.underlying.Read(p)
}

func (f *failingRW) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.written >= f.failAt {
		return 0, f.failErr
	}
	allowed := f.failAt - f.written
	if allowed >= len(p) {
		f.written += len(p)
		if f.underlying != nil {
			return f.underlying.Write(p)
		}
		return len(p), nil
	}
	if f.underlying != nil {
		_, _ = f.underlying.Write(p[:allowed])
	}
	f.written += allowed
	return allowed, f.failErr
}

// TestCoverage_InitiatorMagicWriteFailure drives the Initiator's
// magic-prefix Write error branch.
func TestCoverage_InitiatorMagicWriteFailure(t *testing.T) {
	id, _ := GenerateIdentity()
	rw := &failingRW{failAt: 0, failErr: errors.New("write fail")}
	init := &Initiator{Local: id, Profile: ProfilePermissive}
	_, err := init.Run(rw)
	if err == nil || err.Error() == "" {
		t.Fatal("expected write-failure error")
	}
}

// TestCoverage_ResponderMagicReadFailure drives the magic-prefix
// ReadFull error branch.
func TestCoverage_ResponderMagicReadFailure(t *testing.T) {
	id, _ := GenerateIdentity()
	// Empty reader → io.EOF on ReadFull.
	rw := &emptyRW{}
	rs := &Responder{Local: id, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(rw)
	if err == nil {
		t.Fatal("expected EOF / read error")
	}
}

// TestCoverage_ResponderShortMagicFails drives the magic mismatch
// branch with the correct 4 bytes of NON-magic.
func TestCoverage_ResponderShortMagicFails(t *testing.T) {
	id, _ := GenerateIdentity()
	rw := &bufRW{r: bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF}), w: &bytes.Buffer{}}
	rs := &Responder{Local: id, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(rw)
	if !errors.Is(err, ErrMagicMismatch) {
		t.Fatalf("expected ErrMagicMismatch, got %v", err)
	}
}

// TestCoverage_ResponderTruncatedFirstFrame: after a valid magic,
// truncated stream causes readFrame to fail.
func TestCoverage_ResponderTruncatedFirstFrame(t *testing.T) {
	id, _ := GenerateIdentity()
	// Magic + 2 bytes of a frame header (not enough for the 5-byte header).
	rw := &bufRW{r: bytes.NewReader(append(Magic[:], 0x01, 0x02)), w: &bytes.Buffer{}}
	rs := &Responder{Local: id, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(rw)
	if err == nil {
		t.Fatal("expected truncation error")
	}
}

// TestCoverage_ResponderUnexpectedFirstFrameType: after magic, a
// frame type that isn't HELLO / HELLO_PSK / ALERT.
func TestCoverage_ResponderUnexpectedFirstFrameType(t *testing.T) {
	id, _ := GenerateIdentity()
	var w bytes.Buffer
	body := []byte{0x01}
	// Hand-build envelope with type = FrameData (unexpected for first frame).
	rw := &bufRW{r: bytes.NewReader(append(Magic[:], encodeOuterB(FrameData, body)...)), w: &w}
	rs := &Responder{Local: id, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(rw)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
	if w.Len() == 0 {
		t.Fatal("responder should have written an ALERT")
	}
}

// TestCoverage_ResponderAlertAsFirstFrame: caller sends an ALERT
// as the first frame (responder treats it as a typed error).
func TestCoverage_ResponderAlertAsFirstFrame(t *testing.T) {
	id, _ := GenerateIdentity()
	a := &AlertFrame{Code: AlertPolicyRefused}
	rw := &bufRW{r: bytes.NewReader(append(Magic[:], encodeOuterB(FrameAlert, a.Encode())...)), w: &bytes.Buffer{}}
	rs := &Responder{Local: id, Profile: ProfilePermissive, ReplayCache: NewReplayCache()}
	_, err := rs.Run(rw)
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("expected ErrPolicyRefused, got %v", err)
	}
}

// TestCoverage_InitiatorRunResumeNoSuite: Initiator.Run with invalid
// suite is already covered; this drives Run's suite default with an
// explicit nil Rand + nil Now to traverse the default-fallbacks.
func TestCoverage_InitiatorRunDefaultsThenError(t *testing.T) {
	id, _ := GenerateIdentity()
	rw := &emptyRW{} // Read returns EOF; Initiator's HELLO write will go to discard, then KEM_INIT, then KEM_REPLY read fails.
	init := &Initiator{Local: id, Profile: ProfilePermissive /* Rand nil, Now nil */}
	_, err := init.Run(rw)
	if err == nil {
		t.Fatal("expected error from empty RW")
	}
}

// TestCoverage_SessionRecvAlertBranch: send an ALERT frame to a
// healthy Session; Recv returns the typed error.
func TestCoverage_SessionRecvAlertBranch(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// Inject an ALERT from the server's underlying conn into the
	// client's read stream.
	a := &AlertFrame{Code: AlertHandshakeTimeout, Detail: []byte("test")}
	frame := encodeOuter(FrameAlert, a.Encode())
	if _, err := server.rw.(io.Writer).Write(frame); err != nil {
		t.Fatalf("inject ALERT: %v", err)
	}
	_, err := client.Recv()
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("Recv ALERT translation: %v", err)
	}
}

// TestCoverage_SessionRecvMalformedAlert: an ALERT frame body that
// fails to decode produces a decode-error path inside Recv.
func TestCoverage_SessionRecvMalformedAlert(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// Outer envelope says type=ALERT, length=1, body=0x01 — but ALERT
	// body needs at least 5 bytes (code + u32 detail length).
	bad := encodeOuter(FrameAlert, []byte{0x01})
	if _, err := server.rw.(io.Writer).Write(bad); err != nil {
		t.Fatalf("inject malformed ALERT: %v", err)
	}
	if _, err := client.Recv(); err == nil {
		t.Fatal("malformed ALERT accepted")
	}
}

// TestCoverage_SessionRecvMalformedRekey: similarly for REKEY.
func TestCoverage_SessionRecvMalformedRekey(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	bad := encodeOuter(FrameRekey, []byte{0x01, 0x02}) // REKEY body must be exactly 1 byte
	if _, err := server.rw.(io.Writer).Write(bad); err != nil {
		t.Fatalf("inject malformed REKEY: %v", err)
	}
	if _, err := client.Recv(); err == nil {
		t.Fatal("malformed REKEY accepted")
	}
}

// ---------- helpers ----------

// emptyRW returns io.EOF on every Read; Write succeeds (discards).
type emptyRW struct{}

func (emptyRW) Read([]byte) (int, error)  { return 0, io.EOF }
func (emptyRW) Write(p []byte) (int, error) { return len(p), nil }

// bufRW combines an io.Reader and io.Writer.
type bufRW struct {
	r io.Reader
	w io.Writer
}

func (b *bufRW) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufRW) Write(p []byte) (int, error) { return b.w.Write(p) }

// encodeOuterB is a non-test alias of the helper in aead_test.go so
// this file compiles standalone.
func encodeOuterB(t FrameType, body []byte) []byte {
	return encodeOuter(t, body)
}
