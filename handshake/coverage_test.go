// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Targeted tests to close the remaining coverage gaps in the
// handshake package. Each test names the function:line it covers.

package handshake

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// ---------- identity.go ----------

// Covers Identity.ID nil-receiver branch (identity.go:28).
func TestCoverage_IdentityIDNil(t *testing.T) {
	var id *Identity
	if id.ID() != ([IDLen]byte{}) {
		t.Fatal("nil receiver should return zero ID")
	}
	id2 := &Identity{}
	if id2.ID() != ([IDLen]byte{}) {
		t.Fatal("nil PublicKey should return zero ID")
	}
}

// Covers Identity.PublicBytes nil-receiver branch (identity.go:37).
func TestCoverage_IdentityPublicBytesNil(t *testing.T) {
	var id *Identity
	if id.PublicBytes() != nil {
		t.Fatal("nil receiver should return nil")
	}
	id2 := &Identity{}
	if id2.PublicBytes() != nil {
		t.Fatal("nil PublicKey should return nil")
	}
}

// Covers IdentityFromPrivate (identity.go:64).
func TestCoverage_IdentityFromPrivate(t *testing.T) {
	gen, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if _, err := IdentityFromPrivate(nil); err == nil {
		t.Fatal("nil priv should fail")
	}
	id, err := IdentityFromPrivate(gen.PrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivate: %v", err)
	}
	if id.ID() != gen.ID() {
		t.Fatal("identity round-trip ID mismatch")
	}
}

// Covers GenerateIdentityFrom with explicit nil reader (identity.go:52).
func TestCoverage_GenerateIdentityFromNilReader(t *testing.T) {
	id, err := GenerateIdentityFrom(nil)
	if err != nil {
		t.Fatalf("GenerateIdentityFrom(nil): %v", err)
	}
	if id == nil || id.PrivateKey == nil {
		t.Fatal("nil reader fallback failed")
	}
}

// Covers Sign nil-receiver / no-private-key branches (identity.go:91).
func TestCoverage_SignNilReceiver(t *testing.T) {
	var id *Identity
	if _, err := id.Sign(nil, [TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM); err == nil {
		t.Fatal("nil receiver Sign should fail")
	}
	id2 := &Identity{}
	if _, err := id2.Sign(nil, [TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM); err == nil {
		t.Fatal("nil-PrivateKey Sign should fail")
	}
}

// Covers SignDeterministic nil-receiver / no-private-key (identity.go:121).
func TestCoverage_SignDeterministicNilReceiver(t *testing.T) {
	var id *Identity
	if _, err := id.SignDeterministic([TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM); err == nil {
		t.Fatal("nil receiver SignDeterministic should fail")
	}
}

// Covers VerifyAuth nil-receiver / wrong-length-sig (identity.go:139).
func TestCoverage_VerifyAuthNilAndLength(t *testing.T) {
	var id *Identity
	err := id.VerifyAuth([TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM, make([]byte, MLDSA65SigLen))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("nil receiver should return ErrAuthFailed, got %v", err)
	}
	gen, _ := GenerateIdentity()
	err = gen.VerifyAuth([TranscriptLen]byte{}, RoleInitiator, SuiteX25519MLKEM, []byte{0x01})
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong-length sig should return ErrAuthFailed, got %v", err)
	}
}

// ---------- session.go ----------

// Covers Session.Role accessor (session.go:406).
func TestCoverage_SessionRole(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()
	if client.Role() != RoleInitiator {
		t.Fatalf("client role = %v, want Initiator", client.Role())
	}
	if server.Role() != RoleResponder {
		t.Fatalf("server role = %v, want Responder", server.Role())
	}
}

// Covers newSession invalid role branch (session.go:70).
func TestCoverage_NewSessionInvalidRole(t *testing.T) {
	var buf bytes.Buffer
	_, err := newSession(struct {
		io.Reader
		io.Writer
	}{&buf, &buf}, AuthRole(0x99), [IDLen]byte{}, SuiteX25519MLKEM, SessionKeys{}, time.Now())
	if err == nil {
		t.Fatal("newSession with invalid role should fail")
	}
}

// Covers Send oversize payload branch (session.go:145).
func TestCoverage_SendOversize(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// MaxFrameBody is 16 MiB; outerLen = NonceCtrLen(8) + 4 + ct(payload+16).
	// A payload of MaxFrameBody bytes gives outerLen > MaxFrameBody → reject.
	huge := make([]byte, MaxFrameBody)
	err := client.Send(huge)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("oversize payload should return ErrDecodeError, got %v", err)
	}
}

// Covers Recv on closed session (session.go:193) and Rekey on closed (session.go:280).
func TestCoverage_RecvAndRekeyAfterClose(t *testing.T) {
	client, server := pqPair(t)
	_ = server.Close()
	_ = client.Close()
	if _, err := client.Recv(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Recv after close: %v", err)
	}
	if err := client.Rekey(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Rekey after close: %v", err)
	}
}

// Covers Recv unexpected-frame-type branch (session.go:193 default case).
func TestCoverage_RecvUnexpectedFrameType(t *testing.T) {
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	// Send a HELLO frame mid-session (totally unexpected steady-state).
	body := []byte{0x00, 0x01, 0x02}
	if _, err := server.rw.(net.Conn).Write(encodeOuter(FrameHello, body)); err != nil {
		t.Fatalf("write hello mid-session: %v", err)
	}
	if _, err := client.Recv(); !errors.Is(err, ErrDecodeError) {
		t.Fatalf("Recv on unexpected frame type returned %v", err)
	}
}

// ---------- frames.go ----------

// Covers expectFrame mismatch branch (frames.go:447).
func TestCoverage_ExpectFrameWrongType(t *testing.T) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, FrameRekey, []byte{0x01})
	_, err := expectFrame(&buf, FrameData)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expectFrame wrong type returned %v", err)
	}
}

// Covers expectFrame translating ALERT body to typed error.
func TestCoverage_ExpectFrameAlertBecomesTypedError(t *testing.T) {
	var buf bytes.Buffer
	a := &AlertFrame{Code: AlertPolicyRefused}
	_ = writeFrame(&buf, FrameAlert, a.Encode())
	_, err := expectFrame(&buf, FrameData)
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("expectFrame ALERT translation: %v", err)
	}
}

// Covers writeAlert wrapper (frames.go:467) — the variant that doesn't
// take an error and emits a hand-specified code.
func TestCoverage_WriteAlert(t *testing.T) {
	var buf bytes.Buffer
	err := writeAlert(&buf, AlertReplayDetected, "detail")
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("writeAlert returned %v", err)
	}
	// Frame should have been emitted to buf.
	if buf.Len() == 0 {
		t.Fatal("writeAlert wrote no bytes")
	}
}

// Covers HelloFrame.Encode oversize-pk branch.
func TestCoverage_HelloEncodeBadPubKey(t *testing.T) {
	h := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
		StaticPKInitiator: []byte{0x01}, // wrong size
	}
	if _, err := h.Encode(); !errors.Is(err, ErrDecodeError) {
		t.Fatalf("HelloFrame.Encode bad-pk: %v", err)
	}
}

// Covers KEMReplyFrame.Encode wrong-size pk branch.
func TestCoverage_KEMReplyEncodeBadPubKey(t *testing.T) {
	k := &KEMReplyFrame{StaticPKResponder: []byte{0x01}}
	if _, err := k.Encode(); !errors.Is(err, ErrDecodeError) {
		t.Fatalf("KEMReplyFrame.Encode bad-pk: %v", err)
	}
}

// Covers AuthFrame.Encode bad role branch.
func TestCoverage_AuthEncodeBadRole(t *testing.T) {
	a := &AuthFrame{Role: 0x99, Signature: make([]byte, MLDSA65SigLen)}
	if _, err := a.Encode(); !errors.Is(err, ErrDecodeError) {
		t.Fatalf("AuthFrame.Encode bad role: %v", err)
	}
}

// Covers DecodeAuth bad role branch (frames.go:198).
func TestCoverage_DecodeAuthBadRole(t *testing.T) {
	body := make([]byte, 1+MLDSA65SigLen)
	body[0] = 0x99
	if _, err := DecodeAuth(body); !errors.Is(err, ErrDecodeError) {
		t.Fatalf("DecodeAuth bad role: %v", err)
	}
}

// Covers frameBufBucket / getFrameBuf / putFrameBuf large-overflow path.
func TestCoverage_FrameBufBucketOverflow(t *testing.T) {
	// MaxFrameBody+5 fits in the largest bucket (2^28); test the
	// overflow path with a total > 2^28.
	huge := MaxFrameBody + 5
	if frameBufBucket(huge) < 0 {
		// already overflowed — try a tiny one to ensure normal path works
		if frameBufBucket(32) < 0 {
			t.Fatal("frameBufBucket(32) returned -1")
		}
	}
	// Force the overflow branch.
	if frameBufBucket(1<<30) >= 0 {
		t.Fatal("frameBufBucket should return -1 for huge sizes")
	}
	bufP := getFrameBuf(1 << 30)
	if bufP == nil {
		t.Fatal("getFrameBuf returned nil")
	}
	putFrameBuf(bufP, 1<<30) // no-op when bucket == -1
}

// ---------- transcript.go accessor edges (transcript.go:128/139/146) ----------

func TestCoverage_TranscriptStageAccessors(t *testing.T) {
	tr := NewTranscript(SuiteX25519MLKEM)

	// Before any absorb: all accessors return zero.
	if tr.H0() != ([TranscriptLen]byte{}) {
		t.Fatal("H0 before absorb should be zero")
	}
	if tr.H1() != ([TranscriptLen]byte{}) {
		t.Fatal("H1 before absorb should be zero")
	}
	if tr.H2() != ([TranscriptLen]byte{}) {
		t.Fatal("H2 before absorb should be zero")
	}

	tr.AbsorbHello([]byte("h"))
	// At H_0 stage, H_1 and H_2 still return zero.
	if tr.H1() != ([TranscriptLen]byte{}) {
		t.Fatal("H1 at H0 stage should be zero")
	}
	if tr.H2() != ([TranscriptLen]byte{}) {
		t.Fatal("H2 at H0 stage should be zero")
	}

	tr.AbsorbKEM([]byte("i"), []byte("r"))
	// At H_1 stage, H_0 returns zero (we no longer hold it) and H_2 zero.
	if tr.H0() != ([TranscriptLen]byte{}) {
		t.Fatal("H0 after stage advance should be zero")
	}
	if tr.H2() != ([TranscriptLen]byte{}) {
		t.Fatal("H2 at H1 stage should be zero")
	}

	pkI := bytesPattern(0xAA, MLDSA65PubLen)
	pkR := bytesPattern(0xBB, MLDSA65PubLen)
	tr.FinishFull(pkI, pkR, []SuiteID{SuiteX25519MLKEM})
	if tr.H2() == ([TranscriptLen]byte{}) {
		t.Fatal("H2 after FinishFull should be non-zero")
	}
}

// ---------- responder.go acceptsSuite (responder.go:369) ----------

func TestCoverage_ResponderAcceptsSuiteAllowlist(t *testing.T) {
	rs := &Responder{AcceptedSuites: []SuiteID{SuiteX25519MLKEM}}
	if !rs.acceptsSuite(SuiteX25519MLKEM) {
		t.Fatal("0x01 should be accepted")
	}
	if rs.acceptsSuite(0x02) {
		t.Fatal("0x02 should not be accepted when not in list")
	}
	rsEmpty := &Responder{}
	if !rsEmpty.acceptsSuite(SuiteX25519MLKEM) {
		t.Fatal("empty allowlist should accept default suite")
	}
	if rsEmpty.acceptsSuite(0xFE) {
		t.Fatal("empty allowlist should reject non-default")
	}
}

// ---------- replay.go CheckTimestamp negative branches ----------

func TestCoverage_ReplayCheckTimestampNegativeNow(t *testing.T) {
	c := NewReplayCache()
	// Force a "negative now" by overriding the clock.
	c.now = func() time.Time { return time.Unix(-1, 0) }
	if err := c.CheckTimestamp(0); err == nil {
		t.Fatal("negative now should trip refusal path")
	}
}

// ---------- kdf.go expand panic-on-short-read (kdf.go:172) ----------

// TestCoverage_ExpandMatchesHandHKDF cross-checks our expand() helper
// against a direct hkdf.Expand call on the same PRK/info to prove
// the helper is a faithful wrapper, not just any function that fills
// the output buffer.
func TestCoverage_ExpandMatchesHandHKDF(t *testing.T) {
	prk := bytesPattern(0x01, 32)
	got := make([]byte, 16)
	expand(prk, []byte("test"), got)

	want := readExpand(t, prk, []byte("test"), 16)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("expand byte %d mismatch: got %02x want %02x", i, got[i], want[i])
		}
	}
}

// TestCoverage_ExpandVariedSizes runs expand with a range of output
// lengths to drive any internal buffer-sizing branches in HKDF.
func TestCoverage_ExpandVariedSizes(t *testing.T) {
	prk := bytesPattern(0x22, 32)
	for _, n := range []int{1, 4, 32, 64, 65 /* spans 2 SHA3 blocks */, 200} {
		out := make([]byte, n)
		expand(prk, []byte("varied"), out)
		// Determinism: a second call with the same inputs returns the same bytes.
		out2 := make([]byte, n)
		expand(prk, []byte("varied"), out2)
		for i := 0; i < n; i++ {
			if out[i] != out2[i] {
				t.Fatalf("expand not deterministic at size %d byte %d", n, i)
			}
		}
	}
}
