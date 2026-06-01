// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Comprehensive coverage of the decomplected NodeID handshake and
// correlation-header codecs. These previously lived as duplicated
// inline blocks across handleConn, ConnectDirect, and Call; now
// there's one encoder and one decoder for each, fully unit-testable.

package zap

import (
	"bytes"
	"strings"
	"testing"
)

// ---------- NodeID handshake ----------

func TestCodec_NodeIDHandshakeRoundTrip(t *testing.T) {
	cases := []string{
		"A",
		"node-42",
		"some-very-long-but-acceptable-id-up-to-60-bytes",
		strings.Repeat("x", maxNodeIDLen), // exactly at the cap
	}
	for _, want := range cases {
		t.Run(want, func(t *testing.T) {
			data := EncodeNodeIDHandshake(want)
			got, ok := DecodeNodeIDHandshake(data)
			if !ok {
				t.Fatalf("DecodeNodeIDHandshake !ok for %q", want)
			}
			if got != want {
				t.Fatalf("round-trip mismatch: got %q want %q", got, want)
			}
		})
	}
}

func TestCodec_NodeIDHandshakeTruncatesOverLong(t *testing.T) {
	// IDs longer than maxNodeIDLen are truncated by the encoder; the
	// decoder reads back exactly maxNodeIDLen bytes.
	long := strings.Repeat("z", maxNodeIDLen+10)
	data := EncodeNodeIDHandshake(long)
	got, ok := DecodeNodeIDHandshake(data)
	if !ok {
		t.Fatal("Decode failed on over-long encoder input")
	}
	if len(got) != maxNodeIDLen {
		t.Fatalf("truncation: got %d bytes, want %d", len(got), maxNodeIDLen)
	}
}

func TestCodec_NodeIDHandshakeDecodeRejectsGarbage(t *testing.T) {
	if _, ok := DecodeNodeIDHandshake(nil); ok {
		t.Fatal("nil should not decode")
	}
	if _, ok := DecodeNodeIDHandshake([]byte{0x01, 0x02}); ok {
		t.Fatal("short blob should not decode")
	}
	if _, ok := DecodeNodeIDHandshake(bytes.Repeat([]byte{0xFF}, nodeIDHandshakeSize)); ok {
		t.Fatal("bad-magic blob should not decode")
	}
}

func TestCodec_NodeIDHandshakeDecodeRejectsZeroLen(t *testing.T) {
	// A valid-magic message with length field = 0 must return !ok.
	data := EncodeNodeIDHandshake("")
	if _, ok := DecodeNodeIDHandshake(data); ok {
		t.Fatal("zero-length id should not decode")
	}
}

// ---------- Correlation header ----------

func TestCodec_WrapUnwrapCorrelatedRoundTrip(t *testing.T) {
	body := []byte("hello, world")
	const (
		reqID = uint32(0xDEADBEEF)
		flag  = ReqFlagReq
	)
	wrapped := WrapCorrelated(reqID, flag, body)
	if len(wrapped) != correlatedHeaderSize+len(body) {
		t.Fatalf("wrapped length %d, want %d", len(wrapped), correlatedHeaderSize+len(body))
	}
	gotID, gotFlag, gotBody, ok := UnwrapCorrelated(wrapped)
	if !ok {
		t.Fatal("Unwrap !ok on valid wrapped")
	}
	if gotID != reqID || gotFlag != flag {
		t.Fatalf("header mismatch: id=%x flag=%x", gotID, gotFlag)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body mismatch")
	}
}

func TestCodec_WrapCorrelatedEmptyBody(t *testing.T) {
	wrapped := WrapCorrelated(1, ReqFlagResp, nil)
	if len(wrapped) != correlatedHeaderSize {
		t.Fatalf("empty wrap length %d, want %d", len(wrapped), correlatedHeaderSize)
	}
	_, _, body, ok := UnwrapCorrelated(wrapped)
	if !ok {
		t.Fatal("Unwrap on empty-body wrapped !ok")
	}
	if len(body) != 0 {
		t.Fatalf("empty body got %d bytes", len(body))
	}
}

func TestCodec_UnwrapCorrelatedRejectsShort(t *testing.T) {
	if _, _, _, ok := UnwrapCorrelated(nil); ok {
		t.Fatal("nil should not unwrap")
	}
	if _, _, _, ok := UnwrapCorrelated([]byte{0x00, 0x01, 0x02, 0x03}); ok {
		t.Fatal("4-byte input should not unwrap")
	}
	if _, _, _, ok := UnwrapCorrelated(bytes.Repeat([]byte{0xFF}, correlatedHeaderSize-1)); ok {
		t.Fatal("7-byte input should not unwrap")
	}
}

func TestCodec_UnwrapCorrelatedRejectsUnknownFlag(t *testing.T) {
	// A header with an unrecognised flag value MUST return !ok so
	// callers fall through to the regular-message path.
	wrapped := WrapCorrelated(7, 0xABCDEF, []byte("data"))
	// WrapCorrelated will happily encode any flag; Unwrap must reject.
	if _, _, _, ok := UnwrapCorrelated(wrapped); ok {
		t.Fatal("unknown flag should not unwrap as correlated")
	}
}

// ---------- Cross-codec / integration ----------

// TestCodec_CorrelatedWrappedZAPMessageThroughBothCodecs builds a
// valid ZAP message, wraps it as a Call request, unwraps, and
// reparses the inner ZAP message. Verifies the codec stack is
// composable end-to-end.
func TestCodec_CorrelatedWrappedZAPMessageThroughBothCodecs(t *testing.T) {
	b := NewBuilder(0)
	obj := b.StartObject(4)
	obj.SetUint32(0, 0xCAFEBABE)
	obj.FinishAsRoot()
	body := b.Finish()

	wrapped := WrapCorrelated(99, ReqFlagReq, body)
	reqID, flag, gotBody, ok := UnwrapCorrelated(wrapped)
	if !ok {
		t.Fatal("Unwrap failed")
	}
	if reqID != 99 || flag != ReqFlagReq {
		t.Fatal("header mismatch")
	}
	msg, err := Parse(gotBody)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if msg.Root().Uint32(0) != 0xCAFEBABE {
		t.Fatal("payload mismatch")
	}
}
