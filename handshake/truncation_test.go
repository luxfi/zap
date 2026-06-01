// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// truncationVictims returns one encoded valid body per frame type.
// Each row's decoder is then tested with every prefix length [0, len)
// to confirm none panic and all return errors.
func truncationVictims(t *testing.T) []struct {
	name   string
	body   []byte
	decode func([]byte) error
} {
	t.Helper()
	pk := bytesPattern(0x77, MLDSA65PubLen)
	hello := &HelloFrame{
		Suite:             SuiteX25519MLKEM,
		PQMode:            PQModePQOnly,
		OfferedSchemes:    []SuiteID{SuiteX25519MLKEM},
		StaticPKInitiator: pk,
	}
	helloBody, err := hello.Encode()
	if err != nil {
		t.Fatalf("hello encode: %v", err)
	}

	kemInit := &KEMInitFrame{}
	kemInitBody := kemInit.Encode()

	kemReply := &KEMReplyFrame{StaticPKResponder: pk}
	kemReplyBody, err := kemReply.Encode()
	if err != nil {
		t.Fatalf("kemreply encode: %v", err)
	}

	auth := &AuthFrame{Role: RoleInitiator, Signature: bytesPattern(0x55, MLDSA65SigLen)}
	authBody, err := auth.Encode()
	if err != nil {
		t.Fatalf("auth encode: %v", err)
	}

	data := &DataFrame{NonceCounter: 7, Ciphertext: []byte("ciphertext")}
	dataBody := data.Encode()

	rekey := &RekeyFrame{Reason: RekeyReasonExplicit}
	rekeyBody := rekey.Encode()

	alert := &AlertFrame{Code: AlertAuthFailed, Detail: []byte("nope")}
	alertBody := alert.Encode()

	helloPSK := &HelloPSKFrame{Suite: SuiteX25519MLKEM}
	helloPSKBody := helloPSK.Encode()

	return []struct {
		name   string
		body   []byte
		decode func([]byte) error
	}{
		{"HELLO", helloBody, func(b []byte) error { _, e := DecodeHello(b); return e }},
		{"KEM_INIT", kemInitBody, func(b []byte) error { _, e := DecodeKEMInit(b); return e }},
		{"KEM_REPLY", kemReplyBody, func(b []byte) error { _, e := DecodeKEMReply(b); return e }},
		{"AUTH", authBody, func(b []byte) error { _, e := DecodeAuth(b); return e }},
		{"DATA", dataBody, func(b []byte) error { _, e := DecodeData(b); return e }},
		{"REKEY", rekeyBody, func(b []byte) error { _, e := DecodeRekey(b); return e }},
		{"ALERT", alertBody, func(b []byte) error { _, e := DecodeAlert(b); return e }},
		{"HELLO_PSK", helloPSKBody, func(b []byte) error { _, e := DecodeHelloPSK(b); return e }},
	}
}

// TestDecodersRejectTruncated walks every prefix of every encoded
// frame and asserts the decoder returns an error without panicking.
// One byte short of complete is the most dangerous boundary for
// off-by-one bugs.
func TestDecodersRejectTruncated(t *testing.T) {
	for _, v := range truncationVictims(t) {
		v := v
		t.Run(v.name, func(t *testing.T) {
			for i := 0; i < len(v.body); i++ {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s decoder panicked at prefix length %d: %v", v.name, i, p)
					}
				}()
				if err := v.decode(v.body[:i]); err == nil {
					// HELLO_PSK with a particular prefix could
					// be invalid; we require an error for every
					// non-complete prefix.
					t.Errorf("%s decoder accepted truncated %d-byte input", v.name, i)
				}
			}
		})
	}
}

// TestReadFrameTruncatedHeader: a stream that yields fewer than 5
// bytes returns io.ErrUnexpectedEOF.
func TestReadFrameTruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x01, 0x00})
	_, _, err := readFrame(buf)
	if err == nil {
		t.Fatal("readFrame accepted short header")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF-ish error, got %v", err)
	}
}

// TestReadFrameTruncatedBody: header announces N body bytes; if the
// stream yields fewer, readFrame fails with EOF.
func TestReadFrameTruncatedBody(t *testing.T) {
	// type=0x05 (DATA), length=0x10 (16 bytes), but only 4 bytes follow
	hdr := []byte{0x05, 0x00, 0x00, 0x00, 0x10}
	body := []byte{0x01, 0x02, 0x03, 0x04}
	buf := bytes.NewReader(append(hdr, body...))
	_, _, err := readFrame(buf)
	if err == nil {
		t.Fatal("readFrame accepted short body")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF-ish error, got %v", err)
	}
}

// TestReadFrameOversizeLengthRejected: announced length > MaxFrameBody
// is rejected before any body bytes are read.
func TestReadFrameOversizeLengthRejected(t *testing.T) {
	// type=0x05, length=2^24+1 (oversize)
	hdr := []byte{0x05, 0x01, 0x00, 0x00, 0x01}
	buf := bytes.NewReader(hdr)
	_, _, err := readFrame(buf)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
}

// TestWriteFrameOversizeBodyRejected: writeFrame refuses an
// in-memory body that exceeds the cap so it cannot land on the wire.
func TestWriteFrameOversizeBodyRejected(t *testing.T) {
	var buf bytes.Buffer
	body := make([]byte, MaxFrameBody+1)
	err := writeFrame(&buf, FrameData, body)
	if !errors.Is(err, ErrDecodeError) {
		t.Fatalf("expected ErrDecodeError, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("oversize body was partially written")
	}
}
