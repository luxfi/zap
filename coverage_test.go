// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Coverage tests for the zap-root package: schema builders, EVM
// types, builder helpers, conn_pq accessors, attestation helpers.

package zap

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/zap/handshake"
)

// ---------- schema.go ----------

func TestCoverage_SchemaAddEnum(t *testing.T) {
	s := NewSchema("test")
	e := &Enum{Name: "Color", Type: TypeUint8, Values: map[string]uint64{"RED": 0, "GREEN": 1, "BLUE": 2}}
	s.AddEnum(e)
	if got, ok := s.Enums["Color"]; !ok || got != e {
		t.Fatal("AddEnum did not store the enum")
	}
}

func TestCoverage_TypeSize(t *testing.T) {
	cases := []struct {
		t    Type
		want int
	}{
		{TypeVoid, 0},
		{TypeBool, 1}, {TypeInt8, 1}, {TypeUint8, 1},
		{TypeInt16, 2}, {TypeUint16, 2},
		{TypeInt32, 4}, {TypeUint32, 4}, {TypeFloat32, 4},
		{TypeInt64, 8}, {TypeUint64, 8}, {TypeFloat64, 8},
		{TypeText, 8}, {TypeBytes, 8},
		{TypeList, 8},
		{TypeStruct, 4},
		{Type(0xFF), 0}, // default branch
	}
	for _, c := range cases {
		if got := TypeSize(c.t); got != c.want {
			t.Errorf("TypeSize(%v) = %d, want %d", c.t, got, c.want)
		}
	}
}

func TestCoverage_StructBuilderAllTypes(t *testing.T) {
	st := NewStructBuilder("Everything").
		Bool("flag").
		Int32("i32").
		Int64("i64").
		Uint32("u32").
		Uint64("u64").
		Float64("f64").
		Text("s").
		Bytes("b").
		List("xs", TypeUint32).
		Struct("nested", "Inner").
		Build()

	if st.Name != "Everything" {
		t.Fatal("name mismatch")
	}
	if len(st.Fields) != 10 {
		t.Fatalf("field count %d, want 10", len(st.Fields))
	}
	if st.Size == 0 {
		t.Fatal("size zero")
	}
}

// ---------- evm.go ----------

func TestCoverage_EVMAddressRoundTrip(t *testing.T) {
	addr, err := AddressFromHex("0x" + strings.Repeat("ab", AddressSize))
	if err != nil {
		t.Fatalf("AddressFromHex: %v", err)
	}
	if addr.IsZero() {
		t.Fatal("addr should not be zero")
	}
	if ZeroAddress != ([AddressSize]byte{}) {
		t.Fatal("ZeroAddress should be zero")
	}
	if !ZeroAddress.IsZero() {
		t.Fatal("ZeroAddress.IsZero() false")
	}
	hex := addr.Hex()
	if !strings.HasPrefix(hex, "0x") || len(hex) != 2+AddressSize*2 {
		t.Fatalf("Hex format: %q", hex)
	}
	if addr.String() != hex {
		t.Fatal("String != Hex")
	}

	// Without prefix.
	addr2, err := AddressFromHex(strings.Repeat("cd", AddressSize))
	if err != nil {
		t.Fatalf("AddressFromHex no-prefix: %v", err)
	}
	if addr2.IsZero() {
		t.Fatal("addr2 should not be zero")
	}

	// Bad length.
	if _, err := AddressFromHex("0x01"); err == nil {
		t.Fatal("short hex accepted")
	}
}

func TestCoverage_EVMHashRoundTrip(t *testing.T) {
	h, err := HashFromHex("0x" + strings.Repeat("ef", HashSize))
	if err != nil {
		t.Fatalf("HashFromHex: %v", err)
	}
	if h.IsZero() {
		t.Fatal("h should not be zero")
	}
	if !ZeroHash.IsZero() {
		t.Fatal("ZeroHash.IsZero false")
	}
	if h.String() != h.Hex() {
		t.Fatal("String != Hex")
	}

	// Without prefix.
	h2, err := HashFromHex(strings.Repeat("12", HashSize))
	if err != nil {
		t.Fatalf("HashFromHex no-prefix: %v", err)
	}
	_ = h2

	// Bad length.
	if _, err := HashFromHex("0x01"); err == nil {
		t.Fatal("short hex accepted")
	}
}

// ---------- conn_pq.go accessors ----------

// Drives LocalAddr, RemoteAddr, SetDeadline, SetReadDeadline,
// SetWriteDeadline on a pqConn so they aren't 0% any more.
func TestCoverage_PQConnNetConnInterface(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	clientID, _ := handshake.GenerateIdentity()
	serverID, _ := handshake.GenerateIdentity()

	type result struct {
		c   net.Conn
		err error
	}
	srvCh := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		r := &handshake.Responder{
			Local:       serverID,
			Profile:     handshake.ProfileStrictPQ,
			ReplayCache: handshake.NewReplayCache(),
		}
		sess, err := r.Run(raw)
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		srvCh <- result{WrapPQ(raw, sess), nil}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	init := &handshake.Initiator{
		Local:    clientID,
		Expected: &handshake.Identity{PublicKey: serverID.PublicKey},
		Profile:  handshake.ProfileStrictPQ,
	}
	sess, err := init.Run(raw)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	client := WrapPQ(raw, sess)
	t.Cleanup(func() { _ = client.Close() })

	r := <-srvCh
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	t.Cleanup(func() { _ = r.c.Close() })

	if client.LocalAddr() == nil {
		t.Error("LocalAddr nil")
	}
	if client.RemoteAddr() == nil {
		t.Error("RemoteAddr nil")
	}
	future := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(future); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := client.SetReadDeadline(future); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := client.SetWriteDeadline(future); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

// ---------- pq_attestation.go ----------

func TestCoverage_TLSCertFingerprintFromBytes(t *testing.T) {
	got := TLSCertFingerprintFromBytes([]byte("dummy-der-bytes"))
	if got == ([32]byte{}) {
		t.Fatal("fingerprint should not be zero for non-empty input")
	}
	// Stable across calls.
	again := TLSCertFingerprintFromBytes([]byte("dummy-der-bytes"))
	if got != again {
		t.Fatal("fingerprint not stable")
	}
}
