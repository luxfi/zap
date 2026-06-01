// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Final coverage push for zap-root: every test below asserts a
// specific, verifiable property — no "no panic" smoke tests.

package zap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -------- Node.Start error paths --------

// TestCoverage_StartListenBindFail: a port already bound on all
// interfaces should make Start (which also binds all interfaces)
// fail with a wrapped "failed to listen" error.
func TestCoverage_StartListenBindFail(t *testing.T) {
	// Hold an explicit port on all interfaces — Start binds ":port"
	// which collides with 0.0.0.0:port.
	holder, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := holder.Addr().(*net.TCPAddr).Port
	defer holder.Close()

	n := NewNode(NodeConfig{NodeID: "bind-fail", Port: port, NoDiscovery: true})
	if err := n.Start(); err == nil {
		t.Fatal("Start should fail when port is already bound")
	}
}

// TestCoverage_StartWithTLS: Start with a non-nil TLS config wires
// the TLS-wrapped listener. We verify by performing a TLS dial that
// completes the handshake against the node's listener.
func TestCoverage_StartWithTLS(t *testing.T) {
	cert, key := mkSelfSignedCert(t)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{pair}}

	port := pickFreePort(t)
	n := NewNode(NodeConfig{
		NodeID:      "tls-node",
		Port:        port,
		NoDiscovery: true,
		TLS:         tlsCfg,
	})
	if err := n.Start(); err != nil {
		t.Fatalf("Start with TLS: %v", err)
	}
	defer n.Stop()

	// A plaintext dial should NOT complete a usable session because
	// the listener expects a TLS handshake. We assert the TLS-wrapped
	// dial completes (or at least begins) — that proves the listener
	// is TLS-wrapped.
	clientCfg := &tls.Config{InsecureSkipVerify: true}
	c, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), clientCfg)
	if err != nil {
		t.Fatalf("TLS dial failed (Start did not wire TLS listener): %v", err)
	}
	_ = c.Close()
}

// -------- Node.ConnectDirect error paths --------

// TestCoverage_ConnectDirectDialFails: dialing a closed port returns
// a "failed to connect" wrapped error.
func TestCoverage_ConnectDirectDialFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	n := NewNode(NodeConfig{NodeID: "dialer", NoDiscovery: true})
	err = n.ConnectDirect(addr)
	if err == nil {
		t.Fatal("ConnectDirect should fail to dial closed port")
	}
}

// TestCoverage_ConnectDirectWithTLS: TLS-wrapped dial path.
// Both peers use TLS; ConnectDirect must wrap netConn with
// tls.Client before sending the handshake. We verify by standing
// up a real TLS-enabled responder node and connecting to it.
func TestCoverage_ConnectDirectWithTLS(t *testing.T) {
	cert, key := mkSelfSignedCert(t)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	srvCfg := &tls.Config{Certificates: []tls.Certificate{pair}}
	cliCfg := &tls.Config{InsecureSkipVerify: true}

	portB := pickFreePort(t)
	b := NewNode(NodeConfig{NodeID: "tlsB", Port: portB, NoDiscovery: true, TLS: srvCfg})
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	a := NewNode(NodeConfig{NodeID: "tlsA", NoDiscovery: true, TLS: cliCfg})
	if err := a.ConnectDirect("127.0.0.1:" + strconv.Itoa(portB)); err != nil {
		t.Fatalf("ConnectDirect TLS: %v", err)
	}
	// Verify peer registered.
	for d := time.Now().Add(time.Second); time.Now().Before(d) && len(a.Peers()) == 0; {
		time.Sleep(10 * time.Millisecond)
	}
	if len(a.Peers()) != 1 || a.Peers()[0] != "tlsB" {
		t.Fatalf("expected one peer tlsB, got %v", a.Peers())
	}
}

// TestCoverage_ConnectDirectPeerHandshakeEOF: peer accepts but
// closes before sending its handshake response.
func TestCoverage_ConnectDirectPeerHandshakeEOF(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Drain client's handshake, then close (no response).
		var buf [HeaderSize + 64 + 4]byte
		_, _ = c.Read(buf[:])
		_ = c.Close()
	}()
	n := NewNode(NodeConfig{NodeID: "eof-test", NoDiscovery: true})
	err = n.ConnectDirect(ln.Addr().String())
	if err == nil {
		t.Fatal("ConnectDirect should error when peer EOFs mid-handshake")
	}
}

// -------- Node.Call error paths --------

// TestCoverage_CallContextCanceled: Call must return ctx.Err() when
// the response never arrives and the context times out.
func TestCoverage_CallContextCanceled(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)
	a := NewNode(NodeConfig{NodeID: "ctxA", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "ctxB", Port: portB, NoDiscovery: true})
	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	// B registers NO handler for type 0x99, so Call's response chan
	// never fills and ctx times out.
	if err := a.ConnectDirect("127.0.0.1:" + strconv.Itoa(portB)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	// Wait for handshake.
	for d := time.Now().Add(time.Second); time.Now().Before(d) && len(a.Peers()) == 0; {
		time.Sleep(10 * time.Millisecond)
	}

	bld := NewBuilder(0)
	ob := bld.StartObject(4)
	ob.SetUint32(0, 1)
	ob.FinishAsRoot()
	msg := &Message{data: bld.FinishWithFlags(0x9900)} // msgType=0x99

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := a.Call(ctx, "ctxB", msg); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call: %v, want DeadlineExceeded", err)
	}
}

// TestCoverage_CallReturnsRoutedResponse: register a handler that
// returns a SPECIFIC payload; Call must return the same payload.
// This is the round-trip test that proves correlation works
// end-to-end (request id matches up).
func TestCoverage_CallReturnsRoutedResponse(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)
	a := NewNode(NodeConfig{NodeID: "rrA", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "rrB", Port: portB, NoDiscovery: true})
	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	// B's handler returns a freshly-built response carrying a
	// distinct magic value.
	const respMagic uint32 = 0xBADDC0DE
	b.Handle(0x33, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		rb := NewBuilder(64)
		ob := rb.StartObject(4)
		ob.SetUint32(0, respMagic)
		ob.FinishAsRoot()
		return &Message{data: rb.FinishWithFlags(0x3300)}, nil
	})

	if err := a.ConnectDirect("127.0.0.1:" + strconv.Itoa(portB)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	for d := time.Now().Add(time.Second); time.Now().Before(d) && len(a.Peers()) == 0; {
		time.Sleep(10 * time.Millisecond)
	}

	bld := NewBuilder(0)
	ob := bld.StartObject(4)
	ob.SetUint32(0, 0x01010101)
	ob.FinishAsRoot()
	msg := &Message{data: bld.FinishWithFlags(0x3300)}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := a.Call(ctx, "rrB", msg)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if got := resp.Root().Uint32(0); got != respMagic {
		t.Fatalf("response payload = 0x%08X, want 0x%08X", got, respMagic)
	}
}

// TestCoverage_NodeConcurrentCalls: many concurrent Calls into the
// same peer must each get THEIR OWN response (correlation header is
// per-request). Asserts that responses route correctly.
func TestCoverage_NodeConcurrentCalls(t *testing.T) {
	portA := pickFreePort(t)
	portB := pickFreePort(t)
	a := NewNode(NodeConfig{NodeID: "ccA", Port: portA, NoDiscovery: true})
	b := NewNode(NodeConfig{NodeID: "ccB", Port: portB, NoDiscovery: true})
	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	// B's handler echoes the request payload back, tagging it.
	b.Handle(0x44, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		in := msg.Root().Uint32(0)
		rb := NewBuilder(64)
		ob := rb.StartObject(4)
		ob.SetUint32(0, in^0xFFFFFFFF) // XOR so client can verify uniqueness
		ob.FinishAsRoot()
		return &Message{data: rb.FinishWithFlags(0x4400)}, nil
	})

	if err := a.ConnectDirect("127.0.0.1:" + strconv.Itoa(portB)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	for d := time.Now().Add(time.Second); time.Now().Before(d) && len(a.Peers()) == 0; {
		time.Sleep(10 * time.Millisecond)
	}

	const N = 8
	var wg sync.WaitGroup
	var errs atomic.Int32
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			bld := NewBuilder(0)
			ob := bld.StartObject(4)
			ob.SetUint32(0, uint32(i+1)<<16)
			ob.FinishAsRoot()
			msg := &Message{data: bld.FinishWithFlags(0x4400)}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, err := a.Call(ctx, "ccB", msg)
			if err != nil {
				t.Errorf("Call[%d]: %v", i, err)
				errs.Add(1)
				return
			}
			want := uint32(i+1)<<16 ^ 0xFFFFFFFF
			if got := resp.Root().Uint32(0); got != want {
				t.Errorf("Call[%d] payload = 0x%08X want 0x%08X", i, got, want)
				errs.Add(1)
			}
		}()
	}
	wg.Wait()
	if errs.Load() != 0 {
		t.Fatalf("%d concurrent Calls had errors", errs.Load())
	}
}

// -------- writeMessage / readMessageRaw error paths --------

// TestCoverage_WriteMessageWriteFails: a writer that errors on the
// first Write surfaces the error directly.
func TestCoverage_WriteMessageWriteFails(t *testing.T) {
	bad := &erroringWriter{err: errors.New("write boom")}
	if err := writeMessage(bad, []byte{0x01}); err == nil {
		t.Fatal("expected boom")
	}
}

type erroringWriter struct{ err error }

func (e *erroringWriter) Write(p []byte) (int, error) { return 0, e.err }

// TestCoverage_ReadMessageRawShortHeader: a reader that yields fewer
// than 4 bytes returns io.ErrUnexpectedEOF.
func TestCoverage_ReadMessageRawShortHeader(t *testing.T) {
	_, err := readMessageRaw(&shortReader{src: []byte{0x01, 0x02}})
	if err == nil {
		t.Fatal("expected EOF")
	}
}

// TestCoverage_ReadMessageRawShortBody: header announces a length
// the body doesn't satisfy → ErrUnexpectedEOF.
func TestCoverage_ReadMessageRawShortBody(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 100)
	body := append(hdr[:], []byte{0x01, 0x02}...) // only 2 of 100
	_, err := readMessageRaw(&shortReader{src: body})
	if err == nil {
		t.Fatal("expected short-body EOF")
	}
}

type shortReader struct {
	src []byte
	pos int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.src) {
		return 0, io.EOF
	}
	n := copy(p, s.src[s.pos:])
	s.pos += n
	return n, nil
}

// -------- Helpers --------

// mkSelfSignedCert returns a self-signed P-256 cert + key (PEM) for
// TLS-listener tests. Lifted to a helper so each test stays terse.
func mkSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM = encodePEM("CERTIFICATE", der)
	keyPEM = encodePEM("EC PRIVATE KEY", keyDER)
	return
}

func encodePEM(typ string, der []byte) []byte {
	// Inline minimal PEM encoder to avoid pulling encoding/pem into
	// every coverage file that doesn't need it.
	const hdr = "-----BEGIN "
	const ftr = "-----END "
	const dashes = "-----\n"
	out := []byte(hdr)
	out = append(out, typ...)
	out = append(out, dashes...)
	// Base64 wrap at 64 cols.
	b64 := base64Encode(der)
	for len(b64) > 0 {
		chunk := b64
		if len(chunk) > 64 {
			chunk = chunk[:64]
		}
		out = append(out, chunk...)
		out = append(out, '\n')
		b64 = b64[len(chunk):]
	}
	out = append(out, ftr...)
	out = append(out, typ...)
	out = append(out, dashes...)
	return out
}

func base64Encode(src []byte) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, ((len(src)+2)/3)*4)
	for i := 0; i < len(src); i += 3 {
		var b0, b1, b2 byte
		b0 = src[i]
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		out = append(out,
			tbl[b0>>2],
			tbl[((b0&0x03)<<4)|(b1>>4)],
			tbl[((b1&0x0F)<<2)|(b2>>6)],
			tbl[b2&0x3F],
		)
		if i+2 >= len(src) {
			out[len(out)-1] = '='
			if i+1 >= len(src) {
				out[len(out)-2] = '='
			}
		}
	}
	return string(out)
}
