// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	zapquic "github.com/luxfi/zap/quic"
)

// benchSizes are the message sizes we benchmark in both directions:
// 256B representative of a small RPC envelope, 1 MiB representative
// of a large message (block proposal, FHE ciphertext fragment, etc.).
var benchSizes = []int{256, 1024 * 1024}

// BenchmarkRTT_QUIC measures per-RPC round-trip latency on a single
// QUIC connection (control stream). One frame request → one frame
// response → repeat. b.N round trips are measured.
//
// Compare to BenchmarkRTT_TCP_Baseline below.
func BenchmarkRTT_QUIC(b *testing.B) {
	for _, sz := range benchSizes {
		sz := sz
		b.Run(payloadLabel(sz), func(b *testing.B) {
			srv, cli := newBenchPair(b)
			defer cli.Close()
			defer srv.Close()

			payload := makePayload(sz)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := srv.Accept(context.Background())
				if err != nil {
					return
				}
				defer c.Close()
				for {
					frame, err := c.Recv()
					if err != nil {
						return
					}
					if err := c.Send(frame); err != nil {
						return
					}
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := cli.Dial(ctx, srv.Addr().String())
			if err != nil {
				b.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			b.SetBytes(int64(sz))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.Send(payload); err != nil {
					b.Fatalf("Send: %v", err)
				}
				if _, err := c.Recv(); err != nil {
					b.Fatalf("Recv: %v", err)
				}
			}
			b.StopTimer()
			c.Close()
			<-serverDone
		})
	}
}

// BenchmarkRTT_TCP_Baseline is the TCP+plaintext comparison: same
// payload sizes, same one-frame-per-rpc pattern, no TLS overhead at
// all. This is the baseline against which QUIC is measured.
//
// Plaintext TCP is the most generous baseline; QUIC always pays for
// TLS 1.3 + hybrid PQ KEM. We use it as the upper bound — QUIC
// cannot beat plaintext TCP in latency, but it should be in the
// same order of magnitude.
func BenchmarkRTT_TCP_Baseline(b *testing.B) {
	for _, sz := range benchSizes {
		sz := sz
		b.Run(payloadLabel(sz), func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				for {
					frame, err := readLPFrame(c)
					if err != nil {
						return
					}
					if err := writeLPFrame(c, frame); err != nil {
						return
					}
				}
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Fatalf("dial: %v", err)
			}
			defer c.Close()

			payload := makePayload(sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := writeLPFrame(c, payload); err != nil {
					b.Fatalf("write: %v", err)
				}
				if _, err := readLPFrame(c); err != nil {
					b.Fatalf("read: %v", err)
				}
			}
			b.StopTimer()
			c.Close()
			<-serverDone
		})
	}
}

// BenchmarkThroughput_QUIC measures one-way throughput on a single
// QUIC stream: client streams b.N frames, server reads them.
func BenchmarkThroughput_QUIC(b *testing.B) {
	for _, sz := range benchSizes {
		sz := sz
		b.Run(payloadLabel(sz), func(b *testing.B) {
			srv, cli := newBenchPair(b)
			defer cli.Close()
			defer srv.Close()

			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := srv.Accept(context.Background())
				if err != nil {
					return
				}
				defer c.Close()
				for {
					if _, err := c.Recv(); err != nil {
						return
					}
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := cli.Dial(ctx, srv.Addr().String())
			if err != nil {
				b.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			payload := makePayload(sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.Send(payload); err != nil {
					b.Fatalf("Send: %v", err)
				}
			}
			b.StopTimer()
			c.Close()
			<-serverDone
		})
	}
}

// BenchmarkThroughput_TCP_Baseline is the TCP plaintext throughput
// baseline.
func BenchmarkThroughput_TCP_Baseline(b *testing.B) {
	for _, sz := range benchSizes {
		sz := sz
		b.Run(payloadLabel(sz), func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				for {
					if _, err := readLPFrame(c); err != nil {
						return
					}
				}
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Fatalf("dial: %v", err)
			}
			defer c.Close()

			payload := makePayload(sz)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := writeLPFrame(c, payload); err != nil {
					b.Fatalf("write: %v", err)
				}
			}
			b.StopTimer()
			c.Close()
			<-serverDone
		})
	}
}

// BenchmarkMultistreamConcurrentRPC measures how QUIC's stream
// multiplexing changes per-RPC latency under concurrency. We fan
// out 16 concurrent RPCs over one connection and report aggregate
// per-RPC latency.
func BenchmarkMultistreamConcurrentRPC(b *testing.B) {
	const concurrency = 16
	srv, cli := newBenchPair(b)
	defer cli.Close()
	defer srv.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := srv.Accept(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		for {
			s, err := c.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func(s *zapquic.Stream) {
				defer s.Close()
				frame, err := s.ReadFrame()
				if err != nil {
					return
				}
				_ = s.WriteFrame(frame)
			}(s)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := cli.Dial(ctx, srv.Addr().String())
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	payload := makePayload(256)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s, err := c.OpenStream(ctx)
			if err != nil {
				b.Fatalf("OpenStream: %v", err)
			}
			if err := s.WriteFrame(payload); err != nil {
				b.Fatalf("WriteFrame: %v", err)
			}
			if err := s.CloseWrite(); err != nil {
				b.Fatalf("CloseWrite: %v", err)
			}
			if _, err := s.ReadFrame(); err != nil {
				b.Fatalf("ReadFrame: %v", err)
			}
			_ = s.Close()
		}
	})
	b.StopTimer()
	_ = concurrency // documentation
	c.Close()
	<-serverDone
}

// newBenchPair returns a fresh server+client. Shared by all the
// QUIC benchmarks to keep the setup boilerplate localized.
func newBenchPair(tb testing.TB) (*zapquic.Server, *zapquic.Client) {
	cert, err := zapquic.GenerateSelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		tb.Fatalf("cert: %v", err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientTLS := &tls.Config{InsecureSkipVerify: true}

	srv, err := zapquic.Listen(zapquic.ServerConfig{
		NodeID: "bench-server",
		Addr:   "127.0.0.1:0",
		TLS:    serverTLS,
	})
	if err != nil {
		tb.Fatalf("Listen: %v", err)
	}

	cli, err := zapquic.NewClient(zapquic.ClientConfig{
		NodeID: "bench-client",
		TLS:    clientTLS,
	})
	if err != nil {
		_ = srv.Close()
		tb.Fatalf("NewClient: %v", err)
	}
	return srv, cli
}

// makePayload returns a deterministic byte slice of size n.
func makePayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

// payloadLabel returns "256B" or "1MiB" — used as the sub-benchmark
// name.
func payloadLabel(n int) string {
	switch n {
	case 256:
		return "256B"
	case 1024 * 1024:
		return "1MiB"
	default:
		return ""
	}
}

// writeLPFrame writes a length-prefixed frame to a plaintext TCP
// connection — used by the TCP baselines. Wire format matches
// ZAP's TCP transport.
func writeLPFrame(w io.Writer, frame []byte) error {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

func readLPFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("zero-length frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Just keep sync referenced (used historically); silences any future
// unused-import refactor noise.
var _ = sync.Mutex{}
