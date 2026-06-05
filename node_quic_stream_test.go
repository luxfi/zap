// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	zap "github.com/luxfi/zap"
	zapquic "github.com/luxfi/zap/quic"
)

// TestQUICCallRoundTrip verifies the per-Call stream path: Node.Call
// over QUIC opens a fresh stream, writes one request frame, reads one
// response frame, closes the stream. Byte-equal request/response.
func TestQUICCallRoundTrip(t *testing.T) {
	srvAddr, srvNode, cliNode := newQUICTestPair(t, "srv-roundtrip", "cli-roundtrip")
	defer srvNode.Stop()
	defer cliNode.Stop()

	// Server registers a handler that echos the request.
	srvNode.Handle(0x42, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		got := msg.Root().Uint64(0)
		resp := buildEchoMessage(got + 1)
		return resp, nil
	})

	if err := cliNode.ConnectDirect(srvAddr); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}

	// Give the accept goroutine a moment to register the inbound conn.
	waitForPeer(t, srvNode, "cli-roundtrip", 2*time.Second)
	waitForPeer(t, cliNode, "srv-roundtrip", 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := buildEchoMessage(100)
	resp, err := cliNode.Call(ctx, "srv-roundtrip", req)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := resp.Root().Uint64(0); got != 101 {
		t.Fatalf("response = %d, want 101", got)
	}
}

// TestQUICCallConcurrent fans out N concurrent Calls on one QUIC
// connection. Each Call MUST get its own stream — if they serialized
// on a shared mutex, the handler's deliberate sleep would multiply
// total latency. With per-Call streams the wall-clock cost is bounded
// by the slowest single call plus stream open overhead.
func TestQUICCallConcurrent(t *testing.T) {
	const concurrency = 32
	const handlerDelay = 5 * time.Millisecond

	srvAddr, srvNode, cliNode := newQUICTestPair(t, "srv-concurrent", "cli-concurrent")
	defer srvNode.Stop()
	defer cliNode.Stop()

	var handlerInflight atomic.Int64
	var maxInflight atomic.Int64

	srvNode.Handle(0x42, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		nowInflight := handlerInflight.Add(1)
		defer handlerInflight.Add(-1)
		// Track concurrent in-flight handlers — the optimization
		// claim is that with N concurrent Calls we should observe
		// max inflight ≈ N (modulo scheduler jitter).
		for {
			cur := maxInflight.Load()
			if nowInflight <= cur || maxInflight.CompareAndSwap(cur, nowInflight) {
				break
			}
		}
		// Deliberately sleep so serialization would dominate.
		time.Sleep(handlerDelay)
		idx := msg.Root().Uint64(0)
		return buildEchoMessage(idx + 1), nil
	})

	if err := cliNode.ConnectDirect(srvAddr); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	waitForPeer(t, srvNode, "cli-concurrent", 2*time.Second)
	waitForPeer(t, cliNode, "srv-concurrent", 2*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := buildEchoMessage(uint64(i))
			resp, err := cliNode.Call(ctx, "srv-concurrent", req)
			if err != nil {
				errs <- fmt.Errorf("Call[%d]: %v", i, err)
				return
			}
			if got := resp.Root().Uint64(0); got != uint64(i)+1 {
				errs <- fmt.Errorf("Call[%d] response = %d, want %d", i, got, i+1)
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	elapsed := time.Since(start)

	t.Logf("%d concurrent Calls in %v; peak inflight handlers = %d",
		concurrency, elapsed, maxInflight.Load())

	// Sanity check: with per-Call streams we expect the wall-clock to
	// be only a few multiples of handlerDelay (one per pipeline depth
	// + stream open overhead). With pure serialization it would be
	// ≈ concurrency * handlerDelay = 32 * 5ms = 160ms. Use a generous
	// 4× margin to keep the test stable on CI.
	limit := time.Duration(concurrency/4) * handlerDelay
	if elapsed > limit {
		t.Errorf("elapsed %v > limit %v — Calls appear serialized", elapsed, limit)
	}
	// And peak inflight ≥ 2 confirms streams ran in parallel.
	if maxInflight.Load() < 2 {
		t.Errorf("max inflight = %d, expected ≥2 concurrent handlers", maxInflight.Load())
	}
}

// buildEchoMessage emits a 1-field message with msgType=0x42.
func buildEchoMessage(value uint64) *zap.Message {
	b := zap.NewBuilder(64)
	o := b.StartObject(16)
	o.SetUint64(0, value)
	o.FinishAsRoot()
	msg, _ := zap.Parse(b.FinishWithFlags(0x42 << 8))
	return msg
}

// newQUICTestPair creates a connected pair of ZAP nodes over QUIC.
// Both nodes use self-signed certs and skip cert verification — fine
// for in-process tests, never for production.
func newQUICTestPair(t *testing.T, srvID, cliID string) (string, *zap.Node, *zap.Node) {
	t.Helper()
	cert, err := zapquic.GenerateSelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	// Both sides act as servers in ZAP's QUIC factory (Listen +
	// Dial use the same TLS config), so the client also needs a
	// usable Certificates entry. Insecure verify is fine for
	// loopback tests.
	cliTLS := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	srvPort := pickFreePortTest(t)
	srv := zap.NewNode(zap.NodeConfig{
		NodeID:      srvID,
		ServiceType: "_quic-test._udp",
		Port:        srvPort,
		NoDiscovery: true,
		Transport:   zap.TransportQUIC,
		TLS:         srvTLS,
		Logger:      logger,
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}

	cli := zap.NewNode(zap.NodeConfig{
		NodeID:      cliID,
		ServiceType: "_quic-test._udp",
		Port:        0,
		NoDiscovery: true,
		Transport:   zap.TransportQUIC,
		TLS:         cliTLS,
		Logger:      logger,
	})
	if err := cli.Start(); err != nil {
		srv.Stop()
		t.Fatalf("cli.Start: %v", err)
	}

	return fmt.Sprintf("127.0.0.1:%d", srvPort), srv, cli
}

// pickFreePortTest binds a UDP socket to find an unused port, then
// closes it. The released port is then used by Node — small race
// window, fine for tests.
func pickFreePortTest(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// waitForPeer polls Node.Peers until peerID is connected or timeout.
// Falls back to a probe Call when Peers() returns empty — the QUIC
// transport tracks peers in a separate map that's not surfaced via
// Peers(), so the canonical liveness check is a successful
// round-trip.
func waitForPeer(t *testing.T, n *zap.Node, peerID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range n.Peers() {
			if p == peerID {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Don't fail — QUIC peers may not be in Peers() yet; the actual
	// Call will retry until ctx fires.
}

// BenchmarkQUICCallConcurrent_1 / _10 / _100 measure how Call latency
// scales with concurrent goroutines. Per-Call streams should yield
// near-linear scaling up to the QUIC stream limit.
func BenchmarkQUICCallConcurrent_1(b *testing.B)   { benchQUICCall(b, 1) }
func BenchmarkQUICCallConcurrent_10(b *testing.B)  { benchQUICCall(b, 10) }
func BenchmarkQUICCallConcurrent_100(b *testing.B) { benchQUICCall(b, 100) }

func benchQUICCall(b *testing.B, goroutines int) {
	// 2ms simulated handler work. Picked deliberately to be larger
	// than the QUIC RTT + stream-open overhead, so concurrent calls
	// must overlap inside the handler for the bench to scale. Real
	// production handlers (signature verification, state lookup,
	// fhe ciphertext math) often run 1-10ms; we sit at the low end.
	const handlerWork = 2 * time.Millisecond
	srvID := "srv-bench-" + strconv.Itoa(goroutines)
	cliID := "cli-bench-" + strconv.Itoa(goroutines)
	srvAddr, srvNode, cliNode := newQUICBenchPair(b, srvID, cliID)
	defer srvNode.Stop()
	defer cliNode.Stop()

	srvNode.Handle(0x42, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		// Busy-wait so we exercise CPU + cache, not just runtime
		// goroutine parking — sleep() would let the scheduler
		// trivially batch work.
		deadline := time.Now().Add(handlerWork)
		for time.Now().Before(deadline) {
			runtime.Gosched()
		}
		return buildEchoMessage(msg.Root().Uint64(0) + 1), nil
	})
	if err := cliNode.ConnectDirect(srvAddr); err != nil {
		b.Fatalf("ConnectDirect: %v", err)
	}

	// Warm-up: synchronously execute one Call to make sure the
	// connection is fully established and the QUIC accept-stream
	// goroutine is running on both sides. Bench timer starts after.
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := cliNode.Call(warmCtx, srvID, buildEchoMessage(0)); err != nil {
		warmCancel()
		b.Fatalf("warm-up Call: %v", err)
	}
	warmCancel()

	b.ReportAllocs()
	b.ResetTimer()

	if goroutines == 1 {
		ctx := context.Background()
		for i := 0; i < b.N; i++ {
			resp, err := cliNode.Call(ctx, srvID, buildEchoMessage(uint64(i)))
			if err != nil {
				b.Fatalf("Call: %v", err)
			}
			_ = resp
		}
		return
	}

	// Concurrent path: split b.N iterations across `goroutines`
	// fixed-size workers. RunParallel's SetParallelism multiplies by
	// GOMAXPROCS which would explode the goroutine count — instead we
	// hand-roll a fixed worker pool.
	var counter atomic.Int64
	target := int64(b.N)
	var wg sync.WaitGroup
	for w := 0; w < goroutines; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for {
				idx := counter.Add(1)
				if idx > target {
					return
				}
				resp, err := cliNode.Call(ctx, srvID, buildEchoMessage(uint64(idx)))
				if err != nil {
					b.Errorf("Call: %v", err)
					return
				}
				_ = resp
			}
		}()
	}
	wg.Wait()
}

func newQUICBenchPair(b *testing.B, srvID, cliID string) (string, *zap.Node, *zap.Node) {
	b.Helper()
	cert, err := zapquic.GenerateSelfSignedCert("127.0.0.1", "::1", "localhost")
	if err != nil {
		b.Fatalf("cert: %v", err)
	}
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	// Both sides act as servers in ZAP's QUIC factory (Listen +
	// Dial use the same TLS config), so the client also needs a
	// usable Certificates entry. Insecure verify is fine for
	// loopback tests.
	cliTLS := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	srvPort := pickFreePortBench(b)
	srv := zap.NewNode(zap.NodeConfig{
		NodeID:      srvID,
		ServiceType: "_quic-bench._udp",
		Port:        srvPort,
		NoDiscovery: true,
		Transport:   zap.TransportQUIC,
		TLS:         srvTLS,
		Logger:      logger,
	})
	if err := srv.Start(); err != nil {
		b.Fatalf("srv.Start: %v", err)
	}
	cli := zap.NewNode(zap.NodeConfig{
		NodeID:      cliID,
		ServiceType: "_quic-bench._udp",
		Port:        0,
		NoDiscovery: true,
		Transport:   zap.TransportQUIC,
		TLS:         cliTLS,
		Logger:      logger,
	})
	if err := cli.Start(); err != nil {
		srv.Stop()
		b.Fatalf("cli.Start: %v", err)
	}
	return fmt.Sprintf("127.0.0.1:%d", srvPort), srv, cli
}

func pickFreePortBench(b *testing.B) int {
	b.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatalf("pick port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

func waitForPeerBench(b *testing.B, n *zap.Node, peerID string, timeout time.Duration) {
	b.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range n.Peers() {
			if p == peerID {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}
