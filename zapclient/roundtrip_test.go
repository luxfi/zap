package zapclient

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	zap "github.com/luxfi/zap"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func textMsg(field int, s string) *zap.Message {
	b := zap.NewBuilder(128)
	ob := b.StartObject(64)
	ob.SetText(field, s)
	ob.FinishAsRoot()
	m, _ := zap.Parse(b.Finish())
	return m
}

// TestNativeTCPRoundTrip is the regression guard that was missing: a real
// zapclient.Client → zapclient.Server call over native TCP using static
// peers (no mDNS). It exercises BOTH fixes shipped in v0.8.6:
//
//   - server opcode→handler routing: Register binds the node handler
//     under op>>8 to match the inbound Flags()>>8 lookup (previously the
//     full op was used, so the handler was never found and the call hung);
//   - client static-peer dial: WithStaticPeers + dial-by-address via
//     ConnectDirectID (previously a static-discovery node was NoDiscovery
//     and could not dial the peer at all).
func TestNativeTCPRoundTrip(t *testing.T) {
	port := freePort(t)
	srv, err := NewServer("_lux-test._tcp", WithServerPort(port), WithNoDiscovery())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Register("test.echo", func(ctx context.Context, peer PeerInfo, req *zap.Message) (*zap.Message, error) {
		in := req.Root().Text(0)
		b := zap.NewBuilder(128)
		ob := b.StartObject(64)
		ob.SetText(0, "echo:"+in)
		ob.FinishAsRoot()
		out, _ := zap.Parse(b.Finish())
		return out, nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, "_lux-test._tcp",
		WithStaticPeers(fmt.Sprintf("127.0.0.1:%d", port)),
		WithCallTimeout(3*time.Second),
	)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	resp, err := c.Call(ctx, "test.echo", textMsg(0, "hi"))
	if err != nil {
		t.Fatalf("Call over native TCP: %v", err)
	}
	if got := resp.Root().Text(0); got != "echo:hi" {
		t.Fatalf("echo: got %q want %q", got, "echo:hi")
	}

	// Second call reuses the memoized address→NodeID mapping.
	resp2, err := c.Call(ctx, "test.echo", textMsg(0, "again"))
	if err != nil {
		t.Fatalf("second Call: %v", err)
	}
	if got := resp2.Root().Text(0); got != "echo:again" {
		t.Fatalf("echo2: got %q want %q", got, "echo:again")
	}
}
