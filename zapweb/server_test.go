package zapweb

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	zap "github.com/luxfi/zap"
	"github.com/luxfi/zap/zapclient"
)

// fldEcho is the single text field the echo procedure reads + writes.
const fldEcho = 0

// newEchoServer registers a "test.echo" procedure that prefixes its text
// argument with "echo:". It is NOT Started — zapweb bridges to Dispatch
// directly, so the native TCP node never has to listen.
func newEchoServer(t *testing.T) *zapclient.Server {
	t.Helper()
	srv, err := zapclient.NewServer("_lux-test._tcp",
		zapclient.WithNoDiscovery(),
		zapclient.WithServerPort(0),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Register("test.echo", func(ctx context.Context, peer zapclient.PeerInfo, req *zap.Message) (*zap.Message, error) {
		in := req.Root().Text(fldEcho)
		b := zap.NewBuilder(256)
		ob := b.StartObject(64)
		ob.SetText(fldEcho, "echo:"+in)
		ob.FinishAsRoot()
		out, _ := zap.Parse(b.Finish())
		return out, nil
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return srv
}

func textMessage(field int, s string) *zap.Message {
	b := zap.NewBuilder(256)
	ob := b.StartObject(64)
	ob.SetText(field, s)
	ob.FinishAsRoot()
	m, _ := zap.Parse(b.Finish())
	return m
}

// TestRoundTrip drives a browser-shaped WebSocket call end to end: the
// zapweb.Client builds the same frame a JS client would, the Handler
// bridges it to srv.Dispatch, and the echo procedure's reply comes back
// correlated.
func TestRoundTrip(t *testing.T) {
	srv := newEchoServer(t)
	ts := httptest.NewServer(Handler(srv, Options{OriginPatterns: []string{"*"}}))
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	resp, err := c.Call(ctx, "test.echo", textMessage(fldEcho, "hello"))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := resp.Root().Text(fldEcho); got != "echo:hello" {
		t.Fatalf("echo: got %q want %q", got, "echo:hello")
	}

	// Second call on the same socket — correlation + serialization hold.
	resp2, err := c.Call(ctx, "test.echo", textMessage(fldEcho, "world"))
	if err != nil {
		t.Fatalf("Call 2: %v", err)
	}
	if got := resp2.Root().Text(fldEcho); got != "echo:world" {
		t.Fatalf("echo 2: got %q want %q", got, "echo:world")
	}
}

// TestUnknownProcedureErrors asserts a dispatch-level failure (no such
// procedure) returns a FlagErr reply the client surfaces as a Go error,
// rather than hanging the caller.
func TestUnknownProcedureErrors(t *testing.T) {
	srv := newEchoServer(t)
	ts := httptest.NewServer(Handler(srv, Options{OriginPatterns: []string{"*"}}))
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Call(ctx, "test.does.not.exist", textMessage(fldEcho, "x")); err == nil {
		t.Fatal("expected error for unknown procedure, got nil")
	}
}
