package zap

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// A node binds a unix socket and answers a Call over it.
func TestNode_UnixSocketRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tasks.sock")
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	srv := NewNode(NodeConfig{NodeID: "server", ServiceType: "_tasks._tcp", Address: sock, Logger: quiet, NoDiscovery: true})
	if err := srv.Start(); err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	defer srv.Stop()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket not created: %v", err)
	}
	const op uint16 = 0x0090
	srv.Handle(op, func(ctx context.Context, from string, msg *Message) (*Message, error) {
		b := NewBuilder(64)
		o := b.StartObject(24)
		o.SetBytes(0, []byte("pong"))
		o.FinishAsRoot()
		return Parse(b.FinishWithFlags(uint16(op) << 8))
	})

	cli := NewNode(NodeConfig{NodeID: "client", ServiceType: "_tasks._tcp", Logger: quiet, NoDiscovery: true})
	if err := cli.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	defer cli.Stop()
	peer, err := cli.ConnectDirectID(sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}

	b := NewBuilder(64)
	o := b.StartObject(24)
	o.SetBytes(0, []byte("ping"))
	o.FinishAsRoot()
	req, err := Parse(b.FinishWithFlags(uint16(op) << 8))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	resp, err := cli.Call(context.Background(), peer, req)
	if err != nil {
		t.Fatalf("Call over unix socket: %v", err)
	}
	if got := string(resp.Root().Bytes(0)); got != "pong" {
		t.Fatalf("got %q want %q", got, "pong")
	}
}

func TestNetwork(t *testing.T) {
	for addr, want := range map[string]string{
		"/run/tasks.sock":      "unix",
		"./tasks.sock":         "unix",
		"@tasks":               "unix",
		"127.0.0.1:9999":       "tcp",
		":9999":                "tcp",
		"tasks.hanzo.svc:9999": "tcp",
	} {
		if got := Network(addr); got != want {
			t.Fatalf("Network(%q) = %q want %q", addr, got, want)
		}
	}
}
