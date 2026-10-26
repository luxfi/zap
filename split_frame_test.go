package zap

import (
	"context"
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A frame whose length and body arrive a second and a half apart is still one
// frame, in both directions, and a connection idle past the handshake's
// deadline still carries frames. A unix socket writes the length and the body
// as two writes, so a writer descheduled between them splits the frame; the
// read loop keeps the bytes it has and reads the rest, never starting over
// mid-frame and taking body bytes for the next length.
func TestNode_ASplitFrameIsOneFrame(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "split.sock")
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	const op uint16 = 0x0091

	got := map[string]chan string{"server": make(chan string, 4), "client": make(chan string, 4)}
	text := func(s string) *Message {
		b := NewBuilder(64)
		o := b.StartObject(24)
		o.SetBytes(0, []byte(s))
		o.FinishAsRoot()
		m, err := Parse(b.FinishWithFlags(uint16(op) << 8))
		if err != nil {
			t.Fatalf("build %q: %v", s, err)
		}
		return m
	}
	node := func(id, addr string) *Node {
		n := NewNode(NodeConfig{NodeID: id, ServiceType: "_tasks._tcp", Address: addr, Logger: quiet, NoDiscovery: true})
		n.Handle(op, func(_ context.Context, _ string, msg *Message) (*Message, error) {
			got[id] <- string(msg.Root().Bytes(0))
			return nil, nil
		})
		if err := n.Start(); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
		t.Cleanup(n.Stop)
		return n
	}
	srv := node("server", sock)
	cli := node("client", "")
	connected := time.Now()
	peer, err := cli.ConnectDirectID(sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}

	// split writes one frame as its length, a pause of a second and a half, then its body.
	split := func(from *Node, to string, s string) {
		from.connsMu.Lock()
		c := from.conns[to]
		from.connsMu.Unlock()
		if c == nil {
			t.Fatalf("%s holds no connection to %s", from.nodeID, to)
		}
		body := text(s).Bytes()
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(body)))
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.conn.Write(n[:]); err != nil {
			t.Fatalf("write length: %v", err)
		}
		time.Sleep(1500 * time.Millisecond)
		if _, err := c.conn.Write(body); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	want := func(at string, w ...string) {
		for _, s := range w {
			select {
			case g := <-got[at]:
				if g != s {
					t.Fatalf("%s received %q, want %q", at, g, s)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s never received %q", at, s)
			}
		}
	}

	// The dialer's frames, read by the listener (handleConn's dispatch loop).
	split(cli, peer, "one")
	if err := cli.Send(context.Background(), peer, text("two")); err != nil {
		t.Fatalf("send after the split frame: %v", err)
	}
	want("server", "one", "two")

	// The listener's frames, read by the dialer (ConnectDirectID's dispatch loop).
	split(srv, "client", "three")
	if err := srv.Send(context.Background(), "client", text("four")); err != nil {
		t.Fatalf("send after the split frame: %v", err)
	}
	want("client", "three", "four")

	// The listener read its handshake under a 10s deadline; past it, frames
	// still arrive both ways.
	time.Sleep(time.Until(connected.Add(10*time.Second + 500*time.Millisecond)))
	if err := cli.Send(context.Background(), peer, text("five")); err != nil {
		t.Fatalf("send past the handshake deadline: %v", err)
	}
	want("server", "five")
	if err := srv.Send(context.Background(), "client", text("six")); err != nil {
		t.Fatalf("send past the handshake deadline: %v", err)
	}
	want("client", "six")
}
