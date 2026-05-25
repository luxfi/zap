// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"errors"
	"sync"
)

// defaultTransport is the always-available baseline. Uses an in-process
// channel pair as the wire — adequate for tests and single-host dev
// rigs. Production deployments wire this to the existing
// github.com/luxfi/zap NodeServer/NodeClient via a small adapter (not
// included here to keep the transport package dependency-free).
type defaultTransport struct {
	mu     sync.Mutex
	outbox chan envelope
	inbox  chan envelope
	closed bool
}

type envelope struct {
	peer string
	msg  []byte
}

func newDefault() Transport {
	return &defaultTransport{
		outbox: make(chan envelope, 64),
		inbox:  make(chan envelope, 64),
	}
}

func (t *defaultTransport) Name() string { return "default" }

func (t *defaultTransport) Send(ctx context.Context, peer string, msg []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("zap/transport: closed")
	}
	t.mu.Unlock()
	// Copy because the caller may reuse the buffer after Send returns
	// (the Transport interface contract). Outbox is bounded; we respect
	// ctx for back-pressure.
	cp := append([]byte(nil), msg...)
	select {
	case t.outbox <- envelope{peer: peer, msg: cp}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *defaultTransport) Recv(ctx context.Context) (string, []byte, error) {
	select {
	case env := <-t.inbox:
		return env.peer, env.msg, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func (t *defaultTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.outbox)
	close(t.inbox)
	return nil
}

// Outbox / Inbox are package-private hooks used by the adapter that
// bridges this transport to github.com/luxfi/zap NodeServer/NodeClient.
// Kept un-exported to discourage callers from poking at the channels
// directly — the adapter lives next to the production node code.
func (t *defaultTransport) outboxChan() <-chan envelope { return t.outbox }
func (t *defaultTransport) inboxChan() chan<- envelope  { return t.inbox }
