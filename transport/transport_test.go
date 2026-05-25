// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPickAutoFallsBackToDefault(t *testing.T) {
	// No env override, no native paths wired on this host → default.
	t.Setenv(envPreference, "")
	tr, err := Pick("")
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	defer tr.Close()
	if tr.Name() != "default" {
		t.Errorf("Pick auto=%q; want default", tr.Name())
	}
}

func TestPickExplicitDefault(t *testing.T) {
	tr, err := Pick("default")
	if err != nil {
		t.Fatalf("Pick(default): %v", err)
	}
	defer tr.Close()
	if tr.Name() != "default" {
		t.Errorf("name=%q", tr.Name())
	}
}

func TestPickExplicitUnavailable(t *testing.T) {
	// Explicit gpudirect on a host without GPUDirect must return the
	// sentinel error — no silent fallback when the operator asked
	// specifically.
	_, err := Pick("gpudirect")
	if err == nil {
		t.Fatal("Pick(gpudirect) succeeded on a host without GPUDirect; expected error")
	}
	if !errors.Is(err, ErrNotAvailable) {
		t.Errorf("err=%v; want ErrNotAvailable", err)
	}
	if !strings.Contains(err.Error(), "gpudirect") {
		t.Errorf("err message missing transport name: %v", err)
	}
}

func TestDefaultRoundTrip(t *testing.T) {
	tr, err := Pick("default")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	dt := tr.(*defaultTransport)

	// Wire outbox → inbox manually so the round-trip test doesn't need
	// an external relay.
	go func() {
		for env := range dt.outboxChan() {
			dt.inboxChan() <- env
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := tr.Send(ctx, "peer-1", []byte("hello")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	peer, msg, err := tr.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if peer != "peer-1" || string(msg) != "hello" {
		t.Errorf("got peer=%q msg=%q", peer, string(msg))
	}
}

func TestPickEnvOverride(t *testing.T) {
	t.Setenv(envPreference, "default")
	tr, err := Pick("")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if tr.Name() != "default" {
		t.Errorf("env override ignored: got %q", tr.Name())
	}
}

func TestPickUnknownName(t *testing.T) {
	_, err := Pick("nonsense-transport")
	if err == nil {
		t.Fatal("expected error for unknown transport name")
	}
}
