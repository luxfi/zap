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

func TestPickAutoSelectsBestAvailable(t *testing.T) {
	// Auto returns the best-available transport on this host. On a
	// pure-CPU host that's "default"; on a host where the cuda /
	// gpudirect / dpdk build tags brought live implementations
	// online, auto picks one of those.
	//
	// We accept any name from Registered() — the contract is "Pick
	// MUST succeed when no preference is given", not "the result MUST
	// be default".
	t.Setenv(envPreference, "")
	tr, err := Pick("")
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	defer tr.Close()
	registered := map[string]bool{}
	for _, n := range Registered() {
		registered[n] = true
	}
	if !registered[tr.Name()] {
		t.Errorf("Pick auto=%q; want one of %v", tr.Name(), Registered())
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

func TestDefaultCaps(t *testing.T) {
	// The default transport is CPU-only, not GPU-resident, not zero-copy.
	// Callers that need GPU-resident bytes (FHE precompile, BLS batch
	// verify) gate on these flags at construction so they fall back to
	// heap allocation when the chosen transport can't deliver.
	tr, err := Pick("default")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	caps := tr.Caps()
	if caps.GPUResident {
		t.Errorf("default transport reports GPUResident=true; want false")
	}
	if caps.ZeroCopy {
		t.Errorf("default transport reports ZeroCopy=true; want false")
	}
}

func TestDefaultNotBufferAllocator(t *testing.T) {
	// The default transport intentionally does NOT implement
	// BufferAllocator — callers that need managed buffers must pick a
	// transport that can deliver them (uma, gpudirect). The type
	// assertion below documents the contract.
	tr, err := Pick("default")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, ok := tr.(BufferAllocator); ok {
		t.Errorf("default transport unexpectedly implements BufferAllocator")
	}
}

func TestRegistered(t *testing.T) {
	got := Registered()
	want := map[string]bool{"default": true, "uma": true, "gpudirect": true, "dpdk": true}
	if len(got) != len(want) {
		t.Errorf("Registered: got %d entries, want %d", len(got), len(want))
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("Registered: unexpected %q", n)
		}
		delete(want, n)
	}
	if len(want) > 0 {
		t.Errorf("Registered: missing %v", want)
	}
}

func TestUMABufferAllocator(t *testing.T) {
	// Skip when UMA isn't compiled in (cuda build tag missing).
	tr, err := Pick("uma")
	if err != nil {
		t.Skipf("UMA not available on this host: %v", err)
	}
	defer tr.Close()
	caps := tr.Caps()
	if !caps.GPUResident {
		t.Errorf("uma transport reports GPUResident=false; want true")
	}
	if !caps.ZeroCopy {
		t.Errorf("uma transport reports ZeroCopy=false; want true")
	}
	alloc, ok := tr.(BufferAllocator)
	if !ok {
		t.Fatal("uma transport does not implement BufferAllocator")
	}
	// Hit every slab class plus one cold-path size.
	for _, size := range []int{1, 256, 1024, 4096, 16384, 65536, 1 << 20, 4 << 20} {
		buf, err := alloc.AllocBuffer(size)
		if err != nil {
			t.Errorf("AllocBuffer(%d): %v", size, err)
			continue
		}
		b := buf.Bytes()
		if len(b) != size {
			t.Errorf("AllocBuffer(%d): Bytes len=%d", size, len(b))
		}
		// Write + read must round-trip through unified memory.
		for i := range b {
			b[i] = byte(i & 0xFF)
		}
		for i := range b {
			if b[i] != byte(i&0xFF) {
				t.Errorf("buffer corruption at i=%d: got %d", i, b[i])
				break
			}
		}
		// DevicePtr must be non-nil for GPU launches.
		if buf.DevicePtr() == nil {
			t.Errorf("AllocBuffer(%d): DevicePtr is nil", size)
		}
		buf.Release()
		// Double-Release must be a no-op (not a panic).
		buf.Release()
	}
}

func TestPickAllUnavailableOnNonGPUHost(t *testing.T) {
	// On a host without CUDA / DPDK / ibverbs, every native transport
	// must report an error individually. This is the inverse of
	// TestPickAutoFallsBackToDefault — auto must fall through, but
	// explicit requests must error.
	for _, name := range []string{"uma", "gpudirect", "dpdk"} {
		t.Run(name, func(t *testing.T) {
			_, err := Pick(name)
			if err == nil {
				// On a GPU host this CAN succeed — that's fine. The
				// test self-skips when running on real GPU hardware.
				t.Skipf("Pick(%s) succeeded — GPU hardware present, skipping the negative case", name)
				return
			}
			if !errors.Is(err, ErrNotAvailable) {
				t.Errorf("Pick(%s) err=%v; want wrapped ErrNotAvailable", name, err)
			}
		})
	}
}
