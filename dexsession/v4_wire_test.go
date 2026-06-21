// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"testing"
)

// v4_wire_test.go round-trips the new V4 wire envelopes (route request/status) and
// the additive IntentStatus.MatchedOut field through build->parse->read, asserting
// every field survives — the same field-slot-overlap guard wire_test.go applies to
// the base envelopes. A corrupted route path or matched estimate would mislead the
// orchestration stream (never move value, but still a bug to catch here).

func TestWire_RouteRequest_RoundTrip(t *testing.T) {
	in := RouteRequest{
		NetworkID: 96369, CallIndex: 3, AmountIn: 1_000_000, MinAmountOut: 950_000, Deadline: 1 << 40,
		CChainID: fillID(0xC0), DChainID: fillID(0xD0), Account: fillAcct(0xAA),
		AssetIn: fillID(0x0A), AssetInAddr: fillAcct(0x02), Recipient: fillAcct(0xBB),
		Path: []ID{fillID(0x01), fillID(0x02), fillID(0x03), fillID(0x04)},
	}
	m, err := buildRouteRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readRouteRequest(m)
	if got.NetworkID != in.NetworkID || got.CallIndex != in.CallIndex || got.AmountIn != in.AmountIn ||
		got.MinAmountOut != in.MinAmountOut || got.Deadline != in.Deadline ||
		got.CChainID != in.CChainID || got.DChainID != in.DChainID || got.Account != in.Account ||
		got.AssetIn != in.AssetIn || got.AssetInAddr != in.AssetInAddr || got.Recipient != in.Recipient {
		t.Fatalf("RouteRequest scalar/fixed round-trip:\n got %+v\nwant %+v", got, in)
	}
	if len(got.Path) != len(in.Path) {
		t.Fatalf("RouteRequest path length: got %d want %d", len(got.Path), len(in.Path))
	}
	for i := range in.Path {
		if got.Path[i] != in.Path[i] {
			t.Fatalf("RouteRequest path hop %d mismatch", i)
		}
	}
}

func TestWire_RouteRequest_EmptyPath(t *testing.T) {
	in := RouteRequest{NetworkID: 1, AmountIn: 100, Path: nil}
	m, err := buildRouteRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readRouteRequest(m)
	if len(got.Path) != 0 {
		t.Fatalf("empty path round-trip produced %d hops", len(got.Path))
	}
}

func TestWire_RouteStatus_RoundTrip(t *testing.T) {
	in := RouteStatus{
		IntentID: fillID(0x4B), Phase: RouteCommitted, HopIndex: 2, HopCount: 3,
		HopAmountOut: 977_000, FinalOut: 970_000,
		Ref:    DExportRef{SourceChainID: fillID(0xDD), SourceTxID: fillID(0xFE), OutputIndex: 1, IntentID: fillID(0x4B)},
		Reason: "ok",
	}
	m, err := buildRouteStatus(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readRouteStatus(m)
	if got.IntentID != in.IntentID || got.Phase != in.Phase || got.HopIndex != in.HopIndex ||
		got.HopCount != in.HopCount || got.HopAmountOut != in.HopAmountOut || got.FinalOut != in.FinalOut ||
		got.Ref.SourceChainID != in.Ref.SourceChainID || got.Ref.SourceTxID != in.Ref.SourceTxID ||
		got.Ref.OutputIndex != in.Ref.OutputIndex || got.Reason != in.Reason {
		t.Fatalf("RouteStatus round-trip:\n got %+v\nwant %+v", got, in)
	}
}

// TestWire_IntentStatus_MatchedOut pins the additive MatchedOut field (the matched
// estimate). The existing IntentStatus round-trip leaves it zero; this asserts a
// non-zero value survives — and that it is carried alongside the ref without
// clobbering it (the field-slot guard for the new offset).
func TestWire_IntentStatus_MatchedOut(t *testing.T) {
	in := IntentStatus{
		IntentID: fillID(0x4B), Phase: PhaseCommitted, MatchedOut: 999_000,
		Ref:    DExportRef{SourceChainID: fillID(0xDD), SourceTxID: fillID(0xEE), OutputIndex: 7, IntentID: fillID(0x4B)},
		Reason: "matched",
	}
	m, err := buildIntentStatus(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readIntentStatus(m)
	if got.MatchedOut != in.MatchedOut {
		t.Fatalf("IntentStatus.MatchedOut: got %d want %d", got.MatchedOut, in.MatchedOut)
	}
	// The new field must not clobber the ref or reason (adjacent slots).
	if got.Ref.SourceTxID != in.Ref.SourceTxID || got.Ref.OutputIndex != in.Ref.OutputIndex || got.Reason != in.Reason {
		t.Fatalf("MatchedOut field clobbered adjacent fields:\n got %+v\nwant %+v", got, in)
	}
}

// TestV4Msg_DirectionAndInvariant asserts the message-type classification is correct
// and the type-level money-plane invariant holds for EVERY message type.
func TestV4Msg_DirectionAndInvariant(t *testing.T) {
	// A representative set across all actions.
	cToD := []V4MsgType{
		V4_SWAP_PREPARE_INTENT, V4_SWAP_NOTIFY_C_EXPORT, V4_SWAP_PREPARE_C_SETTLEMENT, V4_SWAP_SUBMIT_C_SETTLEMENT,
		V4_ROUTE_PREPARE_INTENT, V4_ROUTE_NOTIFY_C_EXPORT, V4_ROUTE_PREPARE_C_SETTLEMENT,
		V4_LP_PREPARE_COMMIT, V4_LP_NOTIFY_C_EXPORT,
		V4_COLLECT_REQUEST, V4_COLLECT_PREPARE_C_SETTLEMENT,
		V4_CANCEL_REQUEST, V4_CANCEL_PREPARE_C_SETTLEMENT,
	}
	for _, m := range cToD {
		if m.Dir() != DirCToD {
			t.Fatalf("%s: Dir() = %d, want DirCToD", m, m.Dir())
		}
	}
	dToC := []V4MsgType{
		V4_SWAP_D_IMPORTED, V4_SWAP_MATCHED, V4_SWAP_D_EXPORT_READY, V4_SWAP_C_SETTLED,
		V4_ROUTE_HOP_STARTED, V4_ROUTE_HOP_FILLED, V4_ROUTE_D_EXPORT_READY, V4_ROUTE_REFUND_READY, V4_ROUTE_C_SETTLED,
		V4_LP_D_COMMITTED, V4_LP_POSITION_OPEN,
		V4_COLLECT_D_EXPORT_READY, V4_COLLECT_C_SETTLED,
		V4_CANCEL_D_EXPORT_READY, V4_CANCEL_C_SETTLED,
		V4_STATE_QUOTE_UPDATE, V4_STATE_BOOK_UPDATE, V4_ERROR, V4_HALTED,
	}
	for _, m := range dToC {
		if m.Dir() != DirDToC {
			t.Fatalf("%s: Dir() = %d, want DirDToC", m, m.Dir())
		}
	}
	local := []V4MsgType{V4_SWAP_OPEN, V4_ROUTE_OPEN, V4_LP_OPEN, V4_COLLECT_OPEN, V4_CANCEL_OPEN, V4_STATE_OPEN, V4_STATE_CLOSE}
	for _, m := range local {
		if m.Dir() != DirLocal {
			t.Fatalf("%s: Dir() = %d, want DirLocal", m, m.Dir())
		}
	}
	// THE type-level invariant: NO message type credits value — in any direction.
	all := append(append(append([]V4MsgType{}, cToD...), dToC...), local...)
	for _, m := range all {
		if m.CreditsValue() {
			t.Fatalf("%s.CreditsValue() = true — the money-plane invariant is broken at the type level", m)
		}
	}
	// HasRef is true ONLY for the export/refund reads (the only settleable pointers).
	refBearing := map[V4MsgType]bool{
		V4_SWAP_D_EXPORT_READY: true, V4_ROUTE_D_EXPORT_READY: true, V4_ROUTE_REFUND_READY: true,
		V4_COLLECT_D_EXPORT_READY: true, V4_CANCEL_D_EXPORT_READY: true,
	}
	for _, m := range all {
		ev := V4Event{Type: m}
		if ev.HasRef() != refBearing[m] {
			t.Fatalf("%s: HasRef() = %v, want %v", m, ev.HasRef(), refBearing[m])
		}
	}
}
