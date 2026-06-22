// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"bytes"
	"testing"
)

// wire_test.go round-trips every envelope through build->parse->read and asserts
// EVERY field survives. This catches field-slot overlap (a bytes32 mistakenly
// given an 8-byte slot clobbers the next field) — the exact class of bug that
// must never reach the value-boundary id derivation, since a corrupted intent id
// would name the wrong object.

func TestWire_QuoteRequest_RoundTrip(t *testing.T) {
	in := QuoteRequest{MarketID: fillID(0xA1), AmountIn: 123456789, ZeroForOne: true}
	m, err := buildQuoteRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readQuoteRequest(m)
	if got != in {
		t.Fatalf("QuoteRequest round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_QuoteResult_RoundTrip(t *testing.T) {
	in := QuoteResult{MarketID: fillID(0xB2), AmountIn: 1000, AmountOut: 999, BestPricePx: 0xDEADBEEF, Liquid: true}
	m, err := buildQuoteResult(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readQuoteResult(m)
	if got != in {
		t.Fatalf("QuoteResult round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_StateRequest_RoundTrip(t *testing.T) {
	in := StateRequest{Kind: StateBalance, MarketID: fillID(0x11), Account: fillAcct(0x22), Asset: fillID(0x33), IntentID: fillID(0x44)}
	m, err := buildStateRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readStateRequest(m)
	if got != in {
		t.Fatalf("StateRequest round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_StateResult_RoundTrip(t *testing.T) {
	in := StateResult{Kind: StateMarket, Exists: true, Known: true, Available: 42, BaseID: fillID(0x55), QuoteID: fillID(0x66)}
	m, err := buildStateResult(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readStateResult(m)
	if got != in {
		t.Fatalf("StateResult round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_SwapIntentRequest_RoundTrip(t *testing.T) {
	in := SwapIntentRequest{
		NetworkID: 96369, Nonce: 7, AmountIn: 1_000_000, MinAmountOut: 990_000, Deadline: 1 << 40,
		CChainID: fillID(0xC0), DChainID: fillID(0xD0), Account: fillAcct(0xAA),
		AssetIn: fillID(0x01), AssetInAddr: fillAcct(0x02), MarketID: fillID(0x4D), Recipient: fillAcct(0xBB),
	}
	m, err := buildSwapIntentRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readSwapIntentRequest(m)
	if got != in {
		t.Fatalf("SwapIntentRequest round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_PreparedIntent_RoundTrip(t *testing.T) {
	in := PreparedIntent{
		To: fillAcct(0x99), IntentID: fillID(0x4B), QuotedOut: 12345, AmountIn: 1_000_000,
		DChainID: fillID(0xD0), CChainID: fillID(0xC0), Account: fillAcct(0xAA), Recipient: fillAcct(0xBB),
		AssetIn: fillID(0x01), MarketID: fillID(0x4D),
		Calldata: bytes.Repeat([]byte{0xCA}, 200), HookData: []byte{'D', 'I', '0', '1'},
	}
	m, err := buildPreparedIntent(in, MsgPrepare)
	if err != nil {
		t.Fatal(err)
	}
	if route := m.Flags() >> 8; route != MsgPrepare {
		t.Fatalf("PreparedIntent route flag: got 0x%X want 0x%X", route, MsgPrepare)
	}
	got := readPreparedIntent(m)
	// Compare field by field (slices need bytes.Equal).
	if got.To != in.To || got.IntentID != in.IntentID || got.QuotedOut != in.QuotedOut || got.AmountIn != in.AmountIn ||
		got.DChainID != in.DChainID || got.CChainID != in.CChainID || got.Account != in.Account || got.Recipient != in.Recipient ||
		got.AssetIn != in.AssetIn || got.MarketID != in.MarketID {
		t.Fatalf("PreparedIntent fixed-field round-trip:\n got %+v\nwant %+v", got, in)
	}
	if !bytes.Equal(got.Calldata, in.Calldata) {
		t.Fatalf("PreparedIntent.Calldata: got %x want %x", got.Calldata, in.Calldata)
	}
	if !bytes.Equal(got.HookData, in.HookData) {
		t.Fatalf("PreparedIntent.HookData: got %x want %x", got.HookData, in.HookData)
	}
}

// TestWire_PreparedIntent_RouteFlags proves the same PreparedIntent payload,
// finalized under each route the dispatcher serves, carries the correct flag in
// Flags()>>8 and still round-trips every field. This replaces the old fixed-
// offset [6:8] byte-patch retag with the FinishWithFlags idiom: the flag must
// survive build->parse for both MsgPrepare (the prepare call) and MsgNotify
// (NotifyIntent), and the body must be untouched by the route choice.
func TestWire_PreparedIntent_RouteFlags(t *testing.T) {
	in := PreparedIntent{
		To: fillAcct(0x99), IntentID: fillID(0x4B), QuotedOut: 12345, AmountIn: 1_000_000,
		DChainID: fillID(0xD0), CChainID: fillID(0xC0), Account: fillAcct(0xAA), Recipient: fillAcct(0xBB),
		AssetIn: fillID(0x01), MarketID: fillID(0x4D),
		Calldata: bytes.Repeat([]byte{0xCA}, 200), HookData: []byte{'D', 'I', '0', '1'},
	}
	for _, msgType := range []uint16{MsgPrepare, MsgNotify} {
		m, err := buildPreparedIntent(in, msgType)
		if err != nil {
			t.Fatalf("buildPreparedIntent(%#x): %v", msgType, err)
		}
		if route := m.Flags() >> 8; route != msgType {
			t.Fatalf("route flag for %#x: got 0x%X want 0x%X", msgType, route, msgType)
		}
		got := readPreparedIntent(m)
		if got.IntentID != in.IntentID || got.MarketID != in.MarketID || got.AmountIn != in.AmountIn ||
			!bytes.Equal(got.Calldata, in.Calldata) || !bytes.Equal(got.HookData, in.HookData) {
			t.Fatalf("payload not preserved across route %#x:\n got %+v\nwant %+v", msgType, got, in)
		}
	}
}

func TestWire_DExportRef_RoundTrip(t *testing.T) {
	in := DExportRef{SourceChainID: fillID(0xDD), SourceTxID: fillID(0xEE), OutputIndex: 9, IntentID: fillID(0x4B)}
	m, err := buildDExportRef(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readDExportRef(m)
	if got != in {
		t.Fatalf("DExportRef round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_IntentStatus_RoundTrip(t *testing.T) {
	in := IntentStatus{
		IntentID: fillID(0x4B), Phase: PhaseCommitted,
		Ref:    DExportRef{SourceChainID: fillID(0xDD), SourceTxID: fillID(0xEE), OutputIndex: 3, IntentID: fillID(0x4B)},
		Reason: "ok",
	}
	m, err := buildIntentStatus(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readIntentStatus(m)
	if got.IntentID != in.IntentID || got.Phase != in.Phase || got.Reason != in.Reason ||
		got.Ref.SourceChainID != in.Ref.SourceChainID || got.Ref.SourceTxID != in.Ref.SourceTxID || got.Ref.OutputIndex != in.Ref.OutputIndex {
		t.Fatalf("IntentStatus round-trip:\n got %+v\nwant %+v", got, in)
	}
}

func TestWire_SettlementResult_RoundTrip(t *testing.T) {
	in := SettlementSubmitResult{
		Mode: SettleCalldata, To: fillAcct(0x99), ObjectKey: fillID(0x0B), CTxHash: fillID(0x0C),
		Calldata: bytes.Repeat([]byte{0x5E}, 137),
	}
	m, err := buildSettlementResult(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readSettlementResult(m)
	if got.Mode != in.Mode || got.To != in.To || got.ObjectKey != in.ObjectKey || got.CTxHash != in.CTxHash {
		t.Fatalf("SettlementResult fixed fields:\n got %+v\nwant %+v", got, in)
	}
	if !bytes.Equal(got.Calldata, in.Calldata) {
		t.Fatalf("SettlementResult.Calldata: got %x want %x", got.Calldata, in.Calldata)
	}
}

func TestWire_IntentWatchRef_RoundTrip(t *testing.T) {
	in := IntentWatchRef{IntentID: fillID(0x4B)}
	m, err := buildIntentWatchRef(in)
	if err != nil {
		t.Fatal(err)
	}
	got := readIntentWatchRef(m)
	if got != in {
		t.Fatalf("IntentWatchRef round-trip: got %x want %x", got.IntentID[:], in.IntentID[:])
	}
}

// fillID returns an ID whose every byte is b (so any truncation/overlap shows).
func fillID(b byte) ID {
	var id ID
	for i := range id {
		id[i] = b
	}
	return id
}

// fillAcct returns an Account whose every byte is b.
func fillAcct(b byte) Account {
	var a Account
	for i := range a {
		a[i] = b
	}
	return a
}
