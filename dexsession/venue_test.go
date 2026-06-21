// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"sync"
)

// venue_test.go provides two Venue implementations for the suite:
//
//	honestVenue   — a well-behaved D-Chain stand-in. quote reads a configured book;
//	                notify records the intent; watch returns Pending until the test
//	                marks a commit (modeling a D block); resolveExport points at the
//	                object the test placed in the ledger.
//	maliciousVenue — lies about EVERYTHING: fabricates quotes, claims PhaseCommitted
//	                with bogus refs, returns settlement calldata for objects that do
//	                not exist or that name a different recipient/asset/amount. Used to
//	                prove no ZAP response moves money.

// honestVenue is the cooperative backend. It is wired to an AtomicLedger so the
// refs it returns name objects the ledger actually holds (after the test places
// them). It still NEVER credits — it only reports.
type honestVenue struct {
	mu        sync.Mutex
	bookPrice map[ID]float64 // marketID -> price (quote currency per base)
	bookLiq   map[ID]bool
	committed map[ID]DExportRef // intentID -> the export ref, set when D "commits"
	outAsset  map[ID]ID         // intentID -> output asset (for resolveExport amount lookup)
	ledger    *AtomicLedger
}

func newHonestVenue(l *AtomicLedger) *honestVenue {
	return &honestVenue{
		bookPrice: make(map[ID]float64),
		bookLiq:   make(map[ID]bool),
		committed: make(map[ID]DExportRef),
		outAsset:  make(map[ID]ID),
		ledger:    l,
	}
}

func (v *honestVenue) setBook(market ID, price float64) {
	v.mu.Lock()
	v.bookPrice[market] = price
	v.bookLiq[market] = true
	v.mu.Unlock()
}

// commit models a committed D block: it records the export ref the watch will
// report and (the test having placed the real object in the ledger) the output
// asset for the resolveExport amount.
func (v *honestVenue) commit(intentID ID, ref DExportRef, outAsset ID) {
	v.mu.Lock()
	v.committed[intentID] = ref
	v.outAsset[intentID] = outAsset
	v.mu.Unlock()
}

func (v *honestVenue) Quote(_ context.Context, req QuoteRequest) (QuoteResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	price, ok := v.bookPrice[req.MarketID]
	if !ok || !v.bookLiq[req.MarketID] {
		return QuoteResult{MarketID: req.MarketID, Liquid: false}, nil
	}
	var out uint64
	if req.ZeroForOne {
		out = uint64(float64(req.AmountIn) * price)
	} else {
		if price > 0 {
			out = uint64(float64(req.AmountIn) / price)
		}
	}
	return QuoteResult{MarketID: req.MarketID, AmountIn: req.AmountIn, AmountOut: out, Liquid: true}, nil
}

func (v *honestVenue) State(_ context.Context, req StateRequest) (StateResult, error) {
	return StateResult{Kind: req.Kind, Exists: true}, nil
}

func (v *honestVenue) NotifyIntent(_ context.Context, intent PreparedIntent) (IntentWatchRef, error) {
	return IntentWatchRef{IntentID: intent.IntentID}, nil
}

func (v *honestVenue) WatchStatus(_ context.Context, intentID ID) (IntentStatus, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ref, ok := v.committed[intentID]; ok {
		return IntentStatus{IntentID: intentID, Phase: PhaseCommitted, Ref: ref}, nil
	}
	return IntentStatus{IntentID: intentID, Phase: PhasePending}, nil
}

// ResolveExport builds settlement calldata pointing at the object the ref names.
// The amount is the real object's amount (the venue reads it from the ledger's
// store — modeling reading shared memory). It still cannot credit; it returns
// bytes.
func (v *honestVenue) ResolveExport(_ context.Context, ref DExportRef) (SettlementSubmitResult, error) {
	key := ref.ObjectKey()
	v.ledger.mu.Lock()
	o, ok := v.ledger.objects[key]
	v.ledger.mu.Unlock()
	var amount uint64
	if ok {
		amount = o.amount
	}
	pk := testPoolKey()
	calldata := EncodeSwapCalldata(pk, true, 0, EncodeSettlementHookData(key, amount))
	return SettlementSubmitResult{Mode: SettleCalldata, To: addr9999(), ObjectKey: key, Calldata: calldata}, nil
}

// maliciousVenue lies about everything. It is the adversary in the critical test.
type maliciousVenue struct {
	// fakeAmount is the amount the malicious venue claims in fabricated settlement
	// calldata (typically inflated, or for an object that does not exist).
	fakeAmount uint64
	// fakeRecipient is a recipient the attacker WISHES to credit (their own
	// account); irrelevant because the chain binds recipient to the caller.
	fakeRecipient Account
	// fakeAsset is an asset the attacker wishes to re-denominate to; irrelevant
	// because the chain derives the asset from the swap direction.
	fakeAsset ID
	// fakeKey is the object key the attacker points at (often a non-existent or a
	// victim's object).
	fakeKey ID
}

func (v *maliciousVenue) Quote(_ context.Context, req QuoteRequest) (QuoteResult, error) {
	// Lie: claim a wildly favorable, liquid quote for any market.
	return QuoteResult{MarketID: req.MarketID, AmountIn: req.AmountIn, AmountOut: 1 << 62, Liquid: true}, nil
}

func (v *maliciousVenue) State(_ context.Context, req StateRequest) (StateResult, error) {
	// Lie: claim huge available balances and that everything exists.
	return StateResult{Kind: req.Kind, Exists: true, Available: 1 << 62, Known: true}, nil
}

func (v *maliciousVenue) NotifyIntent(_ context.Context, intent PreparedIntent) (IntentWatchRef, error) {
	return IntentWatchRef{IntentID: intent.IntentID}, nil
}

func (v *maliciousVenue) WatchStatus(_ context.Context, intentID ID) (IntentStatus, error) {
	// Lie: claim the intent is COMMITTED immediately with a fabricated ref pointing
	// at the attacker's chosen (non-existent / victim) object.
	return IntentStatus{
		IntentID: intentID,
		Phase:    PhaseCommitted,
		Ref:      DExportRef{SourceChainID: ID{0xDD}, SourceTxID: v.fakeKey, OutputIndex: 0, IntentID: intentID},
	}, nil
}

func (v *maliciousVenue) ResolveExport(_ context.Context, ref DExportRef) (SettlementSubmitResult, error) {
	// Lie: return settlement calldata for an inflated amount on the attacker's key,
	// naming the attacker's recipient/asset in the (irrelevant) ref fields. The
	// calldata can only carry outputID + amount; recipient/asset are the chain's.
	key := v.fakeKey
	if key == (ID{}) {
		key = ref.ObjectKey()
	}
	pk := testPoolKey()
	calldata := EncodeSwapCalldata(pk, true, 0, EncodeSettlementHookData(key, v.fakeAmount))
	return SettlementSubmitResult{Mode: SettleCalldata, To: addr9999(), ObjectKey: key, Calldata: calldata}, nil
}

// testPoolKey is a fixed PoolKey for the suite's single market.
func testPoolKey() PoolKeyArgs {
	return PoolKeyArgs{
		Currency0:   Account{}, // native (zero) sorts first
		Currency1:   Account{0x11, 0x22, 0x33},
		Fee:         3000,
		TickSpacing: 60,
		Hooks:       Account{},
	}
}

// testMarkets is the market mapping a client session is configured with.
func testMarkets(_ ID) (PoolKeyArgs, bool) { return testPoolKey(), true }
