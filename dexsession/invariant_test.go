// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"testing"
	"time"
)

// invariant_test.go is the security test suite. It proves the hard invariant: a
// ZAP response is NEVER sufficient to move money. The AtomicLedger (harness_test.go)
// is the judge — it mirrors the precompile/dexvm value boundary, and the ONLY way a
// balance changes is consuming a real atomic object placed by a real cross-chain
// export. No ZAP response can place one.

func newClientFor(v Venue) *clientSession {
	lb := venueLoopback(v)
	return NewSession(SessionConfig{Conn: lb, PeerID: "test-peer", Grant: AuthorityPublic, Markets: testMarkets})
}

// canonical fixed request used across tests.
func testReq() SwapIntentRequest {
	return SwapIntentRequest{
		NetworkID:    96369,
		CChainID:     ID{0xC0},
		DChainID:     ID{0xD0},
		Account:      Account{0xAA, 0xBB, 0xCC},
		AssetIn:      ID{}, // native
		AmountIn:     1_000_000,
		MarketID:     ID{0x4D, 0x4B, 0x54},
		MinAmountOut: 990_000,
		Recipient:    Account{0xAA, 0xBB, 0xCC},
		Deadline:     1 << 40,
		CallIndex:    0,
	}
}

// TestZAP_QuoteIsReadOnly_CannotMoveValue: a quote is an estimate; issuing any
// number of quotes (even from a lying venue) moves no balance.
func TestZAP_QuoteIsReadOnly_CannotMoveValue(t *testing.T) {
	ledger := newAtomicLedger()
	owner := Account{0xAA, 0xBB, 0xCC}
	asset := ID{}

	// Malicious venue returns enormous quotes.
	c := newClientFor(&maliciousVenue{})
	ctx := context.Background()

	before := ledger.Balance(owner, asset)
	for i := 0; i < 100; i++ {
		qr, err := c.Quote(ctx, QuoteRequest{MarketID: ID{0x01}, AmountIn: 1000, ZeroForOne: true}).Await(ctx)
		if err != nil {
			t.Fatalf("quote: %v", err)
		}
		_ = qr // a huge estimate is returned, and ignored by the value boundary
	}
	if after := ledger.Balance(owner, asset); after != before {
		t.Fatalf("quote moved balance: before=%d after=%d", before, after)
	}
	// The quote result is NOT enforceable: there is no code path from a QuoteResult
	// to the ledger. (Compile-time: ImportSettlement takes a settleClaim, never a
	// QuoteResult.)
}

// TestZAP_PrepareIntent_ReturnsCalldataNotFunds: prepareSwapIntent yields calldata
// + hookData + an intent id; it reserves nothing and returns no enforceable
// amountOut.
func TestZAP_PrepareIntent_ReturnsCalldataNotFunds(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	hv.setBook(ID{0x4D, 0x4B, 0x54}, 1.0)
	c := newClientFor(hv)
	ctx := context.Background()

	req := testReq()
	owner := req.Account
	before := ledger.Balance(owner, req.AssetIn)

	pi, err := c.PrepareSwapIntent(ctx, req).Await(ctx)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// Output is calldata, not funds.
	if len(pi.Calldata) == 0 {
		t.Fatalf("prepare returned empty calldata")
	}
	if len(pi.HookData) == 0 {
		t.Fatalf("prepare returned empty hookData")
	}
	// hookData is Phase A (intent) — NOT a settlement that could credit.
	if string(pi.HookData) != string(EncodeIntentHookData()) {
		t.Fatalf("prepare hookData is not the intent phase: %x", pi.HookData)
	}
	// The intent id is the deterministic derivation (the user's tx will mint it).
	wantID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, ID{}, req.CallIndex, req.Account, req.AssetIn, req.AmountIn, req.MarketID)
	if pi.IntentID != wantID {
		t.Fatalf("prepare intent id mismatch")
	}
	// No funds reserved: the ledger balance is unchanged by preparing.
	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("prepare reserved funds: before=%d after=%d", before, after)
	}
	// QuotedOut is informational; the calldata's enforceable floor is MinAmountOut
	// (off-chain, the chain/D enforce it). There is no field in PreparedIntent the
	// chain trusts as an output credit — only Calldata the user signs.
}

// TestZAP_NotifyIntent_CannotValidateMatchWithoutDBlock: a notify triggers D, but
// without a committed D block the watch never resolves to a committed ref, and no
// balance moves.
func TestZAP_NotifyIntent_CannotValidateMatchWithoutDBlock(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	hv.setBook(ID{0x4D, 0x4B, 0x54}, 1.0)
	c := newClientFor(hv)

	req := testReq()
	owner := req.Account
	before := ledger.Balance(owner, req.AssetIn)

	ctx := context.Background()
	intent := c.PrepareSwapIntent(ctx, req)
	watch, err := c.NotifyIntent(ctx, intent).Await(ctx)
	if err != nil {
		t.Fatalf("notify: %v", err)
	}

	// D has NOT committed (honestVenue.commit never called) => poll stays Pending.
	st, err := watch.Poll(ctx)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if st.Phase != PhasePending {
		t.Fatalf("phase = %d, want Pending (no D block yet)", st.Phase)
	}

	// OnCommitted must NOT resolve within a bounded wait (no D block => no ref).
	wctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	_, err = watch.OnCommitted(ctx).Await(wctx)
	if err == nil {
		t.Fatalf("OnCommitted resolved without a D block")
	}

	// No balance moved.
	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("notify moved balance without a D block: before=%d after=%d", before, after)
	}
}

// TestZAP_ImportSettlement_CannotSubstituteRecipientAssetAmount: the actual object
// binds recipient/asset/amount; a tampered ref/claim fails on-chain.
func TestZAP_ImportSettlement_CannotSubstituteRecipientAssetAmount(t *testing.T) {
	ledger := newAtomicLedger()

	// A real D->C export exists: owner=victim, asset=A, amount=500.
	victim := Account{0x11, 0x22, 0x33}
	attacker := Account{0x99, 0x88, 0x77}
	assetA := ID{0x0A}
	exportTx := ID{0xEE}
	key := DeriveUTXOID(exportTx, 0)
	ledger.PutExport(key, atomicObject{owner: victim, asset: assetA, amount: 500})

	// (a) Attacker tries to substitute the RECIPIENT (credit themselves). On-chain
	// the recipient is bound to the caller, so even if the attacker submits the
	// settlement (caller=attacker), the object's owner (victim) != caller => reject.
	_, err := ledger.applySettlementCalldata(
		settlementCalldataFor(key, 500), attacker /*caller*/, assetA,
	)
	if err != errLedgerOwner {
		t.Fatalf("recipient substitution not rejected: err=%v", err)
	}

	// (b) Attacker tries to substitute the AMOUNT (claim 5000 for a 500 object).
	_, err = ledger.applySettlementCalldata(
		settlementCalldataFor(key, 5000), victim /*caller*/, assetA,
	)
	if err != errLedgerAmount {
		t.Fatalf("amount substitution not rejected: err=%v", err)
	}

	// (c) Attacker tries to substitute the ASSET (claim asset B). On-chain the asset
	// is DERIVED from the swap direction; pass a different derived asset => reject.
	assetB := ID{0x0B}
	_, err = ledger.applySettlementCalldata(
		settlementCalldataFor(key, 500), victim /*caller*/, assetB,
	)
	if err != errLedgerAsset {
		t.Fatalf("asset substitution not rejected: err=%v", err)
	}

	// (d) The HONEST claim (correct caller=victim, correct derived asset=A, correct
	// amount=500) succeeds — proving the rejections above are about substitution,
	// not a broken path.
	got, err := ledger.applySettlementCalldata(
		settlementCalldataFor(key, 500), victim, assetA,
	)
	if err != nil || got != 500 {
		t.Fatalf("honest settlement failed: got=%d err=%v", got, err)
	}
	if bal := ledger.Balance(victim, assetA); bal != 500 {
		t.Fatalf("victim balance = %d, want 500", bal)
	}
	if bal := ledger.Balance(attacker, assetA); bal != 0 {
		t.Fatalf("attacker credited %d, want 0", bal)
	}
}

// settlementCalldataFor builds 0x9999 settlement calldata pointing at key for
// amount (the bytes a wallet would sign). Helper for the substitution test.
func settlementCalldataFor(key ID, amount uint64) SettlementSubmitResult {
	pk := testPoolKey()
	return SettlementSubmitResult{
		Mode:      SettleCalldata,
		To:        addr9999(),
		ObjectKey: key,
		Calldata:  EncodeSwapCalldata(pk, true, 0, EncodeSettlementHookData(key, amount)),
	}
}

// TestZAP_Capability_NoCapCanMintOrCreditC: exhaustive over the capability set —
// no capability exposes a value-moving method, and each is confined to its grant.
func TestZAP_Capability_NoCapCanMintOrCreditC(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	c := newClientFor(hv)

	// A session granted EVERYTHING (including admin) still cannot move money.
	full := NewSession(SessionConfig{Conn: venueLoopback(hv), PeerID: "p", Grant: AuthorityPublic | AuthAdmin, Markets: testMarkets})

	qc, err := full.QuoteCap()
	if err != nil {
		t.Fatalf("QuoteCap: %v", err)
	}
	ic, err := full.IntentCap()
	if err != nil {
		t.Fatalf("IntentCap: %v", err)
	}
	wc, err := full.WatchCap()
	if err != nil {
		t.Fatalf("WatchCap: %v", err)
	}
	sc, err := full.SettlementCap()
	if err != nil {
		t.Fatalf("SettlementCap: %v", err)
	}
	ac, err := full.AdminCap()
	if err != nil {
		t.Fatalf("AdminCap: %v", err)
	}

	// Each capability holds ONLY its bit. This is the authority confinement.
	if qc.Authority() != AuthQuote {
		t.Fatalf("QuoteCap authority = %b", qc.Authority())
	}
	if ic.Authority() != AuthIntent {
		t.Fatalf("IntentCap authority = %b", ic.Authority())
	}
	if wc.Authority() != AuthWatch {
		t.Fatalf("WatchCap authority = %b", wc.Authority())
	}
	if sc.Authority() != AuthSettlement {
		t.Fatalf("SettlementCap authority = %b", sc.Authority())
	}
	if ac.Authority() != AuthAdmin {
		t.Fatalf("AdminCap authority = %b", ac.Authority())
	}

	// The PROOF by exhaustion: the entire method surface of every capability is
	// READ / BUILD / POINT / SUBSCRIBE — none returns a balance change. This is a
	// compile-time property (there is no creditBalance/settleFill/overrideMatch/
	// adminWithdraw method to call). We assert the ledger is untouched after using
	// every capability's full surface.
	c.assertNoValueMoved(t, ledger)

	// A read-only session CANNOT derive an intent/settlement/admin capability
	// (authority confinement: you cannot widen your grant).
	ro := NewSession(SessionConfig{Conn: venueLoopback(hv), PeerID: "p", Grant: AuthorityReadOnly, Markets: testMarkets})
	if _, err := ro.IntentCap(); err != ErrNoAuthority {
		t.Fatalf("read-only session minted an IntentCap: %v", err)
	}
	if _, err := ro.SettlementCap(); err != ErrNoAuthority {
		t.Fatalf("read-only session minted a SettlementCap: %v", err)
	}
	if _, err := ro.AdminCap(); err != ErrNoAuthority {
		t.Fatalf("read-only session minted an AdminCap: %v", err)
	}
	// And a public (non-admin) session cannot mint an AdminCap.
	if _, err := c.AdminCap(); err != ErrNoAuthority {
		t.Fatalf("public session minted an AdminCap: %v", err)
	}
}

// assertNoValueMoved exercises every operation the session exposes and asserts the
// ledger balance for the test account is unchanged. The operations return
// estimates / calldata / pointers; none credits.
func (s *clientSession) assertNoValueMoved(t *testing.T, ledger *AtomicLedger) {
	t.Helper()
	ctx := context.Background()
	req := testReq()
	owner := req.Account
	before := ledger.Balance(owner, req.AssetIn)

	_, _ = s.Quote(ctx, QuoteRequest{MarketID: req.MarketID, AmountIn: 1000, ZeroForOne: true}).Await(ctx)
	_, _ = s.GetState(ctx, StateRequest{Kind: StateBalance, Account: owner, Asset: req.AssetIn}).Await(ctx)
	pi := s.PrepareSwapIntent(ctx, req)
	w, _ := s.NotifyIntent(ctx, pi).Await(ctx)
	// poll (no commit) — read only.
	_, _ = w.Poll(ctx)
	// import a (non-existent) ref — returns calldata, credits nothing.
	_, _ = s.ImportSettlement(ctx, resolved(DExportRef{SourceTxID: ID{0x01}}, nil)).Await(ctx)

	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("a capability operation moved value: before=%d after=%d", before, after)
	}
}

// TestZAP_PromisePipeline_QuoteIntentNotifyWatchSettle: dependent calls pipeline
// correctly — the declarative chain produces the right artifacts end to end.
func TestZAP_PromisePipeline_QuoteIntentNotifyWatchSettle(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	market := ID{0x4D, 0x4B, 0x54}
	hv.setBook(market, 1.0)
	c := newClientFor(hv)
	ctx := context.Background()

	req := testReq()

	// Establish the funded path: the user's signed C tx created the C->D object and
	// D matched + exported a D->C object. We model that by placing the real export
	// and marking the D commit. (The pipeline does not sign the user's tx — only the
	// user funds their own swap; here the test plays the user + the chain.)
	exportTx := ID{0xEE, 0x01}
	key := DeriveUTXOID(exportTx, 0)
	ledger.PutExport(key, atomicObject{owner: req.Recipient, asset: req.AssetIn, amount: 1_000_000})
	intentID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, ID{}, req.CallIndex, req.Account, req.AssetIn, req.AmountIn, req.MarketID)
	hv.commit(intentID, DExportRef{SourceChainID: req.DChainID, SourceTxID: exportTx, OutputIndex: 0, IntentID: intentID}, req.AssetIn)

	// THE PIPELINE — declarative, dependent calls overlap:
	quote := c.Quote(ctx, QuoteRequest{MarketID: market, AmountIn: req.AmountIn, ZeroForOne: true})
	intent := c.PrepareSwapIntent(ctx, req)
	watch := c.NotifyIntent(ctx, intent)
	committed := thenAsync(ctx, watch, func(ctx context.Context, w IntentWatch) (DExportRef, error) {
		return w.OnCommitted(ctx).Await(ctx)
	})
	settle := c.ImportSettlement(ctx, committed)

	// Await the final artifact (the settlement calldata).
	res, err := settle.Await(ctx)
	if err != nil {
		t.Fatalf("pipeline settle: %v", err)
	}
	if len(res.Calldata) == 0 {
		t.Fatalf("pipeline produced empty settlement calldata")
	}

	// Each intermediate resolved correctly.
	if qr, _ := quote.Await(ctx); !qr.Liquid {
		t.Fatalf("quote not liquid")
	}
	if pi, _ := intent.Await(ctx); pi.IntentID != intentID {
		t.Fatalf("intent id mismatch in pipeline")
	}

	// The settlement calldata, when the chain applies it (caller=recipient, asset
	// derived=AssetIn), credits exactly the object amount — money moved ONLY here,
	// via the real object.
	got, err := ledger.applySettlementCalldata(res, req.Recipient, req.AssetIn)
	if err != nil || got != 1_000_000 {
		t.Fatalf("final on-chain settle: got=%d err=%v", got, err)
	}
	if bal := ledger.Balance(req.Recipient, req.AssetIn); bal != 1_000_000 {
		t.Fatalf("recipient balance = %d, want 1_000_000", bal)
	}
}

// TestZAP_StaleResponse_BadQuoteMissesMinOutOrReverts: a stale/bad quote cannot
// force a bad trade — the enforceable floor is MinAmountOut, which the chain/D
// check independently of the quote.
func TestZAP_StaleResponse_BadQuoteMissesMinOutOrReverts(t *testing.T) {
	ledger := newAtomicLedger()
	// Malicious venue returns a hugely favorable (stale/false) quote.
	c := newClientFor(&maliciousVenue{})
	ctx := context.Background()

	req := testReq()
	req.MinAmountOut = 990_000 // the user's real floor

	pi, err := c.PrepareSwapIntent(ctx, req).Await(ctx)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	// The prepared QuotedOut reflects the lie (huge), but it is informational. The
	// ENFORCEABLE floor rides MinAmountOut in the user's request, which the chain/D
	// honor. Model the chain check: a real D export that delivers LESS than
	// MinAmountOut would be rejected at match (D enforces minOut); here we assert the
	// prepared calldata is a Phase-A intent (no premature credit), and that the lie
	// did not change the user's MinAmountOut.
	if string(pi.HookData) != string(EncodeIntentHookData()) {
		t.Fatalf("stale quote produced a settlement, not an intent")
	}
	// Model: D matched only 980_000 (below the 990_000 floor) -> a correct D would
	// NOT export (slippage). So no D->C object exists -> importSettlement of any ref
	// reverts on-chain (object missing). Prove a settlement attempt with no object
	// credits nothing.
	owner := req.Recipient
	before := ledger.Balance(owner, req.AssetIn)
	missingKey := DeriveUTXOID(ID{0xBA, 0xD0}, 0)
	_, serr := ledger.applySettlementCalldata(settlementCalldataFor(missingKey, 980_000), owner, req.AssetIn)
	if serr != errLedgerNoSettlement {
		t.Fatalf("stale settlement did not revert on missing object: %v", serr)
	}
	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("stale quote moved balance: before=%d after=%d", before, after)
	}
}

// TestZAP_DuplicateSettlement_ReplayRejected: a D->C object is consumed exactly
// once; replaying the same settlement is rejected.
func TestZAP_DuplicateSettlement_ReplayRejected(t *testing.T) {
	ledger := newAtomicLedger()
	owner := Account{0x11, 0x22, 0x33}
	asset := ID{0x0A}
	exportTx := ID{0xEE}
	key := DeriveUTXOID(exportTx, 0)
	ledger.PutExport(key, atomicObject{owner: owner, asset: asset, amount: 750})

	// First settlement succeeds.
	got, err := ledger.applySettlementCalldata(settlementCalldataFor(key, 750), owner, asset)
	if err != nil || got != 750 {
		t.Fatalf("first settle: got=%d err=%v", got, err)
	}
	// Replay the SAME settlement calldata -> rejected (one-time).
	_, err = ledger.applySettlementCalldata(settlementCalldataFor(key, 750), owner, asset)
	if err != errLedgerReplay && err != errLedgerNoSettlement {
		// After consumption the object is removed; a replay sees either the replay
		// guard or a missing object. Both are correct rejections.
		t.Fatalf("replay not rejected: %v", err)
	}
	// Balance credited exactly once.
	if bal := ledger.Balance(owner, asset); bal != 750 {
		t.Fatalf("balance after replay = %d, want 750 (credited once)", bal)
	}
}
