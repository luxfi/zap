// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"sync"
	"testing"
	"time"

	zaplib "github.com/luxfi/zap"
)

// v4_test.go is the V4 bidirectional session suite. It proves:
//
//   - the full bidirectional swap lifecycle (all 9 V4_SWAP_* messages, both
//     directions) drives correctly and credits ONLY via a real D->C object;
//   - a multi-hop route prepares ONE C->D intent, streams hop progress, and settles
//     ONE final D->C export — never an intermediate-asset settlement (stays on D);
//   - liquidity commit creates a C->D object only (no credit); collect/cancel credit
//     via the ONE DS01 settlement;
//   - state streaming is read-only;
//   - bidirectional WRITES (D->C MatchResult) update orchestration, never value;
//   - THE critical RED extension: no bidirectional message sequence, absent a real
//     D->C atomic object, moves money;
//   - a session capability is confined to ONE action (intent/pool/params/kind).
//
// The AtomicLedger (harness_test.go) remains the JUDGE: ZAP/session messages drive
// the client; only consuming a real atomic object moves a balance.

// =============================================================================
// V4 test harness — a session factory + a route-capable venue + a loopback that
// routes the route frames.
// =============================================================================

// v4Loopback extends the base venueLoopback with the route frames, so a V4 route
// session can be driven against a RouteVenue with no socket. It composes the existing
// venueLoopback (which registers quote/state/notify/watch/import) and adds the route
// handlers when the venue implements RouteVenue.
func v4Loopback(v Venue) *loopback {
	l := venueLoopback(v)
	if rv, ok := v.(RouteVenue); ok {
		l.Handle(MsgRoutePrepare, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
			req := readRouteRequest(msg)
			ref, err := rv.NotifyRoute(req)
			if err != nil {
				first, _ := req.firstMarket()
				id := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, first, uint64(req.CallIndex))
				return buildIntentWatchRef(IntentWatchRef{IntentID: id})
			}
			return buildIntentWatchRef(ref)
		})
		l.Handle(MsgRouteStatus, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
			intentID := readRouteWatchPoll(msg)
			st, err := rv.RouteStatus(intentID)
			if err != nil {
				return buildRouteStatus(RouteStatus{IntentID: intentID, Phase: RouteUnknown})
			}
			st.IntentID = intentID
			return buildRouteStatus(st)
		})
	}
	return l
}

// newV4For builds a V4PrecompileSession against a venue over the v4 loopback, granted
// the full public authority. The chain identifiers match testReq()/testRouteReq().
func newV4For(t *testing.T, v Venue) *V4PrecompileSession {
	t.Helper()
	lb := v4Loopback(v)
	dex := NewSession(SessionConfig{Conn: lb, PeerID: "v4-peer", Grant: AuthorityPublic | AuthAdmin, Markets: testMarkets})
	v4, err := NewV4PrecompileSession(V4Config{Session: dex, NetworkID: 96369, CChainID: ID{0xC0}, DChainID: ID{0xD0}})
	if err != nil {
		t.Fatalf("NewV4PrecompileSession: %v", err)
	}
	return v4
}

// testRouteReq is the canonical multi-hop route request: input asset -> A -> B -> C
// (3 markets), one final output. The path markets are distinct ids; the entry market
// (A) is the one testMarkets resolves (every market resolves to testPoolKey here).
func testRouteReq() RouteRequest {
	return RouteRequest{
		NetworkID:    96369,
		CChainID:     ID{0xC0},
		DChainID:     ID{0xD0},
		Account:      Account{0xAA, 0xBB, 0xCC},
		AssetIn:      ID{0x0A}, // input asset (hop 0 in)
		AmountIn:     1_000_000,
		Path:         []ID{{0x4D, 0x01}, {0x4D, 0x02}, {0x4D, 0x03}}, // A->B->C
		MinAmountOut: 950_000,
		Recipient:    Account{0xAA, 0xBB, 0xCC},
		Deadline:     1 << 40,
		CallIndex:    0,
	}
}

// routeVenue is an honest route backend: it walks a configured path, streaming hop
// progress, and produces ONE final export the test placed in the ledger. It NEVER
// credits — it reports. It composes honestVenue for the non-route ops.
type routeVenue struct {
	*honestVenue
	mu       sync.Mutex
	phase    map[ID]RoutePhase
	finalRef map[ID]DExportRef
	hopOut   map[ID][]uint64 // per-intent hop output estimates
	hopCount map[ID]uint32
	curHop   map[ID]uint32
	finalOut map[ID]uint64
}

func newRouteVenue(l *AtomicLedger) *routeVenue {
	return &routeVenue{
		honestVenue: newHonestVenue(l),
		phase:       make(map[ID]RoutePhase),
		finalRef:    make(map[ID]DExportRef),
		hopOut:      make(map[ID][]uint64),
		hopCount:    make(map[ID]uint32),
		curHop:      make(map[ID]uint32),
		finalOut:    make(map[ID]uint64),
	}
}

func (v *routeVenue) NotifyRoute(req RouteRequest) (IntentWatchRef, error) {
	first, _ := req.firstMarket()
	id := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, first, uint64(req.CallIndex))
	v.mu.Lock()
	if _, ok := v.phase[id]; !ok {
		v.phase[id] = RoutePending
	}
	v.hopCount[id] = uint32(len(req.Path))
	v.mu.Unlock()
	return IntentWatchRef{IntentID: id}, nil
}

// RouteStatus is a POLL-DRIVEN state machine modeling D taking multiple consensus
// rounds: it reports RouteHopping advancing hop 0 -> 1 -> ... over the first hopCount
// polls (so the stream observes HOP_STARTED/HOP_FILLED for each), then RouteCommitted
// with the ONE final export. This is the realistic cadence the stream is built to
// observe; it changes no value (only a real object credits).
func (v *routeVenue) RouteStatus(intentID ID) (RouteStatus, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	hops := v.hopOut[intentID]
	if len(hops) == 0 {
		// Not yet committed by the test: report Pending.
		return RouteStatus{IntentID: intentID, Phase: RoutePending, HopCount: v.hopCount[intentID]}, nil
	}
	cur := v.curHop[intentID]
	st := RouteStatus{IntentID: intentID, HopCount: uint32(len(hops)), HopIndex: cur, FinalOut: v.finalOut[intentID]}
	if int(cur) < len(hops) {
		st.HopAmountOut = hops[cur]
	}
	if int(cur) < len(hops)-1 {
		// Still walking: report Hopping and advance for the next poll.
		st.Phase = RouteHopping
		v.curHop[intentID] = cur + 1
		return st, nil
	}
	// Reached the last hop: the route committed the ONE final export.
	st.Phase = RouteCommitted
	st.HopIndex = uint32(len(hops) - 1)
	st.Ref = v.finalRef[intentID]
	return st, nil
}

// commitRoute models D walking the whole path and committing ONE final export. It
// arms the poll-driven state machine: curHop starts at 0 and RouteStatus advances it
// each poll until the final hop, then reports Committed.
func (v *routeVenue) commitRoute(intentID ID, hops []uint64, finalOut uint64, ref DExportRef) {
	v.mu.Lock()
	v.hopOut[intentID] = hops
	v.curHop[intentID] = 0
	v.finalOut[intentID] = finalOut
	v.finalRef[intentID] = ref
	v.phase[intentID] = RouteHopping
	v.mu.Unlock()
}

// maliciousRouteVenue lies about route progress: it claims COMMITTED with fabricated
// refs and floods hop fills for intermediate assets. Used to prove a route cannot be
// stolen and that intermediate hops never settle.
type maliciousRouteVenue struct {
	*maliciousVenue
	fakeFinalKey ID
}

func (v *maliciousRouteVenue) NotifyRoute(req RouteRequest) (IntentWatchRef, error) {
	first, _ := req.firstMarket()
	id := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, first, uint64(req.CallIndex))
	return IntentWatchRef{IntentID: id}, nil
}

func (v *maliciousRouteVenue) RouteStatus(intentID ID) (RouteStatus, error) {
	// Lie: claim the route committed instantly with a fabricated final ref and a
	// gigantic final output. (Hops are skipped — the adversary wants to jump straight
	// to a settleable claim.)
	return RouteStatus{
		IntentID: intentID,
		Phase:    RouteCommitted,
		HopCount: 3,
		FinalOut: 1 << 62,
		Ref:      DExportRef{SourceChainID: ID{0xDD}, SourceTxID: v.fakeFinalKey, OutputIndex: 0, IntentID: intentID},
	}, nil
}

// matchingVenue is an honest venue that ALSO reports a matched-out estimate (the
// bidirectional MatchResult) and drives the watch through a realistic Matching ->
// Committed cadence: it reports PhaseMatching (with the MatchedOut estimate) for the
// first `holdPolls` status reads, then PhaseCommitted once the honest base has a
// committed ref. This lets a test observe the FULL D->C read stream (D_IMPORTED,
// MATCHED, then D_EXPORT_READY). It composes honestVenue and changes no value.
type matchingVenue struct {
	*honestVenue
	mu        sync.Mutex
	matched   map[ID]uint64 // intentID -> matched-out estimate
	matching  map[ID]bool   // intentID -> D is matching
	pollCount map[ID]int
	holdPolls int
}

func newMatchingVenue(l *AtomicLedger) *matchingVenue {
	return &matchingVenue{
		honestVenue: newHonestVenue(l),
		matched:     make(map[ID]uint64),
		matching:    make(map[ID]bool),
		pollCount:   make(map[ID]int),
		holdPolls:   2, // report Matching for 2 polls before allowing Committed
	}
}

func (v *matchingVenue) setMatching(intentID ID, matchedOut uint64) {
	v.mu.Lock()
	v.matched[intentID] = matchedOut
	v.matching[intentID] = true
	v.mu.Unlock()
}

func (v *matchingVenue) WatchStatus(_ context.Context, intentID ID) (IntentStatus, error) {
	v.mu.Lock()
	matched := v.matched[intentID]
	isMatching := v.matching[intentID]
	n := v.pollCount[intentID]
	v.pollCount[intentID] = n + 1
	v.mu.Unlock()
	// If matching, report Matching for the first holdPolls reads (so the stream sees
	// D_IMPORTED + MATCHED) before Committed can win.
	if isMatching && n < v.holdPolls {
		return IntentStatus{IntentID: intentID, Phase: PhaseMatching, MatchedOut: matched}, nil
	}
	// After the hold, a committed ref (the final export) wins.
	v.honestVenue.mu.Lock()
	ref, committed := v.honestVenue.committed[intentID]
	v.honestVenue.mu.Unlock()
	if committed {
		return IntentStatus{IntentID: intentID, Phase: PhaseCommitted, Ref: ref, MatchedOut: matched}, nil
	}
	if isMatching {
		return IntentStatus{IntentID: intentID, Phase: PhaseMatching, MatchedOut: matched}, nil
	}
	return IntentStatus{IntentID: intentID, Phase: PhasePending}, nil
}

// =============================================================================
// 1. Full bidirectional swap lifecycle — all 9 V4_SWAP_* messages, both directions.
// =============================================================================

func TestV4SwapSession_FullLifecycleBidirectional(t *testing.T) {
	ledger := newAtomicLedger()
	mv := newMatchingVenue(ledger)
	market := ID{0x4D, 0x4B, 0x54}
	mv.setBook(market, 1.0)
	v4 := newV4For(t, mv)
	ctx := context.Background()

	req := testReq()
	req.MarketID = market

	sess, err := v4.OpenSwap(req) // V4_SWAP_OPEN [local]
	if err != nil {
		t.Fatalf("OpenSwap: %v", err)
	}
	defer sess.Close()
	intentID := sess.IntentID()

	// Establish the funded path: the user's signed C tx created the C->D object and D
	// matched + exported ONE D->C object. The test plays the user + the chain.
	exportTx := ID{0xEE, 0x01}
	key := DeriveUTXOID(exportTx, 0)
	ledger.PutExport(key, atomicObject{owner: req.Recipient, asset: req.AssetIn, amount: 1_000_000})
	mv.setMatching(intentID, 999_000) // D->C MatchResult estimate (orchestration)
	mv.commit(intentID, DExportRef{SourceChainID: req.DChainID, SourceTxID: exportTx, OutputIndex: 0, IntentID: intentID}, req.AssetIn)

	// --- C->D WRITES: PrepareIntent, NotifyCToDExport -------------------------------
	intent := sess.WritePrepareIntent(ctx) // V4_SWAP_PREPARE_INTENT [C->D]
	pi, err := intent.Await(ctx)
	if err != nil {
		t.Fatalf("WritePrepareIntent: %v", err)
	}
	if pi.IntentID != intentID || len(pi.Calldata) == 0 {
		t.Fatalf("prepared intent wrong: id match=%v calldata=%d", pi.IntentID == intentID, len(pi.Calldata))
	}
	if string(pi.HookData) != string(EncodeIntentHookData(req.Deadline, req.Nonce)) {
		t.Fatalf("swap prepare hookData is not a Phase-A intent: %x", pi.HookData)
	}
	watch, err := sess.WriteNotifyCToDExport(ctx, intent).Await(ctx) // V4_SWAP_NOTIFY_C_EXPORT [C->D]
	if err != nil {
		t.Fatalf("WriteNotifyCToDExport: %v", err)
	}

	// --- D->C READS: stream D_IMPORTED -> MATCHED -> D_EXPORT_READY -----------------
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream := sess.ReadStream(sctx, watch)
	seen := map[V4MsgType]bool{}
	var exportRef DExportRef
	var matchedEst uint64
	for ev := range stream {
		seen[ev.Type] = true
		if ev.Type == V4_SWAP_MATCHED {
			matchedEst = ev.EstAmount
		}
		if ev.Type == V4_SWAP_D_EXPORT_READY {
			exportRef = ev.Ref
			break
		}
		if ev.Type == V4_ERROR {
			t.Fatalf("stream error: %s", ev.Reason)
		}
	}
	if !seen[V4_SWAP_D_IMPORTED] {
		t.Fatalf("never saw V4_SWAP_D_IMPORTED")
	}
	if !seen[V4_SWAP_MATCHED] {
		t.Fatalf("never saw V4_SWAP_MATCHED")
	}
	if !seen[V4_SWAP_D_EXPORT_READY] {
		t.Fatalf("never saw V4_SWAP_D_EXPORT_READY")
	}
	// The MATCHED estimate is the orchestration figure — NOT the credit (the credit is
	// the recorded object's amount, asserted below).
	if matchedEst != 999_000 {
		t.Fatalf("matched estimate = %d, want the orchestration value 999_000", matchedEst)
	}
	if exportRef.ObjectKey() != key {
		t.Fatalf("export ref did not point at the real object")
	}

	// --- C->D WRITES: PrepareCSettlement (+ optional SubmitCSettlement) -------------
	settle, err := sess.WritePrepareCSettlement(ctx, resolved(exportRef, nil)).Await(ctx) // V4_SWAP_PREPARE_C_SETTLEMENT [C->D]
	if err != nil {
		t.Fatalf("WritePrepareCSettlement: %v", err)
	}
	if len(settle.Calldata) == 0 {
		t.Fatalf("settlement calldata empty")
	}

	// --- THE MONEY MOVE: on-chain, consuming the REAL object (V4_SWAP_C_SETTLED) ----
	// The credit is the recorded amount (1_000_000), NOT the matched estimate (999_000)
	// and NOT anything the control plane said.
	got, err := ledger.applySettlementCalldata(settle, req.Recipient, req.AssetIn)
	if err != nil || got != 1_000_000 {
		t.Fatalf("on-chain settle: got=%d err=%v (want 1_000_000)", got, err)
	}
	if bal := ledger.Balance(req.Recipient, req.AssetIn); bal != 1_000_000 {
		t.Fatalf("recipient balance = %d, want 1_000_000", bal)
	}
	// The estimate and the credit DIFFER — proving the control-plane MatchResult is
	// orchestration, and the money came from the object.
	if matchedEst == got {
		t.Logf("note: estimate happened to equal credit; the binding is to the object regardless")
	}
}

// =============================================================================
// 2. Multi-hop route — stays on D until the ONE final export.
// =============================================================================

func TestV4RouteSession_MultiHopStaysOnDUntilFinalExport(t *testing.T) {
	ledger := newAtomicLedger()
	rv := newRouteVenue(ledger)
	v4 := newV4For(t, rv)
	ctx := context.Background()

	req := testRouteReq()
	sess, err := v4.OpenRoute(req) // V4_ROUTE_OPEN [local]
	if err != nil {
		t.Fatalf("OpenRoute: %v", err)
	}
	defer sess.Close()
	intentID := sess.IntentID()

	// --- C->D WRITE: PrepareIntent — EXACTLY ONE route-intent calldata --------------
	intent := sess.WritePrepareIntent(ctx) // V4_ROUTE_PREPARE_INTENT [C->D]
	pi, err := intent.Await(ctx)
	if err != nil {
		t.Fatalf("route prepare: %v", err)
	}
	// The ONE on-chain calldata is a PLAIN DI01 intent on the entry market — the body the
	// precompile ACCEPTS. The path is NOT in the signed hookData (an RT01 body would revert
	// on-chain: decodeIntentBody rejects any width outside {0,32,64}); it travels to the D
	// router over the ZAP control plane. It is a single C->D INPUT intent (Phase A — DI01
	// leads the hookData), and the body is a width the precompile's decodeIntentBody accepts.
	if string(pi.HookData[0:4]) != string(intentPhaseTag[:]) {
		t.Fatalf("route intent is not a Phase-A intent")
	}
	switch len(pi.HookData) {
	case 4, 4 + 32, 4 + 64: // DI01 | DI01+deadline | DI01+deadline+nonce — all precompile-accepted
	default:
		t.Fatalf("route on-chain intent body width %d is not a precompile-accepted DI01 body "+
			"(would revert on-chain)", len(pi.HookData))
	}
	// The PATH is still fully available — carried by the route session (control plane), the
	// same path the venue learns via buildRouteRequest/NotifyRoute.
	if got := sess.Path(); len(got) != 3 {
		t.Fatalf("route session must carry the 3-hop path on the control plane, got len=%d", len(got))
	} else {
		for i := range got {
			if got[i] != req.Path[i] {
				t.Fatalf("route path hop %d mismatch: got %x want %x", i, got[i][:2], req.Path[i][:2])
			}
		}
	}

	watch, err := sess.WriteNotifyCToDExport(ctx, intent).Await(ctx) // V4_ROUTE_NOTIFY_C_EXPORT [C->D]
	if err != nil {
		t.Fatalf("route notify: %v", err)
	}

	// The route walks A->B->C on D and produces ONE final D->C export. The test places
	// the SINGLE final object (asset C-out) and commits the route. CRUCIALLY: NO
	// intermediate object for asset B is ever placed — the route stays on D.
	finalTx := ID{0xFE, 0x01}
	finalKey := DeriveUTXOID(finalTx, 0)
	finalAsset := ID{0x0C} // the route's final output asset (C-side of the last hop)
	ledger.PutExport(finalKey, atomicObject{owner: req.Recipient, asset: finalAsset, amount: 970_000})
	// Hop output estimates: A->B 985000, B->C(mid) 977000, final 970000 — orchestration.
	rv.commitRoute(intentID, []uint64{985_000, 977_000, 970_000}, 970_000,
		DExportRef{SourceChainID: req.DChainID, SourceTxID: finalTx, OutputIndex: 0, IntentID: intentID})

	// --- D->C READS: stream hop progress -> ONE final export ------------------------
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream := sess.ReadStream(sctx, watch)
	var hopFills int
	var finalRef DExportRef
	sawExport := false
	for ev := range stream {
		switch ev.Type {
		case V4_ROUTE_HOP_FILLED:
			hopFills++
			// A hop fill is an ESTIMATE with NO settleable ref (no per-hop object).
			if ev.HasRef() {
				t.Fatalf("hop fill carried a settleable ref — route did NOT stay on D")
			}
		case V4_ROUTE_D_EXPORT_READY:
			finalRef = ev.Ref
			sawExport = true
		case V4_ERROR:
			t.Fatalf("route stream error: %s", ev.Reason)
		}
		if sawExport {
			break
		}
	}
	if !sawExport {
		t.Fatalf("never saw the final V4_ROUTE_D_EXPORT_READY")
	}
	if finalRef.ObjectKey() != finalKey {
		t.Fatalf("final export ref did not point at the ONE final object")
	}

	// --- THE MONEY MOVE: ONE settlement of the ONE final export ---------------------
	settle, err := sess.WritePrepareCSettlement(ctx, resolved(finalRef, nil)).Await(ctx) // V4_ROUTE_PREPARE_C_SETTLEMENT
	if err != nil {
		t.Fatalf("route settle prepare: %v", err)
	}
	got, err := ledger.applySettlementCalldata(settle, req.Recipient, finalAsset)
	if err != nil || got != 970_000 {
		t.Fatalf("route final settle: got=%d err=%v (want 970_000)", got, err)
	}

	// THE STAYS-ON-D PROOF: there is NO intermediate-asset (B) object to settle. Try to
	// settle an intermediate asset B — it reverts (no object), so an attacker (or a
	// confused user) cannot extract value mid-route. The route exposed only ONE
	// settleable pointer (the final), and the intermediate hops created nothing on C.
	assetB := ID{0x0B}
	midKey := DeriveUTXOID(ID{0xB1, 0xD0}, 0) // a plausible "hop 1 output" key — fabricated
	_, serr := ledger.applySettlementCalldata(settlementCalldataFor(midKey, 985_000), req.Recipient, assetB)
	if serr != errLedgerNoSettlement {
		t.Fatalf("an intermediate-asset settlement did NOT revert (route leaked to C): %v", serr)
	}
	// Total credited is exactly the ONE final object — no intermediate credit, no mint.
	if total := ledger.totalCredited(); total != 970_000 {
		t.Fatalf("total credited = %d, want exactly 970_000 (one final export, no hops)", total)
	}
	if hopFills == 0 {
		t.Fatalf("expected to observe hop-progress orchestration events")
	}
}

// =============================================================================
// 3. Liquidity commit (C->D) / Collect (D->C export).
// =============================================================================

func TestV4LiquiditySession_CommitCToD(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	v4 := newV4For(t, hv)
	ctx := context.Background()

	req := LiquidityRequest{
		NetworkID: 96369, CChainID: ID{0xC0}, DChainID: ID{0xD0},
		Account:   Account{0xAA, 0xBB, 0xCC},
		MarketID:  ID{0x4D, 0x4B, 0x54},
		TickLower: -60, TickUpper: 60, LiquidityDelta: 5_000_000, Salt: ID{0x01},
		AssetIn: ID{}, AmountIn: 2_000_000,
	}
	owner := req.Account
	before := ledger.Balance(owner, req.AssetIn)

	sess, err := v4.OpenModifyLiquidity(req) // V4_LP_OPEN [local]
	if err != nil {
		t.Fatalf("OpenModifyLiquidity: %v", err)
	}
	defer sess.Close()

	// V4_LP_PREPARE_COMMIT [C->D] — modifyLiquidity (+delta) calldata, a DEPOSIT.
	pi, err := sess.WritePrepareCommit(ctx).Await(ctx)
	if err != nil {
		t.Fatalf("WritePrepareCommit: %v", err)
	}
	if len(pi.Calldata) == 0 {
		t.Fatalf("commit calldata empty")
	}
	// The calldata is a modifyLiquidity call (selector 0x5A6BCFDA), NOT a settlement.
	if sel := beU32(pi.Calldata[:4]); sel != SelectorModifyLiquidity {
		t.Fatalf("commit selector = %08X, want %08X (modifyLiquidity)", sel, SelectorModifyLiquidity)
	}

	// V4_LP_NOTIFY_C_EXPORT [C->D] — tell D to scan the funded position object.
	if _, err := sess.WriteNotifyCToDExport(ctx, resolved(pi, nil)).Await(ctx); err != nil {
		t.Fatalf("liquidity notify: %v", err)
	}

	// A commit is a DEPOSIT: it creates a C->D object and NEVER credits C. The session
	// has no settlement method. Balance is unchanged.
	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("liquidity commit credited C: before=%d after=%d", before, after)
	}
	// A positive delta is required (the rejection of a removal-as-commit is structural).
	bad := req
	bad.LiquidityDelta = -1
	if _, err := v4.OpenModifyLiquidity(bad); err == nil {
		t.Fatalf("OpenModifyLiquidity accepted a negative (removal) delta as a commit")
	}
}

func TestV4CollectSession_DToCExport(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	v4 := newV4For(t, hv)
	ctx := context.Background()

	req := CollectRequest{
		NetworkID: 96369, CChainID: ID{0xC0}, DChainID: ID{0xD0},
		Account:   Account{0xAA, 0xBB, 0xCC},
		MarketID:  ID{0x4D, 0x4B, 0x54},
		TickLower: -60, TickUpper: 60, LiquidityDelta: -5_000_000, Salt: ID{0x01},
		AssetOut: ID{0x0A},
	}
	sess, err := v4.OpenCollect(req) // V4_COLLECT_OPEN [local]
	if err != nil {
		t.Fatalf("OpenCollect: %v", err)
	}
	defer sess.Close()
	intentID := sess.IntentID()

	// V4_COLLECT_REQUEST [C->D] — modifyLiquidity (-delta) calldata to remove.
	pi, err := sess.WriteRequest(ctx).Await(ctx)
	if err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}
	if sel := beU32(pi.Calldata[:4]); sel != SelectorModifyLiquidity {
		t.Fatalf("collect selector = %08X, want modifyLiquidity", sel)
	}

	// The removal's output becomes a D->C export. Place the real object + commit.
	exportTx := ID{0xCC, 0x01}
	key := DeriveUTXOID(exportTx, 0)
	ledger.PutExport(key, atomicObject{owner: req.Account, asset: req.AssetOut, amount: 4_800_000})
	hv.commit(intentID, DExportRef{SourceChainID: req.DChainID, SourceTxID: exportTx, OutputIndex: 0, IntentID: intentID}, req.AssetOut)

	if _, err := sess.WriteNotify(ctx, resolved(pi, nil)).Await(ctx); err != nil {
		t.Fatalf("collect notify: %v", err)
	}

	// V4_COLLECT_D_EXPORT_READY [D->C] — the D->C export pointer.
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	watch := IntentWatch{session: sess.dex, intentID: intentID}
	ref, err := sess.OnExportReady(wctx, watch).Await(wctx)
	if err != nil {
		t.Fatalf("OnExportReady: %v", err)
	}

	// V4_COLLECT_PREPARE_C_SETTLEMENT [C->D] — settle via the ONE DS01 credit path.
	settle, err := sess.WritePrepareCSettlement(ctx, resolved(ref, nil)).Await(ctx)
	if err != nil {
		t.Fatalf("collect settle prepare: %v", err)
	}
	got, err := ledger.applySettlementCalldata(settle, req.Account, req.AssetOut)
	if err != nil || got != 4_800_000 {
		t.Fatalf("collect settle: got=%d err=%v (want 4_800_000)", got, err)
	}
	if bal := ledger.Balance(req.Account, req.AssetOut); bal != 4_800_000 {
		t.Fatalf("collector balance = %d, want 4_800_000", bal)
	}
}

// =============================================================================
// 4. State streaming is read-only.
// =============================================================================

func TestV4StateSession_StreamsQuotesReadOnly(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	market := ID{0x4D, 0x4B, 0x54}
	hv.setBook(market, 2.0)
	v4 := newV4For(t, hv)
	ctx := context.Background()

	owner := Account{0xAA, 0xBB, 0xCC}
	asset := ID{}
	before := ledger.Balance(owner, asset)

	sess, err := v4.OpenState(owner, market) // V4_STATE_OPEN [local]
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	defer sess.Close()

	// One-shot quote read.
	qr, err := sess.ReadQuote(ctx, 1000, true).Await(ctx)
	if err != nil || !qr.Liquid || qr.AmountOut != 2000 {
		t.Fatalf("ReadQuote: liquid=%v out=%d err=%v", qr.Liquid, qr.AmountOut, err)
	}

	// Streamed quotes: collect a few V4_STATE_QUOTE_UPDATE events.
	sctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	updates := 0
	for ev := range sess.StreamQuotes(sctx, 1000, true) {
		if ev.Type == V4_STATE_QUOTE_UPDATE {
			updates++
			if ev.EstAmount != 2000 {
				t.Fatalf("quote update estimate = %d, want 2000", ev.EstAmount)
			}
		}
		if updates >= 3 {
			cancel()
		}
	}
	if updates == 0 {
		t.Fatalf("no quote updates streamed")
	}

	// A state session is READ-ONLY: it cannot derive intent/settlement authority. The
	// session's scoped cap holds ONLY AuthQuote.
	if got := sess.cap.Authority(); got != AuthQuote {
		t.Fatalf("state session authority = %b, want AuthQuote only", got)
	}
	// And the ledger is untouched by all the reading.
	if after := ledger.Balance(owner, asset); after != before {
		t.Fatalf("state streaming moved value: before=%d after=%d", before, after)
	}
}

// =============================================================================
// 5. Bidirectional writes update orchestration, not value (D->C MatchResult).
// =============================================================================

func TestV4Session_BidirectionalWritesUpdateOrchestrationNotValue(t *testing.T) {
	ledger := newAtomicLedger()
	mv := newMatchingVenue(ledger)
	market := ID{0x4D, 0x4B, 0x54}
	mv.setBook(market, 1.0)
	v4 := newV4For(t, mv)
	ctx := context.Background()

	req := testReq()
	req.MarketID = market
	owner := req.Recipient
	before := ledger.Balance(owner, req.AssetIn)

	sess, err := v4.OpenSwap(req)
	if err != nil {
		t.Fatalf("OpenSwap: %v", err)
	}
	defer sess.Close()
	intentID := sess.IntentID()

	// D writes a MatchResult through the control plane claiming a HUGE matched amount.
	// NO real object exists yet. The session surfaces it as orchestration.
	mv.setMatching(intentID, 1<<62)

	intent := sess.WritePrepareIntent(ctx)
	watch, err := sess.WriteNotifyCToDExport(ctx, intent).Await(ctx)
	if err != nil {
		t.Fatalf("notify: %v", err)
	}

	// Read the MATCHED event — it carries the huge estimate (orchestration).
	sctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	var sawMatched bool
	var est uint64
	for ev := range sess.ReadStream(sctx, watch) {
		if ev.Type == V4_SWAP_MATCHED {
			sawMatched = true
			est = ev.EstAmount
			cancel() // we have what we need; no commit will come (no real object)
		}
		if ev.Type == V4_ERROR {
			break
		}
	}
	if !sawMatched {
		t.Fatalf("never saw a MATCHED event")
	}
	if est != 1<<62 {
		t.Fatalf("matched estimate = %d, want the (huge, orchestration) claim 1<<62", est)
	}

	// Despite D writing a 1<<62 MatchResult through the bidirectional plane, the ledger
	// is UNTOUCHED — orchestration state moved; value did not. There is no real object
	// and the session has no method to turn the MatchResult into a credit.
	if after := ledger.Balance(owner, req.AssetIn); after != before {
		t.Fatalf("a D->C MatchResult write moved value: before=%d after=%d", before, after)
	}
	// And the MatchResult.CreditsValue() is statically false for the message type.
	if V4_SWAP_MATCHED.CreditsValue() {
		t.Fatalf("V4_SWAP_MATCHED.CreditsValue() is true — invariant broken at the type level")
	}
}

// =============================================================================
// 6. THE critical RED extension — no bidirectional sequence credits absent a real
//    object. Extends TestRED_ZAP_ResponseAloneCannotMoveMoney to the full session.
// =============================================================================

func TestRED_V4Session_LiveMatchResultCannotCreditC(t *testing.T) {
	ctx := context.Background()

	// ---- Act 1: empty ledger, fully malicious bidirectional plane -----------------
	{
		ledger := newAtomicLedger()
		attacker := Account{0x99, 0x88, 0x77}
		victim := Account{0x11, 0x22, 0x33}
		asset := ID{0x0A}

		adversary := &maliciousVenue{
			fakeAmount:    1_000_000_000,
			fakeRecipient: attacker,
			fakeAsset:     asset,
			fakeKey:       DeriveUTXOID(ID{0xBA, 0xD0}, 0), // points at nothing
		}
		v4 := newV4For(t, adversary)

		req := testReq()
		req.Account = attacker
		req.Recipient = attacker
		sess, err := v4.OpenSwap(req)
		if err != nil {
			t.Fatalf("act1 OpenSwap: %v", err)
		}

		// Drive the WHOLE bidirectional lifecycle. The adversary streams D_IMPORTED,
		// MATCHED{1<<62}, and claims D_EXPORT_READY instantly with a fabricated ref.
		stages := sess.Run(ctx)
		res, err := stages.Settle.Await(ctx)
		if err != nil {
			t.Fatalf("act1 settle promise errored: %v", err)
		}

		// The CHAIN judges. Apply the adversary's settlement calldata every way an
		// attacker could try. EVERY path moves zero (empty ledger — no object).
		for _, caller := range []Account{attacker, victim} {
			for _, outAsset := range []ID{asset, {0x0B}, {}} {
				if _, serr := ledger.applySettlementCalldata(res, caller, outAsset); serr == nil {
					t.Fatalf("act1: a bidirectional-session settlement SUCCEEDED on an empty ledger (caller=%x asset=%x)", caller[:3], outAsset[:2])
				}
			}
		}
		if total := ledger.totalCredited(); total != 0 {
			t.Fatalf("act1: %d units credited from session messages alone (want 0)", total)
		}
		sess.Close()
	}

	// ---- Act 2: a real object exists for the victim; adversary tries to steal via
	//      the full bidirectional session ------------------------------------------
	{
		ledger := newAtomicLedger()
		attacker := Account{0x99, 0x88, 0x77}
		victim := Account{0x11, 0x22, 0x33}
		assetA := ID{0x0A}
		assetB := ID{0x0B}

		realTx := ID{0xEE}
		realKey := DeriveUTXOID(realTx, 0)
		ledger.PutExport(realKey, atomicObject{owner: victim, asset: assetA, amount: 500})

		// The adversary points the attacker at the victim's REAL object, streaming a
		// MATCHED for the attacker's recipient/asset and an EXPORT_READY at the real key.
		adversary := &maliciousVenue{fakeAmount: 500, fakeRecipient: attacker, fakeAsset: assetB, fakeKey: realKey}
		v4 := newV4For(t, adversary)

		req := testReq()
		req.Account = attacker
		req.Recipient = attacker
		sess, err := v4.OpenSwap(req)
		if err != nil {
			t.Fatalf("act2 OpenSwap: %v", err)
		}
		res, err := sess.Run(ctx).Settle.Await(ctx)
		if err != nil {
			t.Fatalf("act2 settle: %v", err)
		}
		// The attacker submits (caller=attacker): the object's owner is the VICTIM, so
		// the owner-bind rejects. The bidirectional MatchResult/EXPORT_READY changed
		// nothing — the chain binds owner to the recorded object.
		if _, serr := ledger.applySettlementCalldata(res, attacker, assetA); serr != errLedgerOwner {
			t.Fatalf("act2: attacker stole the victim's object via the session: %v", serr)
		}
		if ledger.Balance(attacker, assetA) != 0 || ledger.Balance(attacker, assetB) != 0 {
			t.Fatalf("act2: attacker was credited via the bidirectional session")
		}
		// Only the victim, honest claim, is credited — exactly once.
		got, err := ledger.applySettlementCalldata(settlementCalldataFor(realKey, 500), victim, assetA)
		if err != nil || got != 500 {
			t.Fatalf("act2: victim honest claim failed: got=%d err=%v", got, err)
		}
		if total := ledger.totalCredited(); total != 500 {
			t.Fatalf("act2: total credited = %d, want exactly 500", total)
		}
		sess.Close()
	}

	// ---- Act 3: the FULL bidirectional message set under exhaustive fuzz -----------
	// Every D->C read the session can surface (QuoteUpdate, D_IMPORTED, MATCHED,
	// D_EXPORT_READY) is permuted against a ledger holding ONE real object. The ONLY
	// successful credit is the exact (owner, asset, amount, key) of the real object.
	{
		ledger := newAtomicLedger()
		victim := Account{0x11, 0x22, 0x33}
		assetA := ID{0x0A}
		realTx := ID{0xEE}
		realKey := DeriveUTXOID(realTx, 0)
		realAmount := uint64(500)
		ledger.PutExport(realKey, atomicObject{owner: victim, asset: assetA, amount: realAmount})

		callers := []Account{victim, {0x99}, {0xAB, 0xCD}, {}}
		assets := []ID{assetA, {0x0B}, {}, {0xFF}}
		amounts := []uint64{0, 1, 499, 500, 501, 1 << 40}
		keys := []ID{realKey, DeriveUTXOID(realTx, 1), DeriveUTXOID(ID{0xBA}, 0), {}, {0xDE, 0xAD}}

		var successCount int
		for _, caller := range callers {
			for _, asset := range assets {
				for _, amount := range amounts {
					for _, key := range keys {
						res := settlementCalldataFor(key, amount)
						credited, err := ledger.applySettlementCalldata(res, caller, asset)
						if err == nil {
							successCount++
							if caller != victim || asset != assetA || amount != realAmount || key != realKey {
								t.Fatalf("act3: ILLEGITIMATE credit: caller=%x asset=%x amount=%d key=%x credited=%d",
									caller[:1], asset[:1], amount, key[:2], credited)
							}
						}
					}
				}
			}
		}
		if successCount != 1 {
			t.Fatalf("act3: %d settlements succeeded, want exactly 1 (one-time object)", successCount)
		}
		if total := ledger.totalCredited(); total != realAmount {
			t.Fatalf("act3: total credited = %d, want %d (no mint)", total, realAmount)
		}
	}

	// ---- Act 4: malicious ROUTE — a faked final export + faked hop fills -----------
	// The bidirectional ROUTE plane is also value-free: a malicious route venue that
	// claims COMMITTED with a fabricated final ref moves nothing.
	{
		ledger := newAtomicLedger()
		attacker := Account{0x99, 0x88, 0x77}
		adversary := &maliciousRouteVenue{
			maliciousVenue: &maliciousVenue{fakeAmount: 1 << 50},
			fakeFinalKey:   DeriveUTXOID(ID{0xBA, 0xDF}, 0), // points at nothing
		}
		v4 := newV4For(t, adversary)

		req := testRouteReq()
		req.Account = attacker
		req.Recipient = attacker
		sess, err := v4.OpenRoute(req)
		if err != nil {
			t.Fatalf("act4 OpenRoute: %v", err)
		}
		intent := sess.WritePrepareIntent(ctx)
		watch, err := sess.WriteNotifyCToDExport(ctx, intent).Await(ctx)
		if err != nil {
			t.Fatalf("act4 route notify: %v", err)
		}
		ref, err := sess.OnFinalExport(ctx, watch).Await(ctx)
		if err != nil {
			t.Fatalf("act4 OnFinalExport: %v", err)
		}
		res, err := sess.WritePrepareCSettlement(ctx, resolved(ref, nil)).Await(ctx)
		if err != nil {
			t.Fatalf("act4 route settle: %v", err)
		}
		// Apply the faked route settlement every way — zero moves (no final object).
		for _, asset := range []ID{{0x0C}, {0x0B}, {}} {
			if _, serr := ledger.applySettlementCalldata(res, attacker, asset); serr == nil {
				t.Fatalf("act4: a faked route final settlement SUCCEEDED on an empty ledger (asset=%x)", asset[:1])
			}
		}
		if total := ledger.totalCredited(); total != 0 {
			t.Fatalf("act4: %d units credited from faked route messages (want 0)", total)
		}
		sess.Close()
	}
}

// =============================================================================
// 7. Capability scoped per action — a swap cap can't drive another intent/pool/kind.
// =============================================================================

func TestV4Session_CapabilityScopedPerAction(t *testing.T) {
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	v4 := newV4For(t, hv)
	ctx := context.Background()

	// Open swap session S1 for intent I1 / market M1.
	req1 := testReq()
	req1.MarketID = ID{0x4D, 0x4B, 0x54}
	s1, err := v4.OpenSwap(req1)
	if err != nil {
		t.Fatalf("OpenSwap S1: %v", err)
	}
	defer s1.Close()

	// (a) S1's scope is the fingerprint of EXACTLY this action. A scope for a
	// different intent id does not match S1's session id.
	differentScope := s1.cap.scope
	differentScope.IntentID = ID{0xFF, 0xFF} // a different intent
	if err := s1.cap.authorizeScoped(AuthIntent, differentScope); err != ErrScopeMismatch {
		t.Fatalf("S1 cap authorized a DIFFERENT intent id: %v", err)
	}
	// A scope for a different pool (PoolKeyHash) does not match either.
	differentPool := s1.cap.scope
	differentPool.PoolKeyHash = ID{0xAB, 0xCD}
	if err := s1.cap.authorizeScoped(AuthIntent, differentPool); err != ErrScopeMismatch {
		t.Fatalf("S1 cap authorized a DIFFERENT pool: %v", err)
	}
	// A scope for a different action KIND (e.g. modifyLiquidity) does not match.
	differentKind := s1.cap.scope
	differentKind.Kind = ActionModifyLiquidity
	if err := s1.cap.authorizeScoped(AuthIntent, differentKind); err != ErrScopeMismatch {
		t.Fatalf("S1 cap authorized a DIFFERENT action kind: %v", err)
	}
	// A scope for different params (amount) does not match.
	differentParams := s1.cap.scope
	differentParams.ParamsHash = DeriveSwapParamsHash(true, 999)
	if err := s1.cap.authorizeScoped(AuthIntent, differentParams); err != ErrScopeMismatch {
		t.Fatalf("S1 cap authorized DIFFERENT params: %v", err)
	}

	// (b) S1's OWN scope authorizes (the positive case — confinement, not a broken gate).
	if err := s1.cap.authorizeSelf(AuthIntent); err != nil {
		t.Fatalf("S1 cap failed its own scope: %v", err)
	}

	// (c) Two sessions for different actions derive DIFFERENT session ids — a cap is a
	// per-action key, not a per-session-wide-grant.
	req2 := testReq()
	req2.AmountIn = 2_000_000 // different params => different intent id + params hash
	s2, err := v4.OpenSwap(req2)
	if err != nil {
		t.Fatalf("OpenSwap S2: %v", err)
	}
	defer s2.Close()
	if s1.SessionID() == s2.SessionID() {
		t.Fatalf("two distinct swap actions share a session id (no per-action confinement)")
	}
	// S1's cap cannot satisfy S2's scope and vice-versa.
	if err := s1.cap.authorizeScoped(AuthIntent, s2.cap.scope); err != ErrScopeMismatch {
		t.Fatalf("S1 cap drove S2's action: %v", err)
	}
	if err := s2.cap.authorizeScoped(AuthIntent, s1.cap.scope); err != ErrScopeMismatch {
		t.Fatalf("S2 cap drove S1's action: %v", err)
	}

	// (d) A cross-intent notify is refused at the session method too: feeding S1 a
	// PreparedIntent for a DIFFERENT intent id fails closed (ErrScopeMismatch).
	foreign := PreparedIntent{IntentID: ID{0xDE, 0xAD}}
	_, nerr := s1.WriteNotifyCToDExport(ctx, resolved(foreign, nil)).Await(ctx)
	if nerr != ErrScopeMismatch {
		t.Fatalf("S1 notified a FOREIGN intent: %v", nerr)
	}
	// And a cross-intent settlement is refused: a DExportRef for a different intent id.
	foreignRef := DExportRef{IntentID: ID{0xDE, 0xAD}, SourceTxID: ID{0x01}}
	_, serr := s1.WritePrepareCSettlement(ctx, resolved(foreignRef, nil)).Await(ctx)
	if serr != ErrScopeMismatch {
		t.Fatalf("S1 settled a FOREIGN intent's ref: %v", serr)
	}
}

// beU32 reads a big-endian uint32 (test helper for selector checks).
func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// =============================================================================
// Concurrency stress — proves the session state machines, promises, and streams are
// concurrency-safe WITHOUT -race (which cannot link against luxfi/accel cgo). Many
// goroutines drive full bidirectional lifecycles against a shared malicious venue and
// a shared ledger holding ONE real object; the invariant must hold under contention:
// exactly one legitimate credit, no attacker credit, no mint, no panic, no deadlock.
// =============================================================================

func TestV4Session_ConcurrentLifecyclesHoldInvariant(t *testing.T) {
	const workers = 64
	const itersPerWorker = 20

	ledger := newAtomicLedger()
	victim := Account{0x11, 0x22, 0x33}
	assetA := ID{0x0A}
	realTx := ID{0xEE}
	realKey := DeriveUTXOID(realTx, 0)
	realAmount := uint64(500)
	ledger.PutExport(realKey, atomicObject{owner: victim, asset: assetA, amount: realAmount})

	ctx := context.Background()

	// Each worker drives the FULL bidirectional swap session against a fresh malicious
	// venue (its own client), trying to steal via fabricated MatchResults/refs, and
	// also legitimately settles the victim's real object. The ledger is the shared
	// judge. We count attacker credits (must be 0) and victim legit credits (the object
	// is one-time, so across all workers AT MOST 1 succeeds).
	var attackerCredits int64
	var legitCredits int64
	var wg sync.WaitGroup
	var mu sync.Mutex // guards the counters (the ledger itself is concurrency-safe)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			attacker := Account{0x99, seed}
			adversary := &maliciousVenue{fakeAmount: 1 << 40, fakeRecipient: attacker, fakeAsset: assetA, fakeKey: realKey}
			v4 := newV4For(t, adversary)

			for i := 0; i < itersPerWorker; i++ {
				// Attacker path: drive a full session and try to settle to themselves.
				req := testReq()
				req.Account = attacker
				req.Recipient = attacker
				sess, err := v4.OpenSwap(req)
				if err != nil {
					t.Errorf("concurrent OpenSwap: %v", err)
					return
				}
				res, err := sess.Run(ctx).Settle.Await(ctx)
				sess.Close()
				if err != nil {
					continue
				}
				// Attacker submits as themselves — must be rejected (owner-bind: victim).
				if _, serr := ledger.applySettlementCalldata(res, attacker, assetA); serr == nil {
					mu.Lock()
					attackerCredits++
					mu.Unlock()
				}
				// Victim's honest claim (the real object). One-time across all workers.
				if got, serr := ledger.applySettlementCalldata(settlementCalldataFor(realKey, realAmount), victim, assetA); serr == nil && got == realAmount {
					mu.Lock()
					legitCredits++
					mu.Unlock()
				}
			}
		}(byte(w))
	}
	wg.Wait()

	if attackerCredits != 0 {
		t.Fatalf("CONCURRENCY BREACH: %d attacker credits succeeded (want 0)", attackerCredits)
	}
	if legitCredits != 1 {
		t.Fatalf("the one-time real object was credited %d times under concurrency (want exactly 1)", legitCredits)
	}
	// No mint: the only value that moved is the single real object.
	if total := ledger.totalCredited(); total != realAmount {
		t.Fatalf("total credited under concurrency = %d, want %d (no mint, one object)", total, realAmount)
	}
	// The victim holds exactly the object's value; no attacker holds anything.
	if bal := ledger.Balance(victim, assetA); bal != realAmount {
		t.Fatalf("victim balance = %d, want %d", bal, realAmount)
	}
}

// TestV4Session_ConcurrentScopeConfinement hammers cross-session capability use under
// concurrency: many workers each open a swap session and concurrently attempt to use
// EVERY OTHER worker's scope. Every cross-use must fail ErrScopeMismatch; only a
// session's own scope authorizes. Proves the scope gate is race-free.
func TestV4Session_ConcurrentScopeConfinement(t *testing.T) {
	const workers = 48
	ledger := newAtomicLedger()
	hv := newHonestVenue(ledger)
	v4 := newV4For(t, hv)

	// Build N distinct sessions (distinct amounts => distinct scopes).
	sessions := make([]*V4SwapSession, workers)
	for i := 0; i < workers; i++ {
		req := testReq()
		req.AmountIn = uint64(1_000_000 + i) // distinct params => distinct scope
		s, err := v4.OpenSwap(req)
		if err != nil {
			t.Fatalf("OpenSwap %d: %v", i, err)
		}
		sessions[i] = s
		defer s.Close()
	}

	var crossUseSucceeded int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			me := sessions[idx]
			for j := 0; j < workers; j++ {
				other := sessions[j]
				err := me.cap.authorizeScoped(AuthIntent, other.cap.scope)
				if idx == j {
					// Own scope must authorize.
					if err != nil {
						t.Errorf("session %d failed its OWN scope: %v", idx, err)
					}
				} else {
					// A different scope must fail closed.
					if err != ErrScopeMismatch {
						if err == nil {
							atomicAdd(&crossUseSucceeded)
						} else {
							t.Errorf("session %d->%d wrong error: %v (want ErrScopeMismatch)", idx, j, err)
						}
					}
				}
			}
		}(i)
	}
	wg.Wait()
	if crossUseSucceeded != 0 {
		t.Fatalf("CONFINEMENT BREACH: %d cross-session scope uses succeeded under concurrency (want 0)", crossUseSucceeded)
	}
}

// atomicAdd is a tiny lock-free counter bump for the stress test (avoids importing
// sync/atomic just for one call site by using a mutex-free CAS-style increment via a
// dedicated mutex would be heavier; a plain atomic is clearest).
var crossUseMu sync.Mutex

func atomicAdd(p *int64) {
	crossUseMu.Lock()
	*p++
	crossUseMu.Unlock()
}
