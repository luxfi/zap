// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"fmt"
)

// v4session.go is the V4-native, bidirectional, capability-scoped session model. It
// is the TOP layer of the orchestration stack:
//
//	V4PrecompileSession   (this file) — opens a session per V4 action
//	  V4SwapSession / V4RouteSession / V4LiquiditySession / V4CollectSession /
//	  V4StateSession                  — one action's lifecycle state machine
//	    clientSession      (session.go) — the typed Call/watch primitives
//	      zap.Node         (luxfi/zap)  — the correlated binary transport
//
// COMPOSITION, NOT A SECOND TRANSPORT (Hickey): a V4 session does NOT open its own
// socket or invent a new wire. It COMPOSES the existing clientSession operations
// (Quote/PrepareSwapIntent/NotifyIntent/ImportSettlement/watch) under named V4
// transitions, and holds a scopedCap that confines it to ONE action. The
// bidirectional message set (v4msg.go) is the SEMANTIC overlay; the wire (wire.go)
// stays the single source of transport truth. This keeps "one way to do everything".
//
// THE MONEY-PLANE INVARIANT, RESTATED FOR THE BIDIRECTIONAL SESSION:
//
//	A V4 session is a live bidirectional control plane: both C-side and D-side write
//	through it during an action's lifetime. EVERY such read/write may update session
//	state; NONE moves value. The session exposes:
//	  - WRITES that BUILD calldata (PrepareIntent / PrepareSettlement / commit /
//	    collect / cancel) — bytes the user signs; reserve nothing, credit nothing.
//	  - WRITES that TRIGGER D (NotifyCToDExport) — make D scan a C->D object the
//	    user's signed tx already created; cannot make a match valid without a D block.
//	  - READS that STREAM status/estimates (QuoteUpdate / D_IMPORTED / MATCHED /
//	    HOP_* / D_COMMITTED) — orchestration; the chain trusts none of them.
//	  - READS that yield a POINTER (D_EXPORT_READY / REFUND_READY) — a DExportRef the
//	    chain re-verifies on import.
//	There is NO session method that takes a D->C read (MatchResult, hop fill, …) and
//	produces a credit. The ONLY way to credit C is to settle a real D->C object via
//	the DS01 Phase-B path — which binds owner/asset/amount to the recorded object.
//	The RED suite proves no bidirectional message sequence, absent a real object,
//	moves money.

// =============================================================================
// V4PrecompileSession — the top-level capability.
// =============================================================================

// V4PrecompileSession is the per-action session factory the spec mandates. It wraps a
// restricted DexSession (the bootstrap grant) and opens a NARROWLY-SCOPED session per
// V4 action. Each open* mints a scopedCap confined to {networkID, cChainID, dChainID,
// 0x9999, account, poolKeyHash, paramsHash, intentID} for exactly that action, so a
// session cannot drive any other intent/pool/params/kind.
type V4PrecompileSession struct {
	dex    *clientSession
	netID  uint32
	cChain ID
	dChain ID
	addr   Account // 0x9999
}

// V4Config configures the V4 precompile session. The chain identifiers and the 0x9999
// address are fixed for the deployment; they bind every action's scope.
type V4Config struct {
	Session   DexSession
	NetworkID uint32
	CChainID  ID
	DChainID  ID
	// Addr9999 is the on-chain settlement authority. Defaults to the canonical
	// 0x...9999 if zero.
	Addr9999 Account
}

// NewV4PrecompileSession builds the top-level session over a bootstrapped DexSession.
// The DexSession MUST be a *clientSession (the only implementation); a foreign
// implementation is rejected, because the V4 layer composes the concrete client ops.
func NewV4PrecompileSession(cfg V4Config) (*V4PrecompileSession, error) {
	cs, ok := cfg.Session.(*clientSession)
	if !ok || cs == nil {
		return nil, fmt.Errorf("dexsession: V4PrecompileSession requires a bootstrapped DexSession")
	}
	addr := cfg.Addr9999
	if addr == (Account{}) {
		addr = addr9999()
	}
	return &V4PrecompileSession{
		dex:    cs,
		netID:  cfg.NetworkID,
		cChain: cfg.CChainID,
		dChain: cfg.DChainID,
		addr:   addr,
	}, nil
}

// scopeFor builds an action scope from the session's fixed identity plus the
// per-action fields. The session id derived from it confines the minted capability.
func (v *V4PrecompileSession) scopeFor(kind V4Action, account Account, poolKeyHash, paramsHash, intentID ID) V4ActionScope {
	return V4ActionScope{
		NetworkID:   v.netID,
		CChainID:    v.cChain,
		DChainID:    v.dChain,
		Addr9999:    v.addr,
		Account:     account,
		PoolKeyHash: poolKeyHash,
		ParamsHash:  paramsHash,
		Kind:        kind,
		IntentID:    intentID,
	}
}

// mint issues a scoped capability for `bits` confined to `scope`. It fails closed if
// the underlying session lacks the operation-class authority (you cannot open a
// session whose actions you could not perform).
func (v *V4PrecompileSession) mint(bits Authority, scope V4ActionScope) (*scopedCap, error) {
	core, err := v.dex.issue(bits)
	if err != nil {
		return nil, err
	}
	return newScopedCap(core, scope), nil
}

// =============================================================================
// openSwap -> V4SwapSession
// =============================================================================

// openSwap opens a single-swap session scoped to {req}. The intent id is derived
// deterministically (identically to the on-chain SubmitSwapIntent) and frozen into
// the scope, so this session's capability can drive ONLY this swap. Requires the
// intent + watch + settlement authorities (a swap walks the full lifecycle).
func (v *V4PrecompileSession) OpenSwap(req SwapIntentRequest) (*V4SwapSession, error) {
	pk, ok := v.dex.market(req.MarketID)
	if !ok {
		return nil, fmt.Errorf("dexsession: openSwap: unknown market %x", req.MarketID[:8])
	}
	zfo := zeroForOneFor(req)
	poolKeyHash := DerivePoolKeyHash(pk)
	paramsHash := DeriveSwapParamsHash(zfo, req.AmountIn)
	intentID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, req.MarketID, req.Nonce)
	scope := v.scopeFor(ActionSwap, req.Account, poolKeyHash, paramsHash, intentID)
	cap, err := v.mint(AuthIntent|AuthWatch|AuthSettlement, scope)
	if err != nil {
		return nil, err
	}
	return &V4SwapSession{dex: v.dex, cap: cap, req: req, intentID: intentID}, nil
}

// V4SwapSession is the single-swap lifecycle state machine. It exposes the
// bidirectional message set as typed methods that compose the clientSession ops and
// pipeline via Promise. It holds a scopedCap confined to ONE swap.
type V4SwapSession struct {
	dex      *clientSession
	cap      *scopedCap
	req      SwapIntentRequest
	intentID ID
}

// SessionID is the action's stable id (binds events to this session).
func (s *V4SwapSession) SessionID() ID { return s.cap.SessionID() }

// IntentID is the deterministic intent id this swap targets.
func (s *V4SwapSession) IntentID() ID { return s.intentID }

// WritePrepareIntent [C->D, V4_SWAP_PREPARE_INTENT] builds the 0x9999 swap calldata
// (DI01 intent) the user signs. It reserves nothing; QuotedOut is an estimate. Scoped:
// only this swap's params. Pipelined: returns a Promise.
func (s *V4SwapSession) WritePrepareIntent(ctx context.Context) *Promise[PreparedIntent] {
	p := newPromise[PreparedIntent]()
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		p.fulfil(PreparedIntent{}, err)
		return p
	}
	return s.dex.PrepareSwapIntent(ctx, s.req)
}

// WriteNotifyCToDExport [C->D, V4_SWAP_NOTIFY_C_EXPORT] tells D to scan the C->D
// object the user's signed tx created and returns a watch. It cannot validate a match
// without a D block. Pipelines on the prepared-intent promise.
func (s *V4SwapSession) WriteNotifyCToDExport(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[IntentWatch] {
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		out := newPromise[IntentWatch]()
		out.fulfil(IntentWatch{}, err)
		return out
	}
	// Bind the intent's scope to THIS session before notifying: a prepared intent for
	// a different swap (different intentID) must not be notified through this session.
	guarded := thenAsync(ctx, intent, func(_ context.Context, pi PreparedIntent) (PreparedIntent, error) {
		if pi.IntentID != s.intentID {
			return PreparedIntent{}, ErrScopeMismatch
		}
		return pi, nil
	})
	return s.dex.NotifyIntent(ctx, guarded)
}

// ReadStream [D->C] streams the D->C reads of the swap lifecycle (D_IMPORTED ->
// MATCHED -> D_EXPORT_READY) as V4Events on the returned channel, until the export is
// ready, the intent is rejected, or ctx ends. Each event is orchestration; only the
// final D_EXPORT_READY carries the settleable POINTER. This is the bidirectional read
// side made explicit: the caller observes D writing to the control plane.
func (s *V4SwapSession) ReadStream(ctx context.Context, watch IntentWatch) <-chan V4Event {
	ch := make(chan V4Event, 4)
	if err := s.cap.authorizeSelf(AuthWatch); err != nil {
		ch <- V4Event{Type: V4_ERROR, SessionID: s.SessionID(), IntentID: s.intentID, Reason: err.Error()}
		close(ch)
		return ch
	}
	go s.streamEvents(ctx, watch, ch)
	return ch
}

// streamEvents polls the watch and translates each IntentStatus phase into the
// corresponding V4 D->C read event. It emits D_IMPORTED on the first Matching, MATCHED
// (with the estimate) while matching, and D_EXPORT_READY with the POINTER on commit.
// It NEVER credits — it labels what D reported.
func (s *V4SwapSession) streamEvents(ctx context.Context, watch IntentWatch, ch chan<- V4Event) {
	defer close(ch)
	sid := s.SessionID()
	emittedImported := false
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		st, err := watch.Poll(ctx)
		if err != nil {
			emit(ctx, ch, V4Event{Type: V4_ERROR, SessionID: sid, IntentID: s.intentID, Reason: err.Error()})
			return
		}
		switch st.Phase {
		case PhaseMatching:
			if !emittedImported {
				if !emit(ctx, ch, V4Event{Type: V4_SWAP_D_IMPORTED, SessionID: sid, IntentID: s.intentID}) {
					return
				}
				emittedImported = true
			}
			// MatchResult: the matched-out ESTIMATE. Orchestration only.
			if !emit(ctx, ch, V4Event{Type: V4_SWAP_MATCHED, SessionID: sid, IntentID: s.intentID, EstAmount: st.MatchedOut}) {
				return
			}
		case PhaseCommitted:
			ref := st.Ref
			ref.IntentID = s.intentID // bind the pointer to THIS intent
			emit(ctx, ch, V4Event{Type: V4_SWAP_D_EXPORT_READY, SessionID: sid, IntentID: s.intentID, EstAmount: st.MatchedOut, Ref: ref})
			return
		case PhaseRejected:
			reason := st.Reason
			if reason == "" {
				reason = "intent rejected by D"
			}
			emit(ctx, ch, V4Event{Type: V4_ERROR, SessionID: sid, IntentID: s.intentID, Reason: reason})
			return
		default:
			// Pending / Unknown: keep polling on the cadence below.
		}
		// Yield to D's commit cadence between polls. A committed/rejected returns above.
		if !sleepCtx(ctx, watchPollCadence) {
			return
		}
	}
}

// OnExportReady [D->C, V4_SWAP_D_EXPORT_READY] resolves to the ONE D->C export
// POINTER when D commits — the pipelining hook the spec's lifecycle wants
// (watch.OnCommitted -> settlement). It is the streaming watch; the credit still
// happens on-chain against the real object.
func (s *V4SwapSession) OnExportReady(ctx context.Context, watch IntentWatch) *Promise[DExportRef] {
	if err := s.cap.authorizeSelf(AuthWatch); err != nil {
		p := newPromise[DExportRef]()
		p.fulfil(DExportRef{}, err)
		return p
	}
	return watch.OnCommitted(ctx)
}

// WritePrepareCSettlement [C->D, V4_SWAP_PREPARE_C_SETTLEMENT] builds the 0x9999 DS01
// settlement calldata pointing at the export ref. It binds the ref's intent id to
// THIS session (a ref for another intent is refused). The chain credits on consuming
// the real object; this returns bytes. Pipelines on the ref promise.
func (s *V4SwapSession) WritePrepareCSettlement(ctx context.Context, ref *Promise[DExportRef]) *Promise[SettlementSubmitResult] {
	if err := s.cap.authorizeSelf(AuthSettlement); err != nil {
		out := newPromise[SettlementSubmitResult]()
		out.fulfil(SettlementSubmitResult{}, err)
		return out
	}
	guarded := thenAsync(ctx, ref, func(_ context.Context, r DExportRef) (DExportRef, error) {
		if r.IntentID != s.intentID {
			return DExportRef{}, ErrScopeMismatch
		}
		return r, nil
	})
	return s.dex.ImportSettlement(ctx, guarded)
}

// Run drives the FULL bidirectional swap lifecycle, promise-pipelined, returning the
// stages. It is the V4-native analogue of SwapFlow: prepare -> notify -> watch ->
// export-ready -> settlement calldata. The user signs+sends the prepared intent (this
// layer has no key); pass a sender to RunWithSender for a managed flow. Every stage is
// scoped to this swap.
func (s *V4SwapSession) Run(ctx context.Context) FlowStages {
	intent := s.WritePrepareIntent(ctx)
	watch := s.WriteNotifyCToDExport(ctx, intent)
	committed := thenAsync(ctx, watch, func(ctx context.Context, w IntentWatch) (DExportRef, error) {
		return s.OnExportReady(ctx, w).Await(ctx)
	})
	settle := s.WritePrepareCSettlement(ctx, committed)
	quote := s.dex.Quote(ctx, QuoteRequest{MarketID: s.req.MarketID, AmountIn: s.req.AmountIn, ZeroForOne: zeroForOneFor(s.req)})
	return FlowStages{Quote: quote, Intent: intent, Watch: watch, Committed: committed, Settle: settle}
}

// Close retires the session's capability (no further operation may use it). Idempotent.
func (s *V4SwapSession) Close() { s.dex.Revoke(s.cap.core.tok) }

// =============================================================================
// openRoute -> V4RouteSession
// =============================================================================

// OpenRoute opens a MULTI-HOP route session scoped to {req.Path}. The route intent id
// is derived from the FIRST hop's market (the input lock binds there) and the path is
// hashed into the scope, so this capability can drive ONLY this exact path.
func (v *V4PrecompileSession) OpenRoute(req RouteRequest) (*V4RouteSession, error) {
	first, ok := req.firstMarket()
	if !ok {
		return nil, fmt.Errorf("dexsession: openRoute: empty path")
	}
	pk, ok := v.dex.market(first)
	if !ok {
		return nil, fmt.Errorf("dexsession: openRoute: unknown entry market %x", first[:8])
	}
	_ = pk
	pathHash := DeriveRoutePathHash(req.Path)
	paramsHash := DeriveSwapParamsHash(true, req.AmountIn)
	// The route's intent id binds the single C->D input by the FIRST market (the lock
	// market), identically to a swap intent on that market.
	intentID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, first, uint64(req.CallIndex))
	scope := v.scopeFor(ActionRoute, req.Account, pathHash, paramsHash, intentID)
	cap, err := v.mint(AuthIntent|AuthWatch|AuthSettlement, scope)
	if err != nil {
		return nil, err
	}
	return &V4RouteSession{dex: v.dex, cap: cap, req: req, intentID: intentID, entry: first}, nil
}

// V4RouteSession is the multi-hop route lifecycle state machine. It prepares EXACTLY
// ONE C->D input intent (carrying the path), streams hop progress as orchestration,
// and settles the ONE final D->C export. It NEVER produces an intermediate-asset
// settlement.
type V4RouteSession struct {
	dex      *clientSession
	cap      *scopedCap
	req      RouteRequest
	intentID ID
	entry    ID // entry market (hop 0)
}

func (s *V4RouteSession) SessionID() ID { return s.cap.SessionID() }
func (s *V4RouteSession) IntentID() ID  { return s.intentID }
func (s *V4RouteSession) Path() []ID    { return s.req.Path }

// WritePrepareIntent [C->D, V4_ROUTE_PREPARE_INTENT] builds the ONE route-intent
// calldata: a 0x9999 swap (DI01 intent) on the ENTRY market. This is the single C->D
// input the user signs; there is no per-hop calldata. The route's atomicity starts here:
// one calldata, one intent id, one input. The PATH is NOT carried in the signed on-chain
// hookData — it travels to the D router over the ZAP control plane (buildRouteRequest /
// NotifyRoute, MsgRoutePrepare) — because the on-chain precompile classifies the intent
// purely by its entry market + nonce (DeriveIntentID does NOT hash the path) and only
// supports the DI01 deadline/nonce body; an RT01 path body in the signed calldata would
// REVERT on-chain (the precompile has no route-marker awareness). Keeping the path on the
// control plane is also the right seam: the path is D-matcher orchestration that moves no
// C-side value (one input object, one final output object regardless of hop count).
func (s *V4RouteSession) WritePrepareIntent(ctx context.Context) *Promise[PreparedIntent] {
	p := newPromise[PreparedIntent]()
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		p.fulfil(PreparedIntent{}, err)
		return p
	}
	go func() {
		p.fulfil(s.prepareRouteLocal())
	}()
	return p
}

// prepareRouteLocal builds the single route-intent PreparedIntent CLIENT-SIDE (so a
// malicious server cannot inject a forged path or recipient the user would sign). The
// calldata is a PLAIN DI01 intent (deadline + nonce) on the entry market — the exact body
// the on-chain precompile accepts. It reserves nothing and returns no enforceable amount.
//
// WHY NOT embed the path on-chain (the RT01 fix): the on-chain DeriveIntentID binds the
// entry market + nonce, NOT the path, so a plain DI01 intent on the entry market produces
// the IDENTICAL id this session computed (OpenRoute derived it with `entry` + CallIndex).
// The precompile has no RT01 route-marker awareness; an RT01 body in the signed calldata is
// width 8+n*32, which decodeIntentBody rejects -> the swap REVERTS on-chain. The path is
// instead carried to the D router over the ZAP control plane (buildRouteRequest /
// NotifyRoute), where it belongs — it is D-matcher orchestration, not C-side value. The
// nonce is CallIndex (matching OpenRoute's id derivation) so the off-chain and on-chain ids
// agree and the watch correlates.
func (s *V4RouteSession) prepareRouteLocal() (PreparedIntent, error) {
	if s.req.AmountIn == 0 {
		return PreparedIntent{}, fmt.Errorf("dexsession: openRoute: zero amountIn")
	}
	if len(s.req.Path) == 0 {
		return PreparedIntent{}, fmt.Errorf("dexsession: openRoute: empty path")
	}
	pk, ok := s.dex.market(s.entry)
	if !ok {
		return PreparedIntent{}, fmt.Errorf("dexsession: openRoute: unknown entry market %x", s.entry[:8])
	}
	// Plain DI01 intent on the entry market; nonce == CallIndex to match the id this session
	// derived (and the id the on-chain SubmitSwapIntent will re-derive from this calldata).
	hookData := EncodeIntentHookData(s.req.Deadline, uint64(s.req.CallIndex))
	calldata := EncodeSwapCalldata(pk, true /*entry direction; D re-validates*/, s.req.AmountIn, hookData)
	return PreparedIntent{
		To:        addr9999(),
		Calldata:  calldata,
		HookData:  hookData,
		IntentID:  s.intentID,
		DChainID:  s.req.DChainID,
		CChainID:  s.req.CChainID,
		Account:   s.req.Account,
		Recipient: s.req.Recipient,
		AssetIn:   s.req.AssetIn,
		AmountIn:  s.req.AmountIn,
		MarketID:  s.entry,
	}, nil
}

// WriteNotifyCToDExport [C->D, V4_ROUTE_NOTIFY_C_EXPORT] tells D to scan the SINGLE
// C->D input object and walk the path. Returns a route watch.
func (s *V4RouteSession) WriteNotifyCToDExport(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[RouteWatch] {
	out := newPromise[RouteWatch]()
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		out.fulfil(RouteWatch{}, err)
		return out
	}
	return thenAsync(ctx, intent, func(ctx context.Context, pi PreparedIntent) (RouteWatch, error) {
		if pi.IntentID != s.intentID {
			return RouteWatch{}, ErrScopeMismatch
		}
		reqMsg, err := buildRouteRequest(s.req)
		if err != nil {
			return RouteWatch{}, err
		}
		// retag as a notify-route (server routes MsgRouteStatus for the notify+poll;
		// the request body carries the path so the venue can begin walking).
		resp, err := s.dex.conn.Call(ctx, s.dex.peerID, reqMsg)
		if err != nil {
			return RouteWatch{}, err
		}
		defer resp.Release()
		return RouteWatch{session: s, intentID: s.intentID, hopCount: uint32(len(s.req.Path))}, nil
	})
}

// ReadStream [D->C] streams the route's D->C reads (HOP_STARTED / HOP_FILLED ->
// D_EXPORT_READY or REFUND_READY) as V4Events. Hop events carry intermediate amounts
// as ESTIMATES; only the terminal export/refund carries the ONE settleable POINTER.
func (s *V4RouteSession) ReadStream(ctx context.Context, watch RouteWatch) <-chan V4Event {
	ch := make(chan V4Event, 8)
	if err := s.cap.authorizeSelf(AuthWatch); err != nil {
		ch <- V4Event{Type: V4_ERROR, SessionID: s.SessionID(), IntentID: s.intentID, Reason: err.Error()}
		close(ch)
		return ch
	}
	go s.streamRoute(ctx, watch, ch)
	return ch
}

func (s *V4RouteSession) streamRoute(ctx context.Context, watch RouteWatch, ch chan<- V4Event) {
	defer close(ch)
	sid := s.SessionID()
	lastHop := int64(-1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		st, err := watch.Poll(ctx)
		if err != nil {
			emit(ctx, ch, V4Event{Type: V4_ERROR, SessionID: sid, IntentID: s.intentID, Reason: err.Error()})
			return
		}
		switch st.Phase {
		case RouteHopping:
			if int64(st.HopIndex) > lastHop {
				lastHop = int64(st.HopIndex)
				if !emit(ctx, ch, V4Event{Type: V4_ROUTE_HOP_STARTED, SessionID: sid, IntentID: s.intentID, HopIndex: st.HopIndex}) {
					return
				}
			}
			// HOP_FILLED carries the hop output ESTIMATE — orchestration. NO ref: there
			// is no per-hop settleable object (the route stays on D between hops). The
			// event is constructed with a ZERO Ref regardless of what the venue reported
			// for this phase, so a malicious venue cannot smuggle a settleable pointer
			// into a hop event.
			if !emit(ctx, ch, V4Event{Type: V4_ROUTE_HOP_FILLED, SessionID: sid, IntentID: s.intentID, HopIndex: st.HopIndex, EstAmount: st.HopAmountOut}) {
				return
			}
		case RouteCommitted:
			ref := st.Ref
			ref.IntentID = s.intentID
			emit(ctx, ch, V4Event{Type: V4_ROUTE_D_EXPORT_READY, SessionID: sid, IntentID: s.intentID, EstAmount: st.FinalOut, Ref: ref})
			return
		case RouteRefunded:
			ref := st.Ref
			ref.IntentID = s.intentID
			emit(ctx, ch, V4Event{Type: V4_ROUTE_REFUND_READY, SessionID: sid, IntentID: s.intentID, EstAmount: st.FinalOut, Ref: ref, Reason: st.Reason})
			return
		case RouteRejected:
			reason := st.Reason
			if reason == "" {
				reason = "route rejected by D"
			}
			emit(ctx, ch, V4Event{Type: V4_ERROR, SessionID: sid, IntentID: s.intentID, Reason: reason})
			return
		default:
		}
		if !sleepCtx(ctx, watchPollCadence) {
			return
		}
	}
}

// OnFinalExport [D->C] resolves to the ONE final (or refund) export POINTER when the
// route terminates. This is the SINGLE settleable pointer of the whole route.
func (s *V4RouteSession) OnFinalExport(ctx context.Context, watch RouteWatch) *Promise[DExportRef] {
	p := newPromise[DExportRef]()
	if err := s.cap.authorizeSelf(AuthWatch); err != nil {
		p.fulfil(DExportRef{}, err)
		return p
	}
	go watch.streamUntilFinal(ctx, p)
	return p
}

// WritePrepareCSettlement [C->D, V4_ROUTE_PREPARE_C_SETTLEMENT] settles the ONE final
// (or refund) export. Identical to the swap settlement — the route's single output is
// just a D->C object consumed by the one DS01 credit path.
func (s *V4RouteSession) WritePrepareCSettlement(ctx context.Context, ref *Promise[DExportRef]) *Promise[SettlementSubmitResult] {
	if err := s.cap.authorizeSelf(AuthSettlement); err != nil {
		out := newPromise[SettlementSubmitResult]()
		out.fulfil(SettlementSubmitResult{}, err)
		return out
	}
	guarded := thenAsync(ctx, ref, func(_ context.Context, r DExportRef) (DExportRef, error) {
		if r.IntentID != s.intentID {
			return DExportRef{}, ErrScopeMismatch
		}
		return r, nil
	})
	return s.dex.ImportSettlement(ctx, guarded)
}

// Close retires the route session's capability.
func (s *V4RouteSession) Close() { s.dex.Revoke(s.cap.core.tok) }

// =============================================================================
// openModifyLiquidity -> V4LiquiditySession  (commit C->D funded position)
// =============================================================================

// LiquidityRequest is the off-chain request to COMMIT (open/increase) a funded
// position. LiquidityDelta MUST be positive for a commit (it funds the position from
// C); the negative-delta (collect/decrease/cancel) path is V4CollectSession /
// openCancel, whose credit rides the DS01 settlement.
type LiquidityRequest struct {
	NetworkID      uint32
	CChainID       ID
	DChainID       ID
	Account        Account
	MarketID       ID
	TickLower      int32
	TickUpper      int32
	LiquidityDelta int64 // >0 to commit funds
	Salt           ID
	AssetIn        ID
	AmountIn       uint64 // the C-side funding amount locked for the position
	CallIndex      uint32
}

// OpenModifyLiquidity opens a position-commit session scoped to {req}. A commit is a
// DEPOSIT: it creates a C->D funded-position object and never credits C, so the
// session needs only the intent authority (build + notify), not settlement.
func (v *V4PrecompileSession) OpenModifyLiquidity(req LiquidityRequest) (*V4LiquiditySession, error) {
	if req.LiquidityDelta <= 0 {
		return nil, fmt.Errorf("dexsession: openModifyLiquidity: commit requires positive liquidityDelta (use openCollect/openCancel to remove)")
	}
	pk, ok := v.dex.market(req.MarketID)
	if !ok {
		return nil, fmt.Errorf("dexsession: openModifyLiquidity: unknown market %x", req.MarketID[:8])
	}
	poolKeyHash := DerivePoolKeyHash(pk)
	paramsHash := DeriveLiquidityParamsHash(req.TickLower, req.TickUpper, req.LiquidityDelta, req.Salt)
	// The position-commit object binds by account+pool+params (no swap intent id); the
	// intent id slot is the derivation over the funding identity for correlation.
	intentID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, req.MarketID, uint64(req.CallIndex))
	scope := v.scopeFor(ActionModifyLiquidity, req.Account, poolKeyHash, paramsHash, intentID)
	cap, err := v.mint(AuthIntent|AuthWatch, scope)
	if err != nil {
		return nil, err
	}
	return &V4LiquiditySession{dex: v.dex, cap: cap, req: req, pk: pk, intentID: intentID}, nil
}

// V4LiquiditySession is the position-commit lifecycle. It builds modifyLiquidity
// (+delta) calldata the user signs to fund the position, notifies D, and observes the
// position opening. It has NO settlement method (a commit credits nothing).
type V4LiquiditySession struct {
	dex      *clientSession
	cap      *scopedCap
	req      LiquidityRequest
	pk       PoolKeyArgs
	intentID ID
}

func (s *V4LiquiditySession) SessionID() ID { return s.cap.SessionID() }
func (s *V4LiquiditySession) IntentID() ID  { return s.intentID }

// WritePrepareCommit [C->D, V4_LP_PREPARE_COMMIT] builds the 0x9999 modifyLiquidity
// (+delta) calldata the user signs to fund the position from C. It reserves nothing
// off-chain; the C lock happens when the user's signed tx executes. Scoped to this
// position's exact params.
func (s *V4LiquiditySession) WritePrepareCommit(ctx context.Context) *Promise[PreparedIntent] {
	p := newPromise[PreparedIntent]()
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		p.fulfil(PreparedIntent{}, err)
		return p
	}
	go func() {
		args := ModifyLiquidityArgs{
			TickLower:      s.req.TickLower,
			TickUpper:      s.req.TickUpper,
			LiquidityDelta: s.req.LiquidityDelta, // positive: add/commit
			Salt:           s.req.Salt,
		}
		hookData := EncodeIntentHookData(0, uint64(s.req.CallIndex)) // commit is a Phase-A funding intent
		calldata := EncodeModifyLiquidityCalldata(s.pk, args, hookData)
		p.fulfil(PreparedIntent{
			To:       addr9999(),
			Calldata: calldata,
			HookData: hookData,
			IntentID: s.intentID,
			DChainID: s.req.DChainID,
			CChainID: s.req.CChainID,
			Account:  s.req.Account,
			AssetIn:  s.req.AssetIn,
			AmountIn: s.req.AmountIn,
			MarketID: s.req.MarketID,
		}, nil)
	}()
	return p
}

// WriteNotifyCToDExport [C->D, V4_LP_NOTIFY_C_EXPORT] tells D to scan the funded
// C->D position object and record the position. Returns a watch (position-open is the
// committed phase).
func (s *V4LiquiditySession) WriteNotifyCToDExport(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[IntentWatch] {
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		out := newPromise[IntentWatch]()
		out.fulfil(IntentWatch{}, err)
		return out
	}
	guarded := thenAsync(ctx, intent, func(_ context.Context, pi PreparedIntent) (PreparedIntent, error) {
		if pi.IntentID != s.intentID {
			return PreparedIntent{}, ErrScopeMismatch
		}
		return pi, nil
	})
	return s.dex.NotifyIntent(ctx, guarded)
}

// Close retires the liquidity session's capability.
func (s *V4LiquiditySession) Close() { s.dex.Revoke(s.cap.core.tok) }

// =============================================================================
// openCollect / openCancel -> V4CollectSession  (D->C export -> C credit)
// =============================================================================

// CollectRequest is the off-chain request to COLLECT/DECREASE (negative-delta) or
// CANCEL a position/order. Both produce a D->C export (collected fees / withdrawn
// liquidity / cancelled-order refund) consumed by the ONE DS01 credit path. Cancel is
// the same shape with the cancel marker; the credit is identical.
type CollectRequest struct {
	NetworkID      uint32
	CChainID       ID
	DChainID       ID
	Account        Account
	MarketID       ID
	TickLower      int32
	TickUpper      int32
	LiquidityDelta int64 // <0 to remove/collect (a cancel removes the resting amount)
	Salt           ID
	AssetOut       ID // the asset the collect/cancel returns (for correlation)
	CallIndex      uint32
	IsCancel       bool // true => cancel a resting order; false => collect/decrease
}

// OpenCollect opens a collect/decrease session (negative-delta removal). It produces a
// D->C export -> C credit via DS01, so it needs the watch + settlement authorities.
func (v *V4PrecompileSession) OpenCollect(req CollectRequest) (*V4CollectSession, error) {
	return v.openRemoval(req, ActionCollect)
}

// OpenCancel opens a cancel session (cancel a resting order; refund the locked asset).
// Same removal shape as collect; the credit is the identical DS01 settlement.
func (v *V4PrecompileSession) OpenCancel(req CollectRequest) (*V4CollectSession, error) {
	req.IsCancel = true
	return v.openRemoval(req, ActionCancel)
}

func (v *V4PrecompileSession) openRemoval(req CollectRequest, kind V4Action) (*V4CollectSession, error) {
	if req.LiquidityDelta >= 0 {
		return nil, fmt.Errorf("dexsession: openCollect/openCancel: removal requires negative liquidityDelta")
	}
	pk, ok := v.dex.market(req.MarketID)
	if !ok {
		return nil, fmt.Errorf("dexsession: openCollect: unknown market %x", req.MarketID[:8])
	}
	poolKeyHash := DerivePoolKeyHash(pk)
	paramsHash := DeriveLiquidityParamsHash(req.TickLower, req.TickUpper, req.LiquidityDelta, req.Salt)
	intentID := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetOut, 0, req.MarketID, uint64(req.CallIndex))
	scope := v.scopeFor(kind, req.Account, poolKeyHash, paramsHash, intentID)
	cap, err := v.mint(AuthIntent|AuthWatch|AuthSettlement, scope)
	if err != nil {
		return nil, err
	}
	return &V4CollectSession{dex: v.dex, cap: cap, req: req, pk: pk, intentID: intentID, kind: kind}, nil
}

// V4CollectSession is the removal lifecycle (collect/decrease/cancel). It requests the
// removal, watches for the ONE D->C export, and settles it via the DS01 credit path.
type V4CollectSession struct {
	dex      *clientSession
	cap      *scopedCap
	req      CollectRequest
	pk       PoolKeyArgs
	intentID ID
	kind     V4Action
}

func (s *V4CollectSession) SessionID() ID { return s.cap.SessionID() }
func (s *V4CollectSession) IntentID() ID  { return s.intentID }

// WriteRequest [C->D, V4_COLLECT_REQUEST / V4_CANCEL_REQUEST] builds the 0x9999
// modifyLiquidity (-delta) calldata the user signs to ask D to remove. The removal's
// output becomes a D->C export the session then settles. It reserves/credits nothing.
func (s *V4CollectSession) WriteRequest(ctx context.Context) *Promise[PreparedIntent] {
	p := newPromise[PreparedIntent]()
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		p.fulfil(PreparedIntent{}, err)
		return p
	}
	go func() {
		args := ModifyLiquidityArgs{
			TickLower:      s.req.TickLower,
			TickUpper:      s.req.TickUpper,
			LiquidityDelta: s.req.LiquidityDelta, // negative: remove
			Salt:           s.req.Salt,
		}
		hookData := EncodeIntentHookData(0, uint64(s.req.CallIndex))
		calldata := EncodeModifyLiquidityCalldata(s.pk, args, hookData)
		p.fulfil(PreparedIntent{
			To:       addr9999(),
			Calldata: calldata,
			HookData: hookData,
			IntentID: s.intentID,
			DChainID: s.req.DChainID,
			CChainID: s.req.CChainID,
			Account:  s.req.Account,
			AssetIn:  s.req.AssetOut,
			MarketID: s.req.MarketID,
		}, nil)
	}()
	return p
}

// WriteNotify [C->D] tells D to scan the removal request and produce the D->C export.
func (s *V4CollectSession) WriteNotify(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[IntentWatch] {
	if err := s.cap.authorizeSelf(AuthIntent); err != nil {
		out := newPromise[IntentWatch]()
		out.fulfil(IntentWatch{}, err)
		return out
	}
	guarded := thenAsync(ctx, intent, func(_ context.Context, pi PreparedIntent) (PreparedIntent, error) {
		if pi.IntentID != s.intentID {
			return PreparedIntent{}, ErrScopeMismatch
		}
		return pi, nil
	})
	return s.dex.NotifyIntent(ctx, guarded)
}

// OnExportReady [D->C, V4_COLLECT_D_EXPORT_READY / V4_CANCEL_D_EXPORT_READY] resolves
// to the D->C export POINTER of the collected/cancelled value.
func (s *V4CollectSession) OnExportReady(ctx context.Context, watch IntentWatch) *Promise[DExportRef] {
	p := newPromise[DExportRef]()
	if err := s.cap.authorizeSelf(AuthWatch); err != nil {
		p.fulfil(DExportRef{}, err)
		return p
	}
	return watch.OnCommitted(ctx)
}

// WritePrepareCSettlement [C->D] settles the export via the ONE DS01 credit path —
// byte-identical to a swap settlement. The collected/cancelled value credits on-chain
// when the real object is consumed.
func (s *V4CollectSession) WritePrepareCSettlement(ctx context.Context, ref *Promise[DExportRef]) *Promise[SettlementSubmitResult] {
	if err := s.cap.authorizeSelf(AuthSettlement); err != nil {
		out := newPromise[SettlementSubmitResult]()
		out.fulfil(SettlementSubmitResult{}, err)
		return out
	}
	guarded := thenAsync(ctx, ref, func(_ context.Context, r DExportRef) (DExportRef, error) {
		if r.IntentID != s.intentID {
			return DExportRef{}, ErrScopeMismatch
		}
		return r, nil
	})
	return s.dex.ImportSettlement(ctx, guarded)
}

// Close retires the collect session's capability.
func (s *V4CollectSession) Close() { s.dex.Revoke(s.cap.core.tok) }

// =============================================================================
// V4StateSession  (read-only quote/book/state streaming)
// =============================================================================

// OpenState opens a read-only state session scoped to a market. It needs only the
// quote authority; it has no write or settlement surface.
func (v *V4PrecompileSession) OpenState(account Account, marketID ID) (*V4StateSession, error) {
	pk, ok := v.dex.market(marketID)
	if !ok {
		return nil, fmt.Errorf("dexsession: openState: unknown market %x", marketID[:8])
	}
	scope := v.scopeFor(ActionState, account, DerivePoolKeyHash(pk), ID{}, ID{})
	cap, err := v.mint(AuthQuote, scope)
	if err != nil {
		return nil, err
	}
	return &V4StateSession{dex: v.dex, cap: cap, marketID: marketID}, nil
}

// V4StateSession is the read-only streaming session: quotes and book/state. It cannot
// build calldata, notify, or settle — it observes.
type V4StateSession struct {
	dex      *clientSession
	cap      *scopedCap
	marketID ID
}

func (s *V4StateSession) SessionID() ID { return s.cap.SessionID() }

// ReadQuote [D->C, V4_STATE_QUOTE_UPDATE] reads one quote estimate. Read-only.
func (s *V4StateSession) ReadQuote(ctx context.Context, amountIn uint64, zeroForOne bool) *Promise[QuoteResult] {
	p := newPromise[QuoteResult]()
	if err := s.cap.authorizeSelf(AuthQuote); err != nil {
		p.fulfil(QuoteResult{}, err)
		return p
	}
	return s.dex.Quote(ctx, QuoteRequest{MarketID: s.marketID, AmountIn: amountIn, ZeroForOne: zeroForOne})
}

// ReadState [D->C, V4_STATE_BOOK_UPDATE] reads one state observation. Read-only.
func (s *V4StateSession) ReadState(ctx context.Context, kind StateKind, account Account, asset ID) *Promise[StateResult] {
	p := newPromise[StateResult]()
	if err := s.cap.authorizeSelf(AuthQuote); err != nil {
		p.fulfil(StateResult{}, err)
		return p
	}
	return s.dex.GetState(ctx, StateRequest{Kind: kind, MarketID: s.marketID, Account: account, Asset: asset})
}

// StreamQuotes [D->C] streams quote updates on a cadence until ctx ends, surfacing
// each as a V4_STATE_QUOTE_UPDATE event. Pure reads; moves nothing.
func (s *V4StateSession) StreamQuotes(ctx context.Context, amountIn uint64, zeroForOne bool) <-chan V4Event {
	ch := make(chan V4Event, 4)
	if err := s.cap.authorizeSelf(AuthQuote); err != nil {
		ch <- V4Event{Type: V4_ERROR, SessionID: s.SessionID(), Reason: err.Error()}
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		sid := s.SessionID()
		for {
			qr, err := s.dex.Quote(ctx, QuoteRequest{MarketID: s.marketID, AmountIn: amountIn, ZeroForOne: zeroForOne}).Await(ctx)
			if err != nil {
				emit(ctx, ch, V4Event{Type: V4_ERROR, SessionID: sid, Reason: err.Error()})
				return
			}
			if !emit(ctx, ch, V4Event{Type: V4_STATE_QUOTE_UPDATE, SessionID: sid, EstAmount: qr.AmountOut}) {
				return
			}
			if !sleepCtx(ctx, watchPollCadence) {
				return
			}
		}
	}()
	return ch
}

// Close retires the state session's capability.
func (s *V4StateSession) Close() { s.dex.Revoke(s.cap.core.tok) }
