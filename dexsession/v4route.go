// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"fmt"
	"time"

	zaplib "github.com/luxfi/zap"
)

// watchPollCadence is the poll interval the V4 session streams use between D status
// reads. The happy path on a live D-Chain is sub-second; this caps a stuck action
// from hot-looping while keeping the stream responsive.
const watchPollCadence = 25 * time.Millisecond

// sleepCtx sleeps for d or until ctx is cancelled. Returns true if the full duration
// elapsed, false if ctx was cancelled (the caller surfaces the ctx error).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// emit sends ev on ch, but bails the instant ctx is cancelled — so an abandoned
// consumer (a caller that stops ranging without cancelling) can never wedge a stream
// goroutine on a full buffered channel. Returns false if ctx ended (the stream should
// stop). This is the ONE place a session stream writes an event; all three streams
// (swap/route/state) use it, keeping the ctx-aware send DRY.
func emit(ctx context.Context, ch chan<- V4Event, ev V4Event) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// v4route.go is the MULTI-HOP route control plane: the route-intent request, the
// hop-progress stream, the route wire frames, and the RouteVenue the server
// delegates to. It is an ORTHOGONAL extension of the swap primitives — a route is a
// swap intent whose hookData carries a path (v4liquidity.go), so the money path is
// IDENTICAL to a single swap: ONE C->D input object, ONE D->C output (or refund)
// object. The hops in between are D-internal matching state, streamed as
// orchestration. Nothing here moves value.
//
// THE ATOMICITY PROPERTY (the spec's "stays on D until final export"):
//
//	A route prepares EXACTLY ONE C->D intent (one calldata, one intentID). D imports
//	that single input and walks the whole path A->B->C ATOMICALLY inside dexvm,
//	producing EXACTLY ONE D->C export (the final output) — or, on failure, ONE refund
//	export of the ORIGINAL input asset. There is NEVER an intermediate C-side object
//	for asset B: the route does not bounce to C between hops. So a holder of a route
//	session can settle the ONE final export and nothing else; a fabricated
//	intermediate-asset settlement names no object on C and reverts. The hop stream
//	(HOP_STARTED/HOP_FILLED) carries intermediate amounts as ESTIMATES — never a
//	settleable pointer.

// RouteRequest is the off-chain request to PREPARE a multi-hop route intent. Like a
// SwapIntentRequest it reserves no funds and returns calldata; the difference is
// Path — the ordered list of marketIDs D walks (A->B->C). AmountIn is the SINGLE
// input the user locks on C; MinAmountOut is the floor on the FINAL output, enforced
// by D at the end of the route (a route that cannot deliver MinAmountOut of the final
// asset refunds the input — it never partially settles an intermediate asset).
type RouteRequest struct {
	NetworkID    uint32
	CChainID     ID
	DChainID     ID
	Account      Account // taker — bound as the single C->D input object owner
	AssetIn      ID      // the input asset locked on C (hop 0 input)
	AssetInAddr  Account // ERC-20 token (zero for native) for the C lock
	AmountIn     uint64  // the SINGLE input amount
	Path         []ID    // ordered marketIDs the route walks: A->B->C
	MinAmountOut uint64  // floor on the FINAL output asset (D-enforced)
	Recipient    Account // where the FINAL D->C export must credit
	Deadline     uint64
	CallIndex    uint32
}

// firstMarket is the route's entry market (hop 0). The prepared C->D intent binds the
// route by its FIRST pool (the input lock happens against hop 0's pool); the path
// body carries the rest. ok=false for an empty path (a route needs >=1 hop).
func (r RouteRequest) firstMarket() (ID, bool) {
	if len(r.Path) == 0 {
		return ID{}, false
	}
	return r.Path[0], true
}

// RoutePhase is the lifecycle of a route as the off-chain watcher observes it. Like
// IntentPhase, NONE of these moves value; Committed means the watcher saw the ONE
// final D->C export, Refunded means it saw the ONE refund export.
type RoutePhase uint8

const (
	RoutePending   RoutePhase = 0 // notified; D has not started the route
	RouteHopping   RoutePhase = 1 // D is walking the path (a hop is in progress)
	RouteCommitted RoutePhase = 2 // D produced the ONE final D->C export
	RouteRefunded  RoutePhase = 3 // route failed; D produced the ONE refund export
	RouteRejected  RoutePhase = 4 // D could not import/route (e.g. unbacked, expired)
	RouteUnknown   RoutePhase = 5
)

// RouteStatus is one poll/push of a route watch. HopIndex/HopAmountOut describe the
// CURRENT hop (orchestration ESTIMATES). Ref is the FINAL export POINTER, valid only
// when Phase==RouteCommitted (the final output) or RouteRefunded (the refund). There
// is no per-hop Ref field — by construction there is no per-hop settleable object.
type RouteStatus struct {
	IntentID     ID
	Phase        RoutePhase
	HopIndex     uint32     // the current/last hop the router reached (0-based)
	HopCount     uint32     // total hops in the path
	HopAmountOut uint64     // ESTIMATE: output of the current hop (orchestration only)
	FinalOut     uint64     // ESTIMATE: final output (orchestration only)
	Ref          DExportRef // the ONE final (or refund) export; valid at Committed/Refunded
	Reason       string
}

// =============================================================================
// Route wire frames.
// =============================================================================

// RouteRequest envelope (client -> server for MsgRoutePrepare). The path is a list of
// bytes32 marketIDs; the fixed header carries the scalars and the single input/asset.
const (
	rrNet       = 0   // uint32
	rrCallIdx   = 4   // uint32
	rrHopCount  = 8   // uint32 (path length)
	rrAmountIn  = 16  // uint64
	rrMinOut    = 24  // uint64
	rrDeadline  = 32  // uint64
	rrCChain    = 40  // bytes32 [40:72]
	rrDChain    = 72  // bytes32 [72:104]
	rrAccount   = 104 // bytes20 [104:124]
	rrAssetIn   = 124 // bytes32 [124:156]
	rrAssetAddr = 156 // bytes20 [156:176]
	rrRecipient = 176 // bytes20 [176:196]
	rrPath      = 196 // bytes (slot 8) — concatenated marketIDs (hopCount*32)
	rrSize      = 204
)

func buildRouteRequest(r RouteRequest) (*zaplib.Message, error) {
	pathBytes := make([]byte, 0, len(r.Path)*32)
	for _, m := range r.Path {
		pathBytes = append(pathBytes, m[:]...)
	}
	b := zaplib.NewBuilder(rrSize + len(pathBytes) + 128)
	ob := b.StartObject(rrSize)
	ob.SetUint32(rrNet, r.NetworkID)
	ob.SetUint32(rrCallIdx, r.CallIndex)
	ob.SetUint32(rrHopCount, uint32(len(r.Path)))
	ob.SetUint64(rrAmountIn, r.AmountIn)
	ob.SetUint64(rrMinOut, r.MinAmountOut)
	ob.SetUint64(rrDeadline, r.Deadline)
	ob.SetBytesFixed(rrCChain, r.CChainID[:])
	ob.SetBytesFixed(rrDChain, r.DChainID[:])
	ob.SetBytesFixed(rrAccount, r.Account[:])
	ob.SetBytesFixed(rrAssetIn, r.AssetIn[:])
	ob.SetBytesFixed(rrAssetAddr, r.AssetInAddr[:])
	ob.SetBytesFixed(rrRecipient, r.Recipient[:])
	ob.SetBytes(rrPath, pathBytes)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgRoutePrepare << 8))
}

func readRouteRequest(m *zaplib.Message) RouteRequest {
	r := m.Root()
	var out RouteRequest
	out.NetworkID = r.Uint32(rrNet)
	out.CallIndex = r.Uint32(rrCallIdx)
	hopCount := int(r.Uint32(rrHopCount))
	out.AmountIn = r.Uint64(rrAmountIn)
	out.MinAmountOut = r.Uint64(rrMinOut)
	out.Deadline = r.Uint64(rrDeadline)
	copy(out.CChainID[:], r.BytesFixedSlice(rrCChain, 32))
	copy(out.DChainID[:], r.BytesFixedSlice(rrDChain, 32))
	copy(out.Account[:], r.BytesFixedSlice(rrAccount, 20))
	copy(out.AssetIn[:], r.BytesFixedSlice(rrAssetIn, 32))
	copy(out.AssetInAddr[:], r.BytesFixedSlice(rrAssetAddr, 20))
	copy(out.Recipient[:], r.BytesFixedSlice(rrRecipient, 20))
	pathBytes := r.Bytes(rrPath)
	// Bound the declared hop count to what the bytes actually carry, so a corrupt
	// hopCount cannot drive an over-read (fail-closed to the real byte length).
	// Compare via division, never `hopCount*32`, so the bound holds even on a
	// 32-bit `int` build where a huge hopCount would overflow the multiply.
	if hopCount > len(pathBytes)/32 {
		hopCount = len(pathBytes) / 32
	}
	out.Path = make([]ID, hopCount)
	for i := 0; i < hopCount; i++ {
		copy(out.Path[i][:], pathBytes[i*32:(i+1)*32])
	}
	return out
}

// RouteStatus envelope (server -> client for MsgRouteStatus).
const (
	rsPhase    = 0   // uint8
	rsHopIndex = 4   // uint32
	rsHopCount = 8   // uint32
	rsRefIndex = 12  // uint32 (final ref output index)
	rsHopOut   = 16  // uint64 (hop output ESTIMATE)
	rsFinalOut = 24  // uint64 (final output ESTIMATE)
	rsIntent   = 32  // bytes32 [32:64]
	rsRefChain = 64  // bytes32 [64:96] final ref source chain
	rsRefTx    = 96  // bytes32 [96:128] final ref source tx
	rsReason   = 128 // text (slot 8)
	rsSize     = 136
)

func buildRouteStatus(s RouteStatus) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(rsSize + len(s.Reason) + 160)
	ob := b.StartObject(rsSize)
	ob.SetUint8(rsPhase, uint8(s.Phase))
	ob.SetUint32(rsHopIndex, s.HopIndex)
	ob.SetUint32(rsHopCount, s.HopCount)
	ob.SetUint32(rsRefIndex, s.Ref.OutputIndex)
	ob.SetUint64(rsHopOut, s.HopAmountOut)
	ob.SetUint64(rsFinalOut, s.FinalOut)
	ob.SetBytesFixed(rsIntent, s.IntentID[:])
	ob.SetBytesFixed(rsRefChain, s.Ref.SourceChainID[:])
	ob.SetBytesFixed(rsRefTx, s.Ref.SourceTxID[:])
	ob.SetText(rsReason, s.Reason)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgRouteStatus << 8))
}

func readRouteStatus(m *zaplib.Message) RouteStatus {
	r := m.Root()
	var s RouteStatus
	s.Phase = RoutePhase(r.Uint8(rsPhase))
	s.HopIndex = r.Uint32(rsHopIndex)
	s.HopCount = r.Uint32(rsHopCount)
	s.Ref.OutputIndex = r.Uint32(rsRefIndex)
	s.HopAmountOut = r.Uint64(rsHopOut)
	s.FinalOut = r.Uint64(rsFinalOut)
	copy(s.IntentID[:], r.BytesFixedSlice(rsIntent, 32))
	copy(s.Ref.SourceChainID[:], r.BytesFixedSlice(rsRefChain, 32))
	copy(s.Ref.SourceTxID[:], r.BytesFixedSlice(rsRefTx, 32))
	s.Ref.IntentID = s.IntentID
	s.Reason = r.Text(rsReason)
	// Hygiene (mirror the streamRoute terminal-phase gate at line ~350): the D->C
	// export pointer is meaningful ONLY in a terminal phase. Zero it otherwise so a
	// non-terminal frame cannot surface a venue-supplied Ref to a direct Poll()
	// caller. Defense-in-depth — the chain re-binds the object on import regardless,
	// so this is not the money-plane gate, just orchestration-surface hygiene.
	if s.Phase != RouteCommitted && s.Phase != RouteRefunded {
		s.Ref = DExportRef{}
	}
	return s
}

// the route-watch-poll request carries just the intent id (tagged MsgRouteStatus).
func buildRouteWatchPoll(intentID ID) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(iwSize + 40)
	ob := b.StartObject(iwSize)
	ob.SetBytesFixed(iwIntent, intentID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgRouteStatus << 8))
}

func readRouteWatchPoll(m *zaplib.Message) ID {
	r := m.Root()
	var id ID
	copy(id[:], r.BytesFixedSlice(iwIntent, 32))
	return id
}

// =============================================================================
// RouteVenue — the OPTIONAL backend a server implements to serve routes.
// =============================================================================

// RouteVenue is the route backend a Venue MAY ALSO implement. It is a SEPARATE
// interface (composition, not interface-expansion) so the base Venue — and every
// existing implementation — stays unchanged: a server type-asserts for RouteVenue
// and serves routes only when the backend provides it. Like Venue, it has NO
// credit/settle method: it reports route progress and the final export POINTER; it
// never moves value. Exactly TWO methods — one trigger, one status — keeps it DRY.
type RouteVenue interface {
	// NotifyRoute tells the venue to scan the SINGLE C->D input object the user's
	// signed tx created and begin walking the path carried in the request. It returns
	// the deterministic route intent id to watch; it does NOT build calldata (the
	// SESSION builds calldata client-side from the user's own path, so a malicious
	// server cannot inject a forged path the user would sign), does not block on a D
	// block, and credits nothing.
	NotifyRoute(req RouteRequest) (IntentWatchRef, error)

	// RouteStatus reports the current route phase + hop progress, and (when D has
	// committed) the POINTER to the ONE final (or refund) export. It reads D/shared-
	// memory state; it never fabricates a credit.
	RouteStatus(intentID ID) (RouteStatus, error)
}

// =============================================================================
// RouteWatch — the route subscription handle.
// =============================================================================

// RouteWatch is the subscription a route NotifyCToDExport returns. Poll observes the
// current route phase + hop progress; streamUntilFinal resolves the ONE final (or
// refund) export pointer. It NEVER moves value — the terminal pointer feeds the one
// DS01 settlement, which the chain judges.
type RouteWatch struct {
	session  *V4RouteSession
	intentID ID
	hopCount uint32
}

// IntentID is the route intent this watch tracks.
func (w RouteWatch) IntentID() ID { return w.intentID }

// Poll observes the current route status once (read-only). Gated by AuthWatch.
func (w RouteWatch) Poll(ctx context.Context) (RouteStatus, error) {
	if w.session == nil {
		return RouteStatus{Phase: RouteUnknown}, fmt.Errorf("dexsession: nil route watch")
	}
	if err := w.session.cap.authorizeSelf(AuthWatch); err != nil {
		return RouteStatus{Phase: RouteUnknown}, err
	}
	reqMsg, err := buildRouteWatchPoll(w.intentID)
	if err != nil {
		return RouteStatus{Phase: RouteUnknown}, err
	}
	resp, err := w.session.dex.conn.Call(ctx, w.session.dex.peerID, reqMsg)
	if err != nil {
		return RouteStatus{Phase: RouteUnknown}, err
	}
	defer resp.Release()
	return readRouteStatus(resp), nil
}

// streamUntilFinal polls the route until it commits (the ONE final export), refunds
// (the ONE refund export), is rejected, or ctx ends. A never-resolving route leaves
// the promise pending until ctx — the correct behaviour (no committed export => no
// settlement). It resolves the SINGLE settleable pointer of the whole route.
func (w RouteWatch) streamUntilFinal(ctx context.Context, p *Promise[DExportRef]) {
	backoff := 25 * time.Millisecond
	const maxBackoff = 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			p.fulfil(DExportRef{}, ctx.Err())
			return
		default:
		}
		st, err := w.Poll(ctx)
		if err != nil {
			p.fulfil(DExportRef{}, err)
			return
		}
		switch st.Phase {
		case RouteCommitted, RouteRefunded:
			ref := st.Ref
			ref.IntentID = w.intentID
			p.fulfil(ref, nil)
			return
		case RouteRejected:
			reason := st.Reason
			if reason == "" {
				reason = "route rejected by D"
			}
			p.fulfil(DExportRef{}, fmt.Errorf("dexsession: route %x rejected: %s", w.intentID[:8], reason))
			return
		default:
			if !sleepCtx(ctx, backoff) {
				p.fulfil(DExportRef{}, ctx.Err())
				return
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}
