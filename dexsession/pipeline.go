// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"fmt"
)

// pipeline.go is the high-level, declarative end-to-end flow that wires the five
// operations into the best practical trade path with promise pipelining. It is
// the convenience the spec's example expresses:
//
//	quote  = dex.quote(params)
//	intent = dex.prepareSwapIntent(params, quote)
//	dWatch = dex.notifyIntent(intent)
//	settle = dWatch.onCommitted().importSettlement()
//
// Every stage dispatches the instant its dependency resolves (client-side
// pipelining via thenAsync), so the user-visible latency collapses toward a single
// dependency chain while the consensus path stays native atomic.
//
// SwapFlow returns the FINAL artifact: the on-chain settlement calldata/tx the
// chain consumes against the real D->C object. It is bytes + a pointer — never a
// credit. The caller (wallet) signs the prepared intent calldata, waits for the D
// commit, then signs/submits the settlement calldata. The chain credits.

// FlowStages is the set of promises a SwapFlow produces, exposed so a caller can
// observe intermediate artifacts (e.g. show the user the estimate, the intent id,
// the watch) without re-issuing calls. Each is a value/pointer, never authority.
type FlowStages struct {
	Quote  *Promise[QuoteResult]
	Intent *Promise[PreparedIntent]
	Watch  *Promise[IntentWatch]
	// Committed resolves to the D->C export POINTER when D commits.
	Committed *Promise[DExportRef]
	// Settle resolves to the on-chain settlement calldata/tx (bytes/pointer).
	Settle *Promise[SettlementSubmitResult]
}

// SwapFlow builds and dispatches the full pipelined swap orchestration for a
// request. It does NOT submit the user's C tx (the user signs the prepared intent
// calldata themselves — only the user funds their own swap); it produces the
// artifacts and, after the user's tx + D commit, the settlement calldata.
//
// Pipelining: PrepareSwapIntent overlaps with the Quote (the quote feeds only the
// estimate, not the calldata); NotifyIntent overlaps after the user signals the
// intent is funded; OnCommitted streams the D result; ImportSettlement fires the
// instant the export commits.
//
// NOTE: the user MUST sign+send the PreparedIntent.Calldata to create the funded
// C->D object BEFORE NotifyIntent can find anything to scan. SwapFlow assumes the
// caller drives that step between Intent and Notify (a wallet signs; this layer has
// no signing key and no custody). Callers that want a fully-managed keeper flow
// pass a sign-and-send callback to SwapFlowWithSender below.
func (s *clientSession) SwapFlow(ctx context.Context, req SwapIntentRequest) FlowStages {
	quote := s.Quote(ctx, QuoteRequest{MarketID: req.MarketID, AmountIn: req.AmountIn, ZeroForOne: zeroForOneFor(req)})
	intent := s.PrepareSwapIntent(ctx, req)
	watch := s.NotifyIntent(ctx, intent)
	committed := thenAsync(ctx, watch, func(ctx context.Context, w IntentWatch) (DExportRef, error) {
		return w.OnCommitted(ctx).Await(ctx)
	})
	settle := s.ImportSettlement(ctx, committed)
	return FlowStages{Quote: quote, Intent: intent, Watch: watch, Committed: committed, Settle: settle}
}

// SwapFlowWithSender is SwapFlow with a caller-supplied sign-and-send step
// inserted between PrepareSwapIntent and NotifyIntent. `send` receives the
// prepared calldata + target, signs and submits the C tx (the caller's wallet /
// non-custodial keeper), and returns when the C tx is included (so the C->D object
// exists for D to scan). `send` is the ONLY component with a signing key; this
// layer never holds one.
//
// If send returns an error the flow short-circuits: NotifyIntent is not issued
// (there is no funded object to scan), and every downstream promise resolves with
// that error.
func (s *clientSession) SwapFlowWithSender(
	ctx context.Context,
	req SwapIntentRequest,
	send func(ctx context.Context, to Account, calldata []byte) error,
) FlowStages {
	quote := s.Quote(ctx, QuoteRequest{MarketID: req.MarketID, AmountIn: req.AmountIn, ZeroForOne: zeroForOneFor(req)})
	intent := s.PrepareSwapIntent(ctx, req)

	// After the intent is prepared, sign+send the user's C tx, THEN notify D. This
	// is the one stage that requires authority OUTSIDE this layer (a signing key);
	// it is injected, never held here.
	funded := thenAsync(ctx, intent, func(ctx context.Context, pi PreparedIntent) (PreparedIntent, error) {
		if send == nil {
			return PreparedIntent{}, fmt.Errorf("dexsession: SwapFlowWithSender requires a sender")
		}
		if err := send(ctx, pi.To, pi.Calldata); err != nil {
			return PreparedIntent{}, fmt.Errorf("dexsession: fund C->D intent: %w", err)
		}
		return pi, nil
	})

	watch := s.NotifyIntent(ctx, funded)
	committed := thenAsync(ctx, watch, func(ctx context.Context, w IntentWatch) (DExportRef, error) {
		return w.OnCommitted(ctx).Await(ctx)
	})
	settle := s.ImportSettlement(ctx, committed)
	return FlowStages{Quote: quote, Intent: intent, Watch: watch, Committed: committed, Settle: settle}
}
