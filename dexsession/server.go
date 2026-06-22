// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"

	zaplib "github.com/luxfi/zap"
)

// server.go is the FullServiceNode side: it registers the DexSession ZAP handlers
// on a zap.Node and backs them against a Venue (the D-Chain CLOB + a C/D state
// reader). Bootstrap returns a restricted client DexSession for a peer.
//
// THE SERVER NEVER CREDITS. It reads the D book (quote), reads C/D state
// (getState), tells D to scan an intent and reports the resulting export POINTER
// (notify + watch), and reports a D->C export object's coordinates (the ref). It
// has no path to write a C balance — that is the chain's, via consuming a real
// atomic object. A compromised server can lie about every response; the value
// boundary (precompile / dexvm) rejects any lie because it reads the real object.

// Venue is the read + trigger backend a DexSession server delegates to. It is the
// D-Chain CLOB venue and a C/D state reader. CRITICALLY, it has no credit/settle
// method: the orchestration server cannot move value because its backend cannot
// either. (A real deployment backs Venue with the lux/dex ZAP CLOB client over the
// existing clob_* transport for quotes, plus a chain-state reader for exports.)
type Venue interface {
	// Quote returns an ESTIMATE from the resting book. Read-only.
	Quote(ctx context.Context, req QuoteRequest) (QuoteResult, error)

	// State returns a read-only C/D DEX observation.
	State(ctx context.Context, req StateRequest) (StateResult, error)

	// NotifyIntent asks the venue to begin scanning shared memory for the C->D
	// object named by the intent and submit a D tx that imports+matches it under
	// dexvm consensus. It returns immediately with the intent id to watch; it does
	// NOT block on a D block and does NOT credit anything. A no-op-but-record
	// implementation is valid (the keeper picks up the on-chain IntentSubmitted
	// event); the watch then observes the export when D commits.
	NotifyIntent(ctx context.Context, intent PreparedIntent) (IntentWatchRef, error)

	// WatchStatus reports the current phase of a notified intent and, when D has
	// committed an export, the POINTER to it. It reads D/shared-memory state; it
	// never fabricates a credit. Returning PhaseCommitted with a ref is a CLAIM the
	// chain re-verifies on import.
	WatchStatus(ctx context.Context, intentID ID) (IntentStatus, error)

	// ResolveExport maps a DExportRef to the on-chain settlement calldata that
	// points at the real D->C object. It does NOT submit and does NOT credit; it
	// returns the bytes a wallet/keeper signs. The asset+recipient are NOT taken
	// from the ref (the chain derives the asset from swap direction and binds the
	// recipient to the caller); the calldata carries only outputID + amount, and
	// even those are bound on-chain. amount is the venue's best knowledge of the
	// export amount, used to populate the claim; a wrong amount makes the on-chain
	// bind revert (it must equal the recorded object's amount).
	ResolveExport(ctx context.Context, ref DExportRef) (SettlementSubmitResult, error)
}

// FullServiceNode wraps a zap.Node and a Venue, exposing Bootstrap. It is the
// server-side object the spec's `FullServiceNode.bootstrap() -> DexSession`
// describes.
type FullServiceNode struct {
	node    *zaplib.Node
	venue   Venue
	markets func(marketID ID) (PoolKeyArgs, bool)
}

// FullServiceConfig configures the server node.
type FullServiceConfig struct {
	Node    *zaplib.Node
	Venue   Venue
	// Markets maps a marketID to its V4 PoolKey args, shared with bootstrapped
	// client sessions so prepareSwapIntent can build calldata. Required for swap
	// preparation; nil => prepare fail-closes for every market.
	Markets func(marketID ID) (PoolKeyArgs, bool)
}

// NewFullServiceNode constructs the server and registers its ZAP handlers on the
// node. Call node.Start() separately (the caller owns the node lifecycle).
func NewFullServiceNode(cfg FullServiceConfig) *FullServiceNode {
	fsn := &FullServiceNode{node: cfg.Node, venue: cfg.Venue, markets: cfg.Markets}
	fsn.registerHandlers()
	return fsn
}

// Bootstrap returns a RESTRICTED client DexSession for a peer, granted `grant`
// authority. This is the capability bootstrap: the caller receives a session that
// can derive only capabilities within `grant`, and NONE of those can move money
// (see capability.go). A public surface passes AuthorityPublic; a price widget
// passes AuthorityReadOnly; an operator console adds AuthAdmin.
//
// peerID is the ZAP node id of THIS server (the session Calls it). In-process and
// remote callers both use the node's correlated Call.
func (fsn *FullServiceNode) Bootstrap(peerID string, grant Authority) DexSession {
	return NewSession(SessionConfig{
		Conn:    fsn.node,
		PeerID:  peerID,
		Grant:   grant,
		Markets: fsn.markets,
	})
}

// registerHandlers wires the five read/trigger operations onto the node. Each
// handler decodes a typed request, delegates to the Venue (read/trigger only), and
// encodes a typed response. There is no handler that writes a balance.
func (fsn *FullServiceNode) registerHandlers() {
	fsn.node.Handle(MsgQuote, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		res, err := fsn.venue.Quote(ctx, readQuoteRequest(msg))
		if err != nil {
			// Fail-closed: an unliquid/unknown market returns a non-liquid estimate,
			// never an error that could be mistaken for a tradeable quote.
			return buildQuoteResult(QuoteResult{MarketID: readQuoteRequest(msg).MarketID, Liquid: false})
		}
		return buildQuoteResult(res)
	})

	fsn.node.Handle(MsgGetState, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		res, err := fsn.venue.State(ctx, readStateRequest(msg))
		if err != nil {
			return buildStateResult(StateResult{Kind: readStateRequest(msg).Kind, Exists: false})
		}
		return buildStateResult(res)
	})

	fsn.node.Handle(MsgNotify, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		ref, err := fsn.venue.NotifyIntent(ctx, readPreparedIntent(msg))
		if err != nil {
			// A notify that the venue cannot accept still returns a watch ref for the
			// intent id; the watch then reports PhaseRejected. We never error the
			// notify into a value claim.
			pi := readPreparedIntent(msg)
			return buildIntentWatchRef(IntentWatchRef{IntentID: pi.IntentID})
		}
		return buildIntentWatchRef(ref)
	})

	fsn.node.Handle(MsgWatchPoll, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		intentID := readWatchPollRequest(msg)
		st, err := fsn.venue.WatchStatus(ctx, intentID)
		if err != nil {
			return buildIntentStatus(IntentStatus{IntentID: intentID, Phase: PhaseUnknown, Reason: "venue unavailable"})
		}
		st.IntentID = intentID
		return buildIntentStatus(st)
	})

	fsn.node.Handle(MsgImport, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		ref := readDExportRef(msg)
		res, err := fsn.venue.ResolveExport(ctx, ref)
		if err != nil {
			// Fail-closed: if the venue cannot resolve the export, return a result
			// whose calldata is empty (the caller cannot submit a no-op as a credit;
			// the chain would reject empty/invalid calldata). Never fabricate a credit.
			return buildSettlementResult(SettlementSubmitResult{Mode: SettleCalldata, To: addr9999(), ObjectKey: ref.ObjectKey()})
		}
		// Defence in depth: force the result's ObjectKey to the ref-derived key so the
		// venue cannot point the caller at a different object than the ref names.
		res.ObjectKey = ref.ObjectKey()
		res.To = addr9999()
		return buildSettlementResult(res)
	})

	// Route handlers — registered ONLY when the venue ALSO implements RouteVenue
	// (composition, not interface-expansion). A base Venue without route support
	// simply has no route frames; a route notify/poll to such a node is a dead peer
	// (fail-closed). The route handlers report progress + the ONE final POINTER; they
	// never credit (RouteVenue, like Venue, has no settle method).
	if rv, ok := fsn.venue.(RouteVenue); ok {
		fsn.node.Handle(MsgRoutePrepare, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
			req := readRouteRequest(msg)
			ref, err := rv.NotifyRoute(req)
			if err != nil {
				// The client builds calldata locally; NotifyRoute only triggers the walk.
				// On failure, return the deterministic intent id so the watch can report
				// the rejection — never an error mistaken for a value claim.
				first, _ := req.firstMarket()
				id := DeriveIntentID(req.NetworkID, req.CChainID, req.DChainID, req.Account, req.AssetIn, req.AmountIn, first, uint64(req.CallIndex))
				return buildIntentWatchRef(IntentWatchRef{IntentID: id})
			}
			return buildIntentWatchRef(ref)
		})
		fsn.node.Handle(MsgRouteStatus, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
			intentID := readRouteWatchPoll(msg)
			st, err := rv.RouteStatus(intentID)
			if err != nil {
				return buildRouteStatus(RouteStatus{IntentID: intentID, Phase: RouteUnknown, Reason: "venue unavailable"})
			}
			st.IntentID = intentID
			return buildRouteStatus(st)
		})
	}
}
