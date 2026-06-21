// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

// v4msg.go is the BIDIRECTIONAL control-plane message set, named V4-native. It is
// PURE VALUES — message-type constants, a direction classification, and the typed
// D->C read event a session surfaces. It has NO transport and NO value path: a
// message is a label for "what flows on the control plane", orthogonal to the wire
// bytes (wire.go owns the single transport encoding) and to authority (capability.go
// owns the grants).
//
// THE LOCKED FRAMING (CTO):
//
//	0x9999      = on-chain authority / V4 ABI
//	ZAP         = bidirectional binary session / CONTROL PLANE  <- this file
//	shared mem  = consensus value boundary / MONEY PLANE
//	D           = matching authority
//	C           = EVM balance authority
//
// During a swap's lifetime BOTH C-side and D-side services read/write through ZAP.
// The ONE constraint, enforced structurally and proven by test:
//
//	ZAP read/write may UPDATE session/orchestration state.
//	ZAP read/write MUST NOT MOVE VALUE.
//
// Money still moves ONLY via: C -> D atomic object -> D dexvm import/match/export ->
// D -> C atomic object -> 0x9999 import/credit. Every D->C read below (even
// MatchResult{amountOut}) is ORCHESTRATION STATE; the credit happens on-chain when a
// real D->C object is consumed via the DS01 Phase-B settlement (the ONE credit path
// for swaps, routes, collects, decreases, and cancels alike — see v4liquidity.go).

// V4MsgType is a control-plane message-type. The constants below are the V4-native
// SEMANTIC names the spec mandates. Each maps to an underlying wire frame (Msg* in
// wire.go) or to a LOCAL lifecycle transition (no wire frame — e.g. *_OPEN mints a
// scoped capability client-side). A session is a state machine that emits/consumes
// these; the mapping (v4Wire) keeps the wire the single source of transport truth.
type V4MsgType uint16

// V4Dir classifies a message by who originates it on the bidirectional plane.
type V4Dir uint8

const (
	// DirCToD is a C-side -> D-side WRITE (request side of a Call, or the user's
	// signed C tx the write refers to). It may trigger D work; it never moves value.
	DirCToD V4Dir = iota
	// DirDToC is a D-side -> C-side READ (response side of a Call, or a watch
	// push/poll). It carries estimates / status / a POINTER; never a credit.
	DirDToC
	// DirLocal is a client-side lifecycle transition (open/close): it mints/retires a
	// scoped capability and session state. It touches no peer and no value.
	DirLocal
)

// ----------------------------------------------------------------------------
// Swap action (V4SwapSession): the canonical single-swap lifecycle.
// ----------------------------------------------------------------------------
//
// Lifecycle (promise-pipelined), with direction in brackets:
//
//	OPEN [local]
//	  -> PREPARE_INTENT     [C->D] build 0x9999 swap calldata (DI01) the user signs
//	  -> NOTIFY_C_EXPORT    [C->D] tell D to scan the C->D object the signed tx made
//	  <- D_IMPORTED         [D->C] D imported the C->D object (Phase Matching)
//	  <- MATCHED            [D->C] D matched (MatchResult.amountOut = ESTIMATE only)
//	  <- D_EXPORT_READY     [D->C] D committed a D->C export (DExportRef POINTER)
//	  -> PREPARE_C_SETTLEMENT [C->D] build 0x9999 settlement calldata (DS01) at the ref
//	  -> SUBMIT_C_SETTLEMENT  [C->D] (optional) a keeper submits the signed C tx
//	  <- C_SETTLED          [D->C] C consumed the real object and credited (observed)
const (
	V4_SWAP_OPEN V4MsgType = 0x1000 + iota
	V4_SWAP_PREPARE_INTENT
	V4_SWAP_NOTIFY_C_EXPORT
	V4_SWAP_D_IMPORTED
	V4_SWAP_MATCHED
	V4_SWAP_D_EXPORT_READY
	V4_SWAP_PREPARE_C_SETTLEMENT
	V4_SWAP_SUBMIT_C_SETTLEMENT
	V4_SWAP_C_SETTLED
)

// ----------------------------------------------------------------------------
// Route action (V4RouteSession): MULTI-HOP. C input -> D route A->B->C -> ONE
// final D->C export. The route STAYS ON D between hops; ZAP streams hop progress.
// ----------------------------------------------------------------------------
//
//	OPEN [local]
//	  -> PREPARE_INTENT     [C->D] ONE route-intent calldata (DI01 + path body)
//	  -> NOTIFY_C_EXPORT    [C->D] tell D to scan the single C->D input object
//	  <- HOP_STARTED        [D->C] D began hop i (orchestration — no C object)
//	  <- HOP_FILLED         [D->C] D filled hop i (intermediate amount — orchestration)
//	  <- D_EXPORT_READY     [D->C] D committed the ONE final D->C export (POINTER)
//	  <- REFUND_READY       [D->C] route failed: D exported a refund of the INPUT asset
//	  -> PREPARE_C_SETTLEMENT [C->D] settle the ONE final (or refund) export (DS01)
//	  <- C_SETTLED          [D->C] C credited from the single real object (observed)
const (
	V4_ROUTE_OPEN V4MsgType = 0x1100 + iota
	V4_ROUTE_PREPARE_INTENT
	V4_ROUTE_NOTIFY_C_EXPORT
	V4_ROUTE_HOP_STARTED
	V4_ROUTE_HOP_FILLED
	V4_ROUTE_D_EXPORT_READY
	V4_ROUTE_REFUND_READY
	V4_ROUTE_PREPARE_C_SETTLEMENT
	V4_ROUTE_C_SETTLED
)

// ----------------------------------------------------------------------------
// Liquidity action (V4LiquiditySession): modifyLiquidity COMMIT — a funded C->D
// position. A deposit: it creates a C->D object only. No D->C export, no C credit.
// ----------------------------------------------------------------------------
//
//	OPEN [local]
//	  -> PREPARE_COMMIT     [C->D] build 0x9999 modifyLiquidity calldata (+delta)
//	  -> NOTIFY_C_EXPORT    [C->D] tell D to scan the funded C->D position object
//	  <- D_COMMITTED        [D->C] D recorded the position (orchestration)
//	  <- POSITION_OPEN      [D->C] the position id is live (orchestration)
const (
	V4_LP_OPEN V4MsgType = 0x1200 + iota
	V4_LP_PREPARE_COMMIT
	V4_LP_NOTIFY_C_EXPORT
	V4_LP_D_COMMITTED
	V4_LP_POSITION_OPEN
)

// ----------------------------------------------------------------------------
// Collect action (V4CollectSession): collect/decrease — D->C export -> C credit.
// The withdrawn fees / removed liquidity become a D->C object settled via DS01.
// ----------------------------------------------------------------------------
//
//	OPEN [local]
//	  -> REQUEST            [C->D] ask D to collect/decrease (build -delta calldata)
//	  <- D_EXPORT_READY     [D->C] D committed the D->C export of the collected value
//	  -> PREPARE_C_SETTLEMENT [C->D] settle the export (DS01) -> credit
//	  <- C_SETTLED          [D->C] C credited from the real object (observed)
const (
	V4_COLLECT_OPEN V4MsgType = 0x1300 + iota
	V4_COLLECT_REQUEST
	V4_COLLECT_D_EXPORT_READY
	V4_COLLECT_PREPARE_C_SETTLEMENT
	V4_COLLECT_C_SETTLED
)

// ----------------------------------------------------------------------------
// Cancel action (V4 openCancel): cancel a resting order -> D->C refund export ->
// C credit (of the originally-locked asset). Same credit path as collect (DS01).
// ----------------------------------------------------------------------------
const (
	V4_CANCEL_OPEN V4MsgType = 0x1400 + iota
	V4_CANCEL_REQUEST
	V4_CANCEL_D_EXPORT_READY
	V4_CANCEL_PREPARE_C_SETTLEMENT
	V4_CANCEL_C_SETTLED
)

// ----------------------------------------------------------------------------
// State action (V4StateSession): read-only quote/book/state streaming.
// ----------------------------------------------------------------------------
const (
	V4_STATE_OPEN V4MsgType = 0x1500 + iota
	V4_STATE_QUOTE_UPDATE
	V4_STATE_BOOK_UPDATE
	V4_STATE_CLOSE
)

// Common terminal reads, valid on any session.
const (
	// V4_ERROR is a D->C error read (the venue reports a non-fatal failure for this
	// action). It carries a reason; it never moves value.
	V4_ERROR V4MsgType = 0x1F00 + iota
	// V4_HALTED is a D->C read that the action's market/asset/global swap path is
	// halted. The session refuses to advance (fail-secure). It moves no value (a halt
	// blocks NEW swaps; funds still exit via the un-halted settlement path on-chain).
	V4_HALTED
)

// Dir reports the control-plane direction of a message-type. C->D writes carry a
// request to D (or refer to the user's signed C tx); D->C reads carry status /
// estimates / a pointer; local transitions are client-side capability lifecycle.
func (t V4MsgType) Dir() V4Dir {
	switch t {
	case V4_SWAP_OPEN, V4_ROUTE_OPEN, V4_LP_OPEN, V4_COLLECT_OPEN, V4_CANCEL_OPEN, V4_STATE_OPEN, V4_STATE_CLOSE:
		return DirLocal
	case
		V4_SWAP_PREPARE_INTENT, V4_SWAP_NOTIFY_C_EXPORT, V4_SWAP_PREPARE_C_SETTLEMENT, V4_SWAP_SUBMIT_C_SETTLEMENT,
		V4_ROUTE_PREPARE_INTENT, V4_ROUTE_NOTIFY_C_EXPORT, V4_ROUTE_PREPARE_C_SETTLEMENT,
		V4_LP_PREPARE_COMMIT, V4_LP_NOTIFY_C_EXPORT,
		V4_COLLECT_REQUEST, V4_COLLECT_PREPARE_C_SETTLEMENT,
		V4_CANCEL_REQUEST, V4_CANCEL_PREPARE_C_SETTLEMENT:
		return DirCToD
	default:
		// Everything else is a D->C read (D_IMPORTED, MATCHED, *_EXPORT_READY,
		// HOP_*, REFUND_READY, *_COMMITTED, POSITION_OPEN, *_C_SETTLED, QUOTE/BOOK
		// updates, ERROR, HALTED).
		return DirDToC
	}
}

// CreditsValue reports whether a message-type, by ITSELF, credits a C balance.
// IT IS ALWAYS FALSE. This is the machine-checkable statement of the money-plane
// invariant over the entire bidirectional message set: no control-plane message —
// in either direction — moves value. The credit happens on-chain, off this plane,
// when a real D->C atomic object is consumed (DS01 Phase-B settlement). The RED
// suite proves this dynamically; this method states it for the type system and for
// any caller that wants to assert it (e.g. a gateway audit).
func (t V4MsgType) CreditsValue() bool { return false }

// v4Wire maps a control-plane message-type to its underlying wire frame (a Msg*
// from wire.go) for the messages that cross the network. DirLocal transitions and
// the streamed sub-states of a single wire frame (e.g. D_IMPORTED / MATCHED /
// D_EXPORT_READY are all phases of one MsgWatchPoll/Push) return ok=false: they are
// not distinct frames, they are interpretations of a status. Keeping the wire frames
// as the single transport truth (and the V4 names as a semantic overlay) is the
// "one way to do everything" discipline — the V4 layer adds NO second transport.
func v4Wire(t V4MsgType) (uint16, bool) {
	switch t {
	case V4_SWAP_PREPARE_INTENT, V4_ROUTE_PREPARE_INTENT:
		return MsgPrepare, true
	case V4_SWAP_NOTIFY_C_EXPORT, V4_ROUTE_NOTIFY_C_EXPORT, V4_LP_NOTIFY_C_EXPORT:
		return MsgNotify, true
	case V4_SWAP_PREPARE_C_SETTLEMENT, V4_ROUTE_PREPARE_C_SETTLEMENT,
		V4_COLLECT_PREPARE_C_SETTLEMENT, V4_CANCEL_PREPARE_C_SETTLEMENT:
		return MsgImport, true
	case V4_LP_PREPARE_COMMIT, V4_COLLECT_REQUEST, V4_CANCEL_REQUEST:
		return MsgPrepare, true // committed/collected/cancelled via a prepare call
	case V4_STATE_QUOTE_UPDATE:
		return MsgQuote, true
	case V4_STATE_BOOK_UPDATE:
		return MsgGetState, true
	default:
		return 0, false
	}
}

// String renders a message-type for logs/tests. (No fmt dependency in the hot path;
// a small switch keeps it allocation-free for the common types.)
func (t V4MsgType) String() string {
	switch t {
	case V4_SWAP_OPEN:
		return "V4_SWAP_OPEN"
	case V4_SWAP_PREPARE_INTENT:
		return "V4_SWAP_PREPARE_INTENT"
	case V4_SWAP_NOTIFY_C_EXPORT:
		return "V4_SWAP_NOTIFY_C_EXPORT"
	case V4_SWAP_D_IMPORTED:
		return "V4_SWAP_D_IMPORTED"
	case V4_SWAP_MATCHED:
		return "V4_SWAP_MATCHED"
	case V4_SWAP_D_EXPORT_READY:
		return "V4_SWAP_D_EXPORT_READY"
	case V4_SWAP_PREPARE_C_SETTLEMENT:
		return "V4_SWAP_PREPARE_C_SETTLEMENT"
	case V4_SWAP_SUBMIT_C_SETTLEMENT:
		return "V4_SWAP_SUBMIT_C_SETTLEMENT"
	case V4_SWAP_C_SETTLED:
		return "V4_SWAP_C_SETTLED"
	case V4_ROUTE_HOP_STARTED:
		return "V4_ROUTE_HOP_STARTED"
	case V4_ROUTE_HOP_FILLED:
		return "V4_ROUTE_HOP_FILLED"
	case V4_ROUTE_D_EXPORT_READY:
		return "V4_ROUTE_D_EXPORT_READY"
	case V4_ROUTE_REFUND_READY:
		return "V4_ROUTE_REFUND_READY"
	case V4_LP_D_COMMITTED:
		return "V4_LP_D_COMMITTED"
	case V4_LP_POSITION_OPEN:
		return "V4_LP_POSITION_OPEN"
	case V4_COLLECT_D_EXPORT_READY:
		return "V4_COLLECT_D_EXPORT_READY"
	case V4_CANCEL_D_EXPORT_READY:
		return "V4_CANCEL_D_EXPORT_READY"
	case V4_ERROR:
		return "V4_ERROR"
	case V4_HALTED:
		return "V4_HALTED"
	default:
		return "V4_MSG"
	}
}

// V4Event is the typed D->C read a session surfaces to the caller (the orchestration
// stream). It is a VALUE: a label + the orchestration payload + an OPTIONAL pointer.
// It NEVER carries authority over a balance:
//
//   - Type        — the V4MsgType (always a DirDToC read).
//   - SessionID   — the action the event belongs to (binds it to its session).
//   - IntentID    — the originating intent (correlation).
//   - EstAmount   — an ESTIMATE (quote / matched-out / hop-out). NOT a credit; the
//     chain never trusts it. Exactly the QuotedOut discipline, extended to matches.
//   - HopIndex    — the route hop this event describes (route events only).
//   - Ref         — the D->C export POINTER, set ONLY on *_EXPORT_READY / REFUND_READY.
//     The credit still happens on-chain when the real object behind Ref is consumed.
//   - Reason      — human text for ERROR / HALTED / REFUND.
type V4Event struct {
	Type      V4MsgType
	SessionID ID
	IntentID  ID
	EstAmount uint64
	HopIndex  uint32
	Ref       DExportRef
	Reason    string
}

// HasRef reports whether the event carries a settleable export pointer. Even when
// true, the pointer only NAMES an object the chain re-verifies on import — it is not
// a credit.
func (e V4Event) HasRef() bool {
	return e.Type == V4_SWAP_D_EXPORT_READY ||
		e.Type == V4_ROUTE_D_EXPORT_READY ||
		e.Type == V4_ROUTE_REFUND_READY ||
		e.Type == V4_COLLECT_D_EXPORT_READY ||
		e.Type == V4_CANCEL_D_EXPORT_READY
}
