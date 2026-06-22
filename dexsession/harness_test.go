// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"sync"

	zaplib "github.com/luxfi/zap"
)

// harness_test.go provides the test scaffolding: an in-memory ZAP loopback (so the
// suite needs no socket), and a faithful AtomicLedger that models the C<->D value
// boundary EXACTLY as luxfi/precompile/dex/native_dchain_client.go and
// luxfi/chains/dexvm/atomic.go enforce it. The AtomicLedger is the JUDGE in the
// invariant tests: ZAP responses drive the client; only consuming a real atomic
// object in the ledger moves a balance.

// loopback is an in-process caller that routes a Call straight to a handler map,
// mirroring zap.Node's correlated dispatch without a network. It lets the suite
// drive the full client session against an arbitrary (including malicious) server
// implementation.
type loopback struct {
	mu       sync.RWMutex
	handlers map[uint16]zaplib.Handler
}

func newLoopback() *loopback {
	return &loopback{handlers: make(map[uint16]zaplib.Handler)}
}

func (l *loopback) Handle(msgType uint16, h zaplib.Handler) {
	l.mu.Lock()
	l.handlers[msgType] = h
	l.mu.Unlock()
}

// Call routes msg to the handler for its msgType, returning the handler's response.
// It re-parses the response bytes so the returned *Message is independent (the
// client may Release it). Satisfies the caller interface used by clientSession.
func (l *loopback) Call(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
	msgType := msg.Flags() >> 8
	l.mu.RLock()
	h, ok := l.handlers[msgType]
	l.mu.RUnlock()
	if !ok {
		return nil, context.Canceled // no handler => treat as a dead peer
	}
	resp, err := h(ctx, "test-peer", msg)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, context.Canceled
	}
	// Re-parse a fresh copy so the caller's Release does not disturb the server's
	// buffer (mirrors the network path, which copies across the wire).
	buf := make([]byte, len(resp.Bytes()))
	copy(buf, resp.Bytes())
	return zaplib.Parse(buf)
}

// loopbackHandler is the caller interface backed directly by a Venue, registering
// the same handlers the real FullServiceNode does — but on a loopback. This lets a
// test point a client session at a Venue with no network.
func venueLoopback(v Venue) *loopback {
	l := newLoopback()
	// Re-register the production handlers on the loopback by constructing a
	// FullServiceNode-equivalent handler set. We inline them (mirrors server.go) so
	// the test exercises the SAME request/response codec.
	l.Handle(MsgQuote, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		req := readQuoteRequest(msg)
		res, err := v.Quote(ctx, req)
		if err != nil {
			return buildQuoteResult(QuoteResult{MarketID: req.MarketID, Liquid: false})
		}
		return buildQuoteResult(res)
	})
	l.Handle(MsgGetState, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		req := readStateRequest(msg)
		res, err := v.State(ctx, req)
		if err != nil {
			return buildStateResult(StateResult{Kind: req.Kind})
		}
		return buildStateResult(res)
	})
	l.Handle(MsgNotify, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		pi := readPreparedIntent(msg)
		ref, err := v.NotifyIntent(ctx, pi)
		if err != nil {
			return buildIntentWatchRef(IntentWatchRef{IntentID: pi.IntentID})
		}
		return buildIntentWatchRef(ref)
	})
	l.Handle(MsgWatchPoll, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		intentID := readWatchPollRequest(msg)
		st, err := v.WatchStatus(ctx, intentID)
		if err != nil {
			return buildIntentStatus(IntentStatus{IntentID: intentID, Phase: PhaseUnknown})
		}
		st.IntentID = intentID
		return buildIntentStatus(st)
	})
	l.Handle(MsgImport, func(ctx context.Context, _ string, msg *zaplib.Message) (*zaplib.Message, error) {
		ref := readDExportRef(msg)
		res, err := v.ResolveExport(ctx, ref)
		if err != nil {
			return buildSettlementResult(SettlementSubmitResult{Mode: SettleCalldata, To: addr9999(), ObjectKey: ref.ObjectKey()})
		}
		res.ObjectKey = ref.ObjectKey()
		res.To = addr9999()
		return buildSettlementResult(res)
	})
	return l
}

// =============================================================================
// AtomicLedger — a faithful model of the C<->D value boundary (the JUDGE).
// =============================================================================
//
// It mirrors, byte-rule for byte-rule, the discipline in native_dchain_client.go
// (C side) and dexvm/atomic.go (D side):
//
//	C balance is credited ONLY by ImportSettlement consuming a D->C object: the
//	credited owner/asset/amount are BOUND to the recorded object (mismatch => revert),
//	the object is consumed EXACTLY ONCE (replay => revert), and there is NO MINT (the
//	seam reserve must back it).
//
// Crucially, the ledger's credit path takes NO input from ZAP. It reads the object
// store (shared memory) and a claim. The ONLY way an object enters the store is a
// real D->C export (put). A test that wants money to move MUST place a real object;
// no ZAP response can.

// atomicObject is a recorded D->C export (owner|asset|amount), exactly the 60-byte
// wire DecodeAtomicObject reads.
type atomicObject struct {
	owner  Account
	asset  ID
	amount uint64
}

// AtomicLedger models C-side shared memory + the seam reserve + the consumed set +
// C balances. It is concurrency-safe.
type AtomicLedger struct {
	mu       sync.Mutex
	objects  map[ID]atomicObject // shared-memory D->C export objects (key = ObjectKey)
	consumed map[ID]bool         // one-time settlement guard
	reserve  map[ID]uint64       // seam reserve per asset (must back a credit; no mint)
	balance  map[balKey]uint64   // C balances credited to (owner, asset)
}

type balKey struct {
	owner Account
	asset ID
}

func newAtomicLedger() *AtomicLedger {
	return &AtomicLedger{
		objects:  make(map[ID]atomicObject),
		consumed: make(map[ID]bool),
		reserve:  make(map[ID]uint64),
		balance:  make(map[balKey]uint64),
	}
}

// PutExport places a real D->C export object into shared memory and funds the seam
// reserve to back it. This is the ONLY way value becomes claimable on C — it models
// a real dexvm executeExport after a committed D match. ZAP cannot call this; only
// a test that establishes a real cross-chain object does.
func (l *AtomicLedger) PutExport(key ID, o atomicObject) {
	l.mu.Lock()
	l.objects[key] = o
	l.reserve[o.asset] += o.amount // the export is backed by locked tokenIn / seeding
	l.mu.Unlock()
}

// Balance returns the C balance credited to (owner, asset).
func (l *AtomicLedger) Balance(owner Account, asset ID) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balance[balKey{owner, asset}]
}

// settleClaim is what a settlement tx declares — mirrors precompile SettlementClaim.
// CRITICAL: on-chain the recipient is the CALLER and the asset is DERIVED from the
// swap direction; only outputID + amount ride the calldata. The ledger models the
// FULL bind so a test can attempt substitution and observe rejection.
type settleClaim struct {
	objectKey ID
	asset     ID
	amount    uint64
	recipient Account
}

// ImportSettlement is the faithful C-credit path. It mirrors
// native_dchain_client.go ImportSettlement steps 1-6 EXACTLY:
//
//	1. read the recorded object (missing => revert);
//	2. BIND asset==claim.asset, owner==claim.recipient, amount==claim.amount;
//	3. replay guard (consumed => revert);
//	4. mark consumed (CEI) before value movement;
//	5. credit C from the seam reserve — NO MINT (reserve must back it);
//	6. (atomic remove of the object — modeled by deleting it).
//
// It takes a claim, NOT a ZAP response. There is no parameter for a "fill value" a
// relayer hands it — the credit is the RECORDED object's amount. This is the whole
// invariant in one function.
func (l *AtomicLedger) ImportSettlement(claim settleClaim) (credited uint64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// (1) read the recorded object.
	o, ok := l.objects[claim.objectKey]
	if !ok {
		return 0, errLedgerNoSettlement
	}
	// (2) BIND the credit to the RECORDED value (authoritative, not declared).
	if o.asset != claim.asset {
		return 0, errLedgerAsset
	}
	if o.owner != claim.recipient {
		return 0, errLedgerOwner
	}
	if o.amount != claim.amount {
		return 0, errLedgerAmount
	}
	if o.amount == 0 {
		return 0, errLedgerAmount
	}
	// (3) replay guard.
	if l.consumed[claim.objectKey] {
		return 0, errLedgerReplay
	}
	// (4) mark consumed (CEI) before value movement.
	l.consumed[claim.objectKey] = true
	// (5) credit from the seam reserve — NO MINT.
	if l.reserve[o.asset] < o.amount {
		l.consumed[claim.objectKey] = false // roll back the mark (EVM revert semantics)
		return 0, errLedgerUnbacked
	}
	l.reserve[o.asset] -= o.amount
	l.balance[balKey{o.owner, o.asset}] += o.amount
	// (6) remove the consumed object.
	delete(l.objects, claim.objectKey)
	return o.amount, nil
}

// ledger errors mirror the precompile's ErrNativeSettle* set.
var (
	errLedgerNoSettlement = errLedger("no D->C settlement object for the claimed key")
	errLedgerAsset        = errLedger("object asset != claimed asset")
	errLedgerOwner        = errLedger("object owner != claimed recipient")
	errLedgerAmount       = errLedger("object amount != claimed amount")
	errLedgerReplay       = errLedger("object already consumed (replay)")
	errLedgerUnbacked     = errLedger("seam reserve cannot back the credit (no mint)")
)

type errLedger string

func (e errLedger) Error() string { return "ledger: " + string(e) }

// applySettlementCalldata is the test bridge from a SettlementSubmitResult to the
// ledger: it decodes the Phase-B calldata the way the on-chain handler does
// (deriving recipient=caller, asset from the swap output side) and applies the
// resulting claim. This models "a wallet signs the calldata and the chain executes
// it" — the chain, not ZAP, performs the credit, binding recipient to the caller
// and asset to the swap direction.
//
// caller is who signs/submits (the chain binds recipient := caller). outAsset is
// the swap's output asset (the chain derives it; here the test supplies the true
// output asset). A malicious ZAP cannot influence caller or outAsset — they are the
// chain's, not the ref's.
func (l *AtomicLedger) applySettlementCalldata(res SettlementSubmitResult, caller Account, outAsset ID) (uint64, error) {
	outputID, amount, ok := decodeSettlementCalldata(res.Calldata)
	if !ok {
		return 0, errLedger("malformed settlement calldata")
	}
	return l.ImportSettlement(settleClaim{
		objectKey: outputID,
		asset:     outAsset, // DERIVED on-chain, not from the ZAP ref
		amount:    amount,
		recipient: caller, // BOUND to the caller on-chain, not from the ZAP ref
	})
}

// decodeSettlementCalldata extracts (outputID, amount) from 0x9999 swap calldata
// whose hookData is a Phase-B body. Mirrors the precompile's decodeSwapPhase +
// decodeSettlementBody. Returns ok=false for non-settlement / malformed calldata.
func decodeSettlementCalldata(calldata []byte) (outputID ID, amount uint64, ok bool) {
	// selector(4) + 9 head words (PoolKey 5 + SwapParams 3 + hookData offset 1) +
	// hookData (length word + padded body). The hookData body begins after the
	// length word.
	const headWords = 5 + 3 + 1
	headEnd := 4 + headWords*32
	if len(calldata) < headEnd+32 {
		return ID{}, 0, false
	}
	// hookData length word.
	lenOff := headEnd
	hookLen := int(calldata[lenOff+31]) | int(calldata[lenOff+30])<<8 // small lengths
	bodyOff := lenOff + 32
	if bodyOff+hookLen > len(calldata) {
		return ID{}, 0, false
	}
	hook := calldata[bodyOff : bodyOff+hookLen]
	// Phase-B: tag(4) + outputID(32) + amount(32) + intentID(32). The mock binds on
	// outputID + amount; the intentID word (hook[68:100]) is consumed on-chain by the
	// per-taker cap and is not needed for the substitution properties under test here.
	if len(hook) != 4+settlementBodyLen {
		return ID{}, 0, false
	}
	if string(hook[:4]) != string(settlementPhaseTag[:]) {
		return ID{}, 0, false
	}
	copy(outputID[:], hook[4:36])
	// amount is the low 8 bytes of the 32-byte amount word at hook[36:68].
	for i := 0; i < 8; i++ {
		amount = amount<<8 | uint64(hook[60+i])
	}
	return outputID, amount, true
}
