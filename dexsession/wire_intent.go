// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	zaplib "github.com/luxfi/zap"
)

// wire_intent.go carries the intent / settlement envelopes — the request side
// (SwapIntentRequest), the build result (PreparedIntent: CALLDATA, never funds),
// the D-result pointer (DExportRef), and the watch/import results.
//
// The whole point lives here: a PreparedIntent is CALLDATA the user signs, and a
// DExportRef is a POINTER. Neither is value. The chain mints/credits only when a
// real atomic object is consumed (precompile ImportSettlement / dexvm
// executeImport); these envelopes can only name what to sign or which object to
// point at.

// =============================================================================
// SwapIntentRequest / PreparedIntent
// =============================================================================

// SwapIntentRequest is the off-chain request to PREPARE a C->D swap intent. The
// session validates params, estimates a quote, derives the intent id, and
// returns a PreparedIntent (calldata). It reserves NO funds and returns NO
// enforceable amountOut.
type SwapIntentRequest struct {
	NetworkID    uint32
	CChainID     ID
	DChainID     ID
	Account      Account // taker — bound as the C->D object owner on-chain
	AssetIn      ID      // full injective asset id locked on C
	AssetInAddr  Account // ERC-20 token (zero for native) for the C lock
	AmountIn     uint64
	MarketID     ID
	MinAmountOut uint64  // taker slippage floor — encoded into the signed tx
	Recipient    Account // where the D->C settlement must credit
	Deadline     uint64
	// CallIndex disambiguates two swaps in one tx — matches the precompile's
	// per-tx CallIndex. The user's wallet sets it; off-chain prepare uses 0 for a
	// single-call tx and the caller overrides for batched calls.
	CallIndex uint32
}

// PreparedIntent is the OUTPUT of prepareSwapIntent: everything the user needs to
// sign a normal C tx to 0x9999 that creates the funded C->D intent. It is bytes,
// not authority:
//
//   - To      — the 0x9999 settlement address (the precompile).
//   - Calldata — selector + ABI-encoded args for the on-chain swap entry.
//   - HookData — the V4 hookData the 0x9999 handler consumes (routing payload).
//   - IntentID — the deterministic id the on-chain SubmitSwapIntent will mint
//     (derived identically here; lets the watch locate the D result).
//   - QuotedOut — the ESTIMATE used to build it (informational, not enforceable).
//
// MUST NOT: reserve funds off-chain, claim a fill final, return an amountOut the
// chain trusts. The QuotedOut is explicitly informational; the enforceable floor
// is MinAmountOut baked into Calldata, which the chain/D check.
type PreparedIntent struct {
	To        Account // 0x9999
	Calldata  []byte  // selector + args (the user signs a tx with this data)
	HookData  []byte  // V4 hookData consumed by the 0x9999 handler
	IntentID  ID      // deterministic id the signed tx will create on C
	QuotedOut uint64  // estimate only
	// Echoed request identity so the watch / import can reconstruct the binding
	// without holding the whole request.
	DChainID  ID
	CChainID  ID
	Account   Account
	Recipient Account
	AssetIn   ID
	AmountIn  uint64
	MarketID  ID
}

// Fixed inline byte arrays first (full width), then the two variable bytes slots
// (8 bytes each). Calldata/HookData tails are appended after the fixed section.
const (
	piTo        = 0   // bytes20 [0:20]
	piIntent    = 20  // bytes32 [20:52]
	piQuoted    = 52  // uint64
	piAmountIn  = 60  // uint64
	piDChain    = 68  // bytes32 [68:100]
	piCChain    = 100 // bytes32 [100:132]
	piAccount   = 132 // bytes20 [132:152]
	piRecipient = 152 // bytes20 [152:172]
	piAssetIn   = 172 // bytes32 [172:204]
	piMarket    = 204 // bytes32 [204:236]
	piCalldata  = 236 // bytes  (slot 8)
	piHookData  = 244 // bytes  (slot 8)
	piSize      = 252
)

func buildPreparedIntent(p PreparedIntent) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(piSize + len(p.Calldata) + len(p.HookData) + 256)
	ob := b.StartObject(piSize)
	ob.SetBytesFixed(piTo, p.To[:])
	ob.SetBytesFixed(piIntent, p.IntentID[:])
	ob.SetUint64(piQuoted, p.QuotedOut)
	ob.SetUint64(piAmountIn, p.AmountIn)
	ob.SetBytesFixed(piDChain, p.DChainID[:])
	ob.SetBytesFixed(piCChain, p.CChainID[:])
	ob.SetBytesFixed(piAccount, p.Account[:])
	ob.SetBytesFixed(piRecipient, p.Recipient[:])
	ob.SetBytesFixed(piAssetIn, p.AssetIn[:])
	ob.SetBytesFixed(piMarket, p.MarketID[:])
	ob.SetBytes(piCalldata, p.Calldata)
	ob.SetBytes(piHookData, p.HookData)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgPrepare << 8))
}

func readPreparedIntent(m *zaplib.Message) PreparedIntent {
	r := m.Root()
	var p PreparedIntent
	copy(p.To[:], r.BytesFixedSlice(piTo, 20))
	copy(p.IntentID[:], r.BytesFixedSlice(piIntent, 32))
	p.QuotedOut = r.Uint64(piQuoted)
	p.AmountIn = r.Uint64(piAmountIn)
	copy(p.DChainID[:], r.BytesFixedSlice(piDChain, 32))
	copy(p.CChainID[:], r.BytesFixedSlice(piCChain, 32))
	copy(p.Account[:], r.BytesFixedSlice(piAccount, 20))
	copy(p.Recipient[:], r.BytesFixedSlice(piRecipient, 20))
	copy(p.AssetIn[:], r.BytesFixedSlice(piAssetIn, 32))
	copy(p.MarketID[:], r.BytesFixedSlice(piMarket, 32))
	p.Calldata = append([]byte(nil), r.Bytes(piCalldata)...)
	p.HookData = append([]byte(nil), r.Bytes(piHookData)...)
	return p
}

// the SwapIntentRequest envelope (client -> server for MsgPrepare).
const (
	sirNet       = 0   // uint32
	sirCallIdx   = 4   // uint32
	sirAmountIn  = 8   // uint64
	sirMinOut    = 16  // uint64
	sirDeadline  = 24  // uint64
	sirCChain    = 32  // bytes32 [32:64]
	sirDChain    = 64  // bytes32 [64:96]
	sirAccount   = 96  // bytes20 [96:116]
	sirAssetIn   = 116 // bytes32 [116:148]
	sirAssetAddr = 148 // bytes20 [148:168]
	sirMarket    = 168 // bytes32 [168:200]
	sirRecipient = 200 // bytes20 [200:220]
	sirSize      = 220
)

func buildSwapIntentRequest(r SwapIntentRequest) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(sirSize + 256)
	ob := b.StartObject(sirSize)
	ob.SetUint32(sirNet, r.NetworkID)
	ob.SetUint32(sirCallIdx, r.CallIndex)
	ob.SetUint64(sirAmountIn, r.AmountIn)
	ob.SetUint64(sirMinOut, r.MinAmountOut)
	ob.SetUint64(sirDeadline, r.Deadline)
	ob.SetBytesFixed(sirCChain, r.CChainID[:])
	ob.SetBytesFixed(sirDChain, r.DChainID[:])
	ob.SetBytesFixed(sirAccount, r.Account[:])
	ob.SetBytesFixed(sirAssetIn, r.AssetIn[:])
	ob.SetBytesFixed(sirAssetAddr, r.AssetInAddr[:])
	ob.SetBytesFixed(sirMarket, r.MarketID[:])
	ob.SetBytesFixed(sirRecipient, r.Recipient[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgPrepare << 8))
}

func readSwapIntentRequest(m *zaplib.Message) SwapIntentRequest {
	r := m.Root()
	var out SwapIntentRequest
	out.NetworkID = r.Uint32(sirNet)
	out.CallIndex = r.Uint32(sirCallIdx)
	out.AmountIn = r.Uint64(sirAmountIn)
	out.MinAmountOut = r.Uint64(sirMinOut)
	out.Deadline = r.Uint64(sirDeadline)
	copy(out.CChainID[:], r.BytesFixedSlice(sirCChain, 32))
	copy(out.DChainID[:], r.BytesFixedSlice(sirDChain, 32))
	copy(out.Account[:], r.BytesFixedSlice(sirAccount, 20))
	copy(out.AssetIn[:], r.BytesFixedSlice(sirAssetIn, 32))
	copy(out.AssetInAddr[:], r.BytesFixedSlice(sirAssetAddr, 20))
	copy(out.MarketID[:], r.BytesFixedSlice(sirMarket, 32))
	copy(out.Recipient[:], r.BytesFixedSlice(sirRecipient, 20))
	return out
}

// =============================================================================
// DExportRef — the POINTER (NOT a DFillReceipt)
// =============================================================================

// DExportRef points at a D->C atomic export object. It is deliberately NOT a
// DFillReceipt: it carries no amount the chain trusts and no signature C honours.
// The chain re-reads the actual object (asset/owner/amount/one-time) on import.
//
//	SourceChainID — the D chain whose export the object lives under.
//	SourceTxID    — the D tx that produced the export.
//	OutputIndex   — which exported output (deriveUTXOID(SourceTxID, OutputIndex)).
//	IntentID      — the originating C->D intent (correlation only).
type DExportRef struct {
	SourceChainID ID
	SourceTxID    ID
	OutputIndex   uint32
	IntentID      ID
}

// ObjectKey is the shared-memory UTXO key the on-chain ImportSettlement reads.
// Derived deterministically from (SourceTxID, OutputIndex) — the chain derives
// the same key and binds the object to it, so a forged key just names a missing
// object and the import reverts.
func (r DExportRef) ObjectKey() ID { return DeriveUTXOID(r.SourceTxID, r.OutputIndex) }

const (
	derIndex  = 0   // uint32
	derChain  = 8   // bytes32 [8:40]
	derTx     = 40  // bytes32 [40:72]
	derIntent = 72  // bytes32 [72:104]
	derSize   = 104
)

func buildDExportRef(r DExportRef) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(derSize + 120)
	ob := b.StartObject(derSize)
	ob.SetUint32(derIndex, r.OutputIndex)
	ob.SetBytesFixed(derChain, r.SourceChainID[:])
	ob.SetBytesFixed(derTx, r.SourceTxID[:])
	ob.SetBytesFixed(derIntent, r.IntentID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgImport << 8))
}

func readDExportRef(m *zaplib.Message) DExportRef {
	r := m.Root()
	var out DExportRef
	out.OutputIndex = r.Uint32(derIndex)
	copy(out.SourceChainID[:], r.BytesFixedSlice(derChain, 32))
	copy(out.SourceTxID[:], r.BytesFixedSlice(derTx, 32))
	copy(out.IntentID[:], r.BytesFixedSlice(derIntent, 32))
	return out
}

// =============================================================================
// IntentStatus / IntentWatchRef
// =============================================================================

// IntentPhase is the lifecycle of a notified intent as the off-chain watcher
// observes it. NONE of these phases moves value — Committed merely means the
// watcher SAW a D export object; the user still imports it on C.
type IntentPhase uint8

const (
	PhasePending   IntentPhase = 0 // notified; D has not produced a block yet
	PhaseMatching  IntentPhase = 1 // D imported the C->D object, matching in progress
	PhaseCommitted IntentPhase = 2 // D exported a D->C object (a D block committed)
	PhaseRejected  IntentPhase = 3 // D could not import/match (e.g. unbacked, expired)
	PhaseUnknown   IntentPhase = 4 // watcher has no information
)

// IntentStatus is one poll/push of a watch. When Phase==PhaseCommitted the Ref
// points at the produced D->C object. A malicious server can set Phase=Committed
// with a bogus Ref, but importSettlement of that Ref reverts on-chain (the object
// is missing or binds to a different owner/asset/amount).
//
// MatchedOut is an ESTIMATE the venue reports when D has matched (PhaseMatching/
// Committed): the orchestration "you'll receive ~N" figure the bidirectional
// MatchResult read surfaces. It is INFORMATIONAL ONLY — exactly the QuotedOut
// discipline extended to the match phase. The chain NEVER trusts it: the credit is
// the recorded D->C object's amount, bound on-chain at settlement. A lying venue can
// set MatchedOut to anything; it changes no balance (proven by the RED suite).
type IntentStatus struct {
	IntentID   ID
	Phase      IntentPhase
	Ref        DExportRef // valid only when Phase==PhaseCommitted
	Reason     string     // human-readable, for Rejected/Unknown
	MatchedOut uint64     // ESTIMATE (matched output) — orchestration only, never a credit
}

const (
	isPhase   = 0   // uint8
	isIndex   = 4   // uint32 (ref output index)
	isIntent  = 8   // bytes32 [8:40]
	isChain   = 40  // bytes32 [40:72] ref source chain
	isTx      = 72  // bytes32 [72:104] ref source tx
	isMatched = 104 // uint64 (matched-out ESTIMATE — orchestration only)
	isReason  = 112 // text (slot 8)
	isSize    = 120
)

func buildIntentStatus(s IntentStatus) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(isSize + len(s.Reason) + 160)
	ob := b.StartObject(isSize)
	ob.SetUint8(isPhase, uint8(s.Phase))
	ob.SetUint32(isIndex, s.Ref.OutputIndex)
	ob.SetBytesFixed(isIntent, s.IntentID[:])
	ob.SetBytesFixed(isChain, s.Ref.SourceChainID[:])
	ob.SetBytesFixed(isTx, s.Ref.SourceTxID[:])
	ob.SetUint64(isMatched, s.MatchedOut)
	ob.SetText(isReason, s.Reason)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgWatchPoll << 8))
}

func readIntentStatus(m *zaplib.Message) IntentStatus {
	r := m.Root()
	var s IntentStatus
	s.Phase = IntentPhase(r.Uint8(isPhase))
	copy(s.IntentID[:], r.BytesFixedSlice(isIntent, 32))
	s.Ref.OutputIndex = r.Uint32(isIndex)
	copy(s.Ref.SourceChainID[:], r.BytesFixedSlice(isChain, 32))
	copy(s.Ref.SourceTxID[:], r.BytesFixedSlice(isTx, 32))
	s.Ref.IntentID = s.IntentID
	s.MatchedOut = r.Uint64(isMatched)
	s.Reason = r.Text(isReason)
	return s
}

// IntentWatchRef is the server-side handle a notifyIntent returns: the intent id
// the watch tracks. The client polls it (MsgWatchPoll) or receives a Push
// (MsgWatchPush). It is a subscription token, not authority.
type IntentWatchRef struct {
	IntentID ID
}

const (
	iwIntent = 0 // bytes32 [0:32]
	iwSize   = 32
)

func buildIntentWatchRef(w IntentWatchRef) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(iwSize + 40)
	ob := b.StartObject(iwSize)
	ob.SetBytesFixed(iwIntent, w.IntentID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgNotify << 8))
}

func readIntentWatchRef(m *zaplib.Message) IntentWatchRef {
	r := m.Root()
	var w IntentWatchRef
	copy(w.IntentID[:], r.BytesFixedSlice(iwIntent, 32))
	return w
}

// the watch-poll request carries just the intent id (same shape as IntentWatchRef
// but tagged MsgWatchPoll).
func buildWatchPollRequest(intentID ID) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(iwSize + 40)
	ob := b.StartObject(iwSize)
	ob.SetBytesFixed(iwIntent, intentID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgWatchPoll << 8))
}

func readWatchPollRequest(m *zaplib.Message) ID {
	r := m.Root()
	var id ID
	copy(id[:], r.BytesFixedSlice(iwIntent, 32))
	return id
}

// =============================================================================
// SettlementSubmitResult — what importSettlement returns
// =============================================================================

// SettlementMode tells the caller HOW the settlement is realised. In both modes
// the credit happens ON-CHAIN by consuming the real object — never via this RPC.
type SettlementMode uint8

const (
	// SettleCalldata: the caller (a wallet / keeper) signs a C tx to 0x9999 with
	// the returned Calldata. The chain's ImportSettlement reads the real D->C
	// object and credits the recipient.
	SettleCalldata SettlementMode = 0
	// SettleSubmitted: a keeper with a (non-custodial) signing key already
	// submitted the C tx; CTxHash is the submitted tx. The keeper cannot alter
	// recipient/asset/amount — the chain binds them to the object.
	SettleSubmitted SettlementMode = 1
)

// SettlementSubmitResult is the OUTPUT of importSettlement. It NEVER credits C; it
// returns the calldata to consume the object (or the hash of a tx that points at
// it). The on-chain ImportSettlement is the sole credit path.
type SettlementSubmitResult struct {
	Mode      SettlementMode
	To        Account // 0x9999
	Calldata  []byte  // selector + SettlementClaim args, points at the object
	ObjectKey ID      // the shared-memory key the chain will read
	CTxHash   ID      // set only in SettleSubmitted mode
}

const (
	ssMode   = 0  // uint8
	ssTo     = 8  // bytes20 [8:28]
	ssObjKey = 28 // bytes32 [28:60]
	ssCTx    = 60 // bytes32 [60:92]
	ssCall   = 92 // bytes (slot 8)
	ssSize   = 100
)

func buildSettlementResult(s SettlementSubmitResult) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(ssSize + len(s.Calldata) + 120)
	ob := b.StartObject(ssSize)
	ob.SetUint8(ssMode, uint8(s.Mode))
	ob.SetBytesFixed(ssTo, s.To[:])
	ob.SetBytesFixed(ssObjKey, s.ObjectKey[:])
	ob.SetBytesFixed(ssCTx, s.CTxHash[:])
	ob.SetBytes(ssCall, s.Calldata)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgImport << 8))
}

func readSettlementResult(m *zaplib.Message) SettlementSubmitResult {
	r := m.Root()
	var s SettlementSubmitResult
	s.Mode = SettlementMode(r.Uint8(ssMode))
	copy(s.To[:], r.BytesFixedSlice(ssTo, 20))
	copy(s.ObjectKey[:], r.BytesFixedSlice(ssObjKey, 32))
	copy(s.CTxHash[:], r.BytesFixedSlice(ssCTx, 32))
	s.Calldata = append([]byte(nil), r.Bytes(ssCall)...)
	return s
}
