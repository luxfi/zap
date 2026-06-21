// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"crypto/sha256"
	"encoding/binary"

	zaplib "github.com/luxfi/zap"
)

// wire.go is the typed request/response contract for the DexSession capability
// transport, plus the VALUE-boundary primitives reproduced as pure values.
//
// VALUES, NOT PLACES: this package speaks in [20]byte accounts, [32]byte ids,
// and uint64 amounts — never luxfi/geth common.Address or luxfi/ids ids.ID. The
// EVM type mapping is the precompile caller's concern. Keeping dexsession on
// primitives means the transport module pulls in no EVM / blockchain dep graph,
// and the orchestration layer literally cannot reference a StateDB or an atomic
// shared-memory handle (the structural half of the invariant — see doc.go).
//
// On-wire bytes are github.com/luxfi/zap Objects (the same zero-copy frame the
// forward/ HTTP contract uses). Every field sits at an explicit byte offset; a
// text/bytes slot is 8 bytes (relOffset+length), scalars are natural width.

// Account is a 20-byte EVM account (taker / recipient / owner). Byte-identical
// to the low 20 bytes of an EVM address; the precompile binds it as the atomic
// object owner.
type Account [20]byte

// ID is a 32-byte identifier (chain id, tx id, market id, intent id, asset id).
// Byte-identical to luxfi/ids ids.ID and to an EVM bytes32. Native asset == the
// all-zero ID (mirrors ids.Empty in the dexvm ledger).
type ID [32]byte

// ZeroID is the all-zero ID — native asset / empty sentinel.
var ZeroID = ID{}

// --- Message types -----------------------------------------------------------
//
// The ZAP dispatcher routes on msg.Flags()>>8 (FinishWithFlags(t<<8)), so a type
// must fit the upper byte (uint8). The 0xA0+ range avoids collision with
// forward's 0x80/0x81 and base/plugins' lower-byte IDs.
const (
	MsgQuote      uint16 = 0xA0 // QuoteRequest  -> QuoteResult
	MsgGetState   uint16 = 0xA1 // StateRequest  -> StateResult
	MsgPrepare    uint16 = 0xA2 // SwapIntentRequest -> PreparedIntent
	MsgNotify     uint16 = 0xA3 // PreparedIntent -> IntentWatchRef
	MsgWatchPoll  uint16 = 0xA4 // IntentWatchRef -> IntentStatus
	MsgImport     uint16 = 0xA5 // DExportRef -> SettlementSubmitResult
	MsgPipeline   uint16 = 0xA6 // PipelineBatch -> PipelineResult
	MsgAdminHalt  uint16 = 0xA7 // AdminRequest -> AdminStatus
	MsgWatchPush  uint16 = 0xA8 // server-initiated watch resolution (Push)
	MsgRoutePrepare uint16 = 0xA9 // RouteRequest -> PreparedIntent (route-intent calldata)
	MsgRouteStatus  uint16 = 0xAA // RouteWatchRef -> RouteStatus (hop progress + final ref)
)

// --- Value-boundary primitives (reproduced as values; pinned by parity test) -

// exportedObjectSize is the fixed cross-chain atomic object width:
// owner(20) | asset(32) | amount(8) = 60 bytes. IDENTICAL to
// precompile/dex/native_wire.go exportedOutputSize9999 and
// chains/dexvm/atomic.go exportedOutputSize. wire_parity_test.go pins it.
const exportedObjectSize = 20 + 32 + 8

// EncodeAtomicObject serializes a cross-chain value object as the shared-memory
// value: owner(20) | asset(32) | amount(8). Byte-identical with the precompile
// and dexvm encoders. This is the ONLY value-bearing identity the atomic
// conservation binds; dexsession reproduces the encoding so a watcher can derive
// the object key it points at — it NEVER writes one into shared memory (it has
// no shared memory).
func EncodeAtomicObject(owner Account, asset ID, amount uint64) []byte {
	v := make([]byte, exportedObjectSize)
	copy(v[0:20], owner[:])
	copy(v[20:52], asset[:])
	binary.BigEndian.PutUint64(v[52:60], amount)
	return v
}

// DecodeAtomicObject is the inverse. ok=false for any value that is not exactly
// the canonical width, so a corrupt record is never reinterpreted — the same
// defence the precompile and dexvm decoders apply. A consumer binds the credited
// owner/asset/amount to THIS recorded value, never to a declared claim.
func DecodeAtomicObject(v []byte) (owner Account, asset ID, amount uint64, ok bool) {
	if len(v) != exportedObjectSize {
		return Account{}, ID{}, 0, false
	}
	copy(owner[:], v[0:20])
	copy(asset[:], v[20:52])
	amount = binary.BigEndian.Uint64(v[52:60])
	return owner, asset, amount, true
}

// nativeIntentDomain scopes the intent-id derivation. IDENTICAL string to
// precompile/dex/native_wire.go nativeIntentDomain — the id dexsession derives
// for a PreparedIntent MUST equal the id the precompile derives for the same
// inputs, or the off-chain pointer would name a different object than the chain.
const nativeIntentDomain = "lux.dex.native.intent.v1"

// DeriveIntentID computes the deterministic id of a C->D atomic intent object,
// byte-identical to precompile/dex/native_wire.go DeriveIntentID:
//
//	SHA-256( domain | networkID | cChainID | dChainID | txID | callIndex |
//	         account | assetIn | amountIn | marketID )
//
// Every component is fixed width and length-stable. dexsession derives it so a
// PreparedIntent can carry the id the user's signed C tx will mint and the watch
// can locate the matching D result — it is a NAME, never an authority.
func DeriveIntentID(
	networkID uint32,
	cChainID, dChainID ID,
	txID ID,
	callIndex uint32,
	account Account,
	assetIn ID,
	amountIn uint64,
	marketID ID,
) ID {
	h := sha256.New()
	h.Write([]byte(nativeIntentDomain))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], networkID)
	h.Write(u4[:])
	h.Write(cChainID[:])
	h.Write(dChainID[:])
	h.Write(txID[:])
	binary.BigEndian.PutUint32(u4[:], callIndex)
	h.Write(u4[:])
	h.Write(account[:])
	h.Write(assetIn[:])
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], amountIn)
	h.Write(u8[:])
	h.Write(marketID[:])
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}

// DeriveUTXOID computes the deterministic D->C export object key from
// (sourceTxID, outputIndex), byte-identical to chains/dexvm/atomic.go
// deriveUTXOID (SHA-256 over txID||index). importSettlement uses it to name the
// object the on-chain ImportSettlement will read; the chain re-derives and binds
// it, so a wrong index just names a non-existent (or someone else's) object and
// the on-chain bind rejects.
func DeriveUTXOID(sourceTxID ID, outputIndex uint32) ID {
	var buf [36]byte
	copy(buf[0:32], sourceTxID[:])
	binary.BigEndian.PutUint32(buf[32:36], outputIndex)
	sum := sha256.Sum256(buf[:])
	return ID(sum)
}

// =============================================================================
// QuoteRequest / QuoteResult  (read-only — estimate, never an enforceable price)
// =============================================================================

// QuoteRequest asks the D book for an estimated output. Read-only.
type QuoteRequest struct {
	MarketID   ID
	AmountIn   uint64
	ZeroForOne bool // sell currency0 for currency1
}

// QuoteResult is an ESTIMATE. AmountOut is informational only: the chain never
// trusts it. The user still encodes their own MinAmountOut in the signed C tx,
// and D enforces slippage at match. A stale or malicious quote can only mislead
// a UI — it cannot move value, and a bad quote that misses MinAmountOut makes
// the on-chain swap revert (TestZAP_StaleResponse_BadQuoteMissesMinOutOrReverts).
type QuoteResult struct {
	MarketID    ID
	AmountIn    uint64
	AmountOut   uint64 // ESTIMATE ONLY — not enforceable, not a credit
	BestPricePx uint64 // top-of-book price, IEEE-754 bits (informational)
	Liquid      bool   // false = no resting book / market unknown
}

// Fixed inline byte arrays (SetBytesFixed) consume their FULL width; scalars use
// natural width; only variable bytes/text (SetBytes/SetText) consume an 8-byte
// {relOffset,length} slot. Offsets below are packed accordingly and must not
// overlap. (Mismatching a bytes32 to an 8-byte slot silently clobbers adjacent
// fields — the layout bug the test suite pins against.)
const (
	qReqMarket  = 0  // bytes32 [0:32]
	qReqAmount  = 32 // uint64
	qReqZForOne = 40 // bool
	qReqSize    = 48
)

func buildQuoteRequest(r QuoteRequest) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(qReqSize + 40)
	ob := b.StartObject(qReqSize)
	ob.SetBytesFixed(qReqMarket, r.MarketID[:])
	ob.SetUint64(qReqAmount, r.AmountIn)
	ob.SetBool(qReqZForOne, r.ZeroForOne)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgQuote << 8))
}

func readQuoteRequest(m *zaplib.Message) QuoteRequest {
	r := m.Root()
	var out QuoteRequest
	copy(out.MarketID[:], r.BytesFixedSlice(qReqMarket, 32))
	out.AmountIn = r.Uint64(qReqAmount)
	out.ZeroForOne = r.Bool(qReqZForOne)
	return out
}

const (
	qResMarket = 0  // bytes32 [0:32]
	qResIn     = 32 // uint64
	qResOut    = 40 // uint64
	qResPrice  = 48 // uint64 (float bits)
	qResLiquid = 56 // bool
	qResSize   = 64
)

func buildQuoteResult(r QuoteResult) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(qResSize + 40)
	ob := b.StartObject(qResSize)
	ob.SetBytesFixed(qResMarket, r.MarketID[:])
	ob.SetUint64(qResIn, r.AmountIn)
	ob.SetUint64(qResOut, r.AmountOut)
	ob.SetUint64(qResPrice, r.BestPricePx)
	ob.SetBool(qResLiquid, r.Liquid)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgQuote << 8))
}

func readQuoteResult(m *zaplib.Message) QuoteResult {
	r := m.Root()
	var out QuoteResult
	copy(out.MarketID[:], r.BytesFixedSlice(qResMarket, 32))
	out.AmountIn = r.Uint64(qResIn)
	out.AmountOut = r.Uint64(qResOut)
	out.BestPricePx = r.Uint64(qResPrice)
	out.Liquid = r.Bool(qResLiquid)
	return out
}

// =============================================================================
// StateRequest / StateResult  (read-only — observe C/D DEX state)
// =============================================================================

// StateKind selects which read-only view getState returns.
type StateKind uint8

const (
	StateMarket   StateKind = 0 // market existence / base+quote asset ids
	StateBalance  StateKind = 1 // an account's D available balance for an asset
	StateIntent   StateKind = 2 // a C->D intent's known routing status (off-chain view)
)

// StateRequest is a read-only DEX state query.
type StateRequest struct {
	Kind    StateKind
	MarketID ID
	Account Account
	Asset   ID
	IntentID ID
}

// StateResult is the read-only answer. Like a quote it is informational: a
// balance reported here is NOT a spendable claim the chain honours — only a
// consumed D->C object credits C.
type StateResult struct {
	Kind      StateKind
	Exists    bool
	BaseID    ID
	QuoteID   ID
	Available uint64 // D available balance (observation only)
	Known     bool   // intent known to the venue's router index
}

const (
	sReqKind    = 0   // uint8
	sReqMarket  = 8   // bytes32 [8:40]
	sReqAccount = 40  // bytes20 [40:60]
	sReqAsset   = 60  // bytes32 [60:92]
	sReqIntent  = 92  // bytes32 [92:124]
	sReqSize    = 124
)

func buildStateRequest(r StateRequest) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(sReqSize + 128)
	ob := b.StartObject(sReqSize)
	ob.SetUint8(sReqKind, uint8(r.Kind))
	ob.SetBytesFixed(sReqMarket, r.MarketID[:])
	ob.SetBytesFixed(sReqAccount, r.Account[:])
	ob.SetBytesFixed(sReqAsset, r.Asset[:])
	ob.SetBytesFixed(sReqIntent, r.IntentID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgGetState << 8))
}

func readStateRequest(m *zaplib.Message) StateRequest {
	r := m.Root()
	var out StateRequest
	out.Kind = StateKind(r.Uint8(sReqKind))
	copy(out.MarketID[:], r.BytesFixedSlice(sReqMarket, 32))
	copy(out.Account[:], r.BytesFixedSlice(sReqAccount, 20))
	copy(out.Asset[:], r.BytesFixedSlice(sReqAsset, 32))
	copy(out.IntentID[:], r.BytesFixedSlice(sReqIntent, 32))
	return out
}

const (
	sResKind   = 0  // uint8
	sResExists = 1  // bool
	sResKnown  = 2  // bool
	sResAvail  = 8  // uint64
	sResBase   = 16 // bytes32 [16:48]
	sResQuote  = 48 // bytes32 [48:80]
	sResSize   = 80
)

func buildStateResult(r StateResult) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(sResSize + 80)
	ob := b.StartObject(sResSize)
	ob.SetUint8(sResKind, uint8(r.Kind))
	ob.SetBool(sResExists, r.Exists)
	ob.SetBool(sResKnown, r.Known)
	ob.SetUint64(sResAvail, r.Available)
	ob.SetBytesFixed(sResBase, r.BaseID[:])
	ob.SetBytesFixed(sResQuote, r.QuoteID[:])
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgGetState << 8))
}

func readStateResult(m *zaplib.Message) StateResult {
	r := m.Root()
	var out StateResult
	out.Kind = StateKind(r.Uint8(sResKind))
	out.Exists = r.Bool(sResExists)
	out.Known = r.Bool(sResKnown)
	out.Available = r.Uint64(sResAvail)
	copy(out.BaseID[:], r.BytesFixedSlice(sResBase, 32))
	copy(out.QuoteID[:], r.BytesFixedSlice(sResQuote, 32))
	return out
}
