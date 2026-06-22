// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"encoding/binary"
)

// calldata.go reproduces the 0x9999 CALLDATA byte format the precompile owns, as
// pure functions over values. The precompile (luxfi/precompile/dex) is the
// authority on this encoding; dexsession reproduces it so prepareSwapIntent /
// importSettlement can hand a wallet the exact bytes to sign. calldata_parity_test
// pins every constant against a hardcoded vector so a precompile-side change that
// drifts the format trips a red test here.
//
// WHY REPRODUCE INSTEAD OF IMPORT: importing precompile/dex would drag the EVM +
// geth + (broken) cgo dependency graph into the transport module AND give
// dexsession a compile edge to the C Verify path — both forbidden. The format is a
// small, frozen byte layout (a selector + two ABI tuples + a tagged hookData); the
// "three homes" pattern (already used for the CLOB frames) reproduces it and pins
// it. These are VALUES, not authority — emitting calldata reserves nothing and
// credits nothing; only the user signing it and the chain consuming the resulting
// atomic object move value.

// SelectorSwap is the V4 swap selector — IDENTICAL to
// precompile/dex/module.go SelectorSwap (0xF3CD914C):
//
//	swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)
//
// Both Phase A (intent) and Phase B (settlement) ride this one selector; the
// hookData CONTENTS select the phase (the V4 ABI is unchanged).
const SelectorSwap uint32 = 0xF3CD914C

// Phase tags inside hookData — IDENTICAL to precompile/dex/settle_hookdata.go.
//
//	empty hookData       -> PHASE A (intent), the common case.
//	"DI01"               -> PHASE A (intent), explicit.
//	"DS01" + body        -> PHASE B (settlement), consume a D->C object.
var (
	intentPhaseTag     = [4]byte{'D', 'I', '0', '1'}
	settlementPhaseTag = [4]byte{'D', 'S', '0', '1'}
)

// settlementBodyLen is the fixed Phase-B body width: outputID(32) | amount(32) |
// intentID(32). IDENTICAL to precompile/dex/settle_hookdata.go settlementBodyLen. The
// intentID word binds the credit to the taker's OWN intent record on-chain (the per-taker
// cap + the deadline gate); omitting it makes the body 64 bytes, which the precompile's
// decodeSettlementBody REJECTS (len != 96 -> ErrSettleBodyMalformed) and the settle tx
// REVERTS. The three-homes parity test (calldata_parity_test) pins this width against a
// hardcoded vector so a one-sided drift trips a red test before any wallet signs bad bytes.
const settlementBodyLen = 32 + 32 + 32

// EncodeIntentHookData builds an explicit Phase-A hookData carrying the deadline and the
// intent NONCE. BYTE-IDENTICAL to precompile/dex EncodeIntentHookData — both sides MUST
// produce the same calldata for the same (deadline, nonce) or the off-chain-derived
// intent id would diverge from the on-chain one (the watch-correlation contract). The
// encoding is MINIMAL-WIDTH (the precompile decodes all three widths):
//   - deadline==0 && nonce==0 -> tag only (4 bytes)
//   - nonce==0                -> tag | deadline[32]
//   - else                    -> tag | deadline[32] | nonce[32]
func EncodeIntentHookData(deadline, nonce uint64) []byte {
	if deadline == 0 && nonce == 0 {
		out := make([]byte, 4)
		copy(out, intentPhaseTag[:])
		return out
	}
	var d [32]byte
	binary.BigEndian.PutUint64(d[24:32], deadline)
	if nonce == 0 {
		out := make([]byte, 0, 4+32)
		out = append(out, intentPhaseTag[:]...)
		out = append(out, d[:]...)
		return out
	}
	var n [32]byte
	binary.BigEndian.PutUint64(n[24:32], nonce)
	out := make([]byte, 0, 4+64)
	out = append(out, intentPhaseTag[:]...)
	out = append(out, d[:]...)
	out = append(out, n[:]...)
	return out
}

// EncodeSettlementHookData builds a Phase-B hookData: tag + outputID + amount + intentID.
// Byte-identical to precompile/dex EncodeSettlementHookData (the INVERSE of its
// decodeSettlementBody). amount is right-aligned in a uint256 word (the low 8 bytes),
// matching the precompile's binary.BigEndian.PutUint64(amt[24:32], amount). intentID names
// the originating C->D intent the settlement draws against — the precompile binds the credit
// to that taker's intent record (the per-taker cap + the deadline gate), so it is REQUIRED;
// a body without it is the wrong width and the on-chain decode reverts.
//
// CRITICAL: the body carries outputID + amount + intentID, but NOT the output ASSET or the
// RECIPIENT — on-chain the asset is derived from the swap direction and the recipient is the
// CALLER. So this calldata cannot name a victim's recipient or a re-denominated asset;
// ImportSettlement binds outputID/amount/intentID against the RECORDED object + the recorded
// owner's intent. (This is why a tampered DExportRef cannot substitute recipient/asset/amount
// — see the package invariant.)
func EncodeSettlementHookData(outputID ID, amount uint64, intentID ID) []byte {
	out := make([]byte, 0, 4+settlementBodyLen)
	out = append(out, settlementPhaseTag[:]...)
	out = append(out, outputID[:]...)
	var amt [32]byte
	binary.BigEndian.PutUint64(amt[24:32], amount)
	out = append(out, amt[:]...)
	out = append(out, intentID[:]...)
	return out
}

// abiWord is one 32-byte ABI word.
type abiWord [32]byte

// wordAddr right-aligns a 20-byte account into an ABI address word.
func wordAddr(a Account) abiWord {
	var w abiWord
	copy(w[12:32], a[:])
	return w
}

// wordU24 right-aligns a uint24 (lpFee) into an ABI word.
func wordU24(v uint32) abiWord {
	var w abiWord
	w[29] = byte(v >> 16)
	w[30] = byte(v >> 8)
	w[31] = byte(v)
	return w
}

// wordI24 two's-complement encodes an int24 (tickSpacing) into an ABI word
// (sign-extended to 32 bytes).
func wordI24(v int32) abiWord {
	var w abiWord
	u := uint64(int64(v))
	for i := 0; i < 8; i++ {
		w[31-i] = byte(u >> (8 * i))
	}
	if v < 0 {
		for i := 8; i < 32; i++ {
			w[31-i] = 0xff
		}
	}
	return w
}

// wordBool encodes a bool into an ABI word.
func wordBool(b bool) abiWord {
	var w abiWord
	if b {
		w[31] = 1
	}
	return w
}

// wordI256FromInt encodes a signed int256 from an int64 (amountSpecified). The V4
// convention: amountSpecified < 0 = exact input. A swap intent locks AmountIn of
// the input, so the prepared calldata encodes -AmountIn (exact input).
func wordI256FromNegU64(v uint64) abiWord {
	var w abiWord
	// -v in two's complement over 256 bits.
	neg := new256Neg(v)
	copy(w[:], neg[:])
	return w
}

// new256Neg returns the 32-byte big-endian two's-complement of -v for v>0.
func new256Neg(v uint64) [32]byte {
	var w [32]byte
	// Start with v big-endian in the low 8 bytes, then negate the whole 256-bit.
	binary.BigEndian.PutUint64(w[24:32], v)
	// two's complement: invert all, add 1.
	var carry uint16 = 1
	for i := 31; i >= 0; i-- {
		s := uint16(^w[i]) + carry
		w[i] = byte(s)
		carry = s >> 8
	}
	return w
}

// wordU160 right-aligns a uint160 sqrtPriceLimit into an ABI word. The native
// seam ignores the price limit for matching (D enforces slippage via MinAmountOut
// in the routing event), so prepared calldata passes 0 (no on-chain limit) and the
// enforceable floor rides MinAmountOut. Kept as a helper for completeness.
func wordU160Zero() abiWord { return abiWord{} }

// PoolKeyArgs are the V4 PoolKey tuple fields the swap selector takes:
// (currency0, currency1, fee uint24, tickSpacing int24, hooks address). For the
// native seam the pool is identified by these; the keeper/market binds them to a
// D market. dexsession fills them from the request's market mapping.
type PoolKeyArgs struct {
	Currency0   Account
	Currency1   Account
	Fee         uint32 // uint24
	TickSpacing int32  // int24
	Hooks       Account
}

// EncodeSwapCalldata builds the full 0x9999 swap calldata:
//
//	selector(4) || PoolKey(5 words) || SwapParams(3 words) || offset(1 word) ||
//	hookData(length word + padded bytes)
//
// This is the standard Solidity ABI encoding of
// swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes). The
// dynamic `bytes hookData` is tail-encoded with a head offset word.
//
// zeroForOne + amountSpecified come from the request; amountSpecified is encoded
// as -AmountIn (exact input). The hookData selects the phase: pass
// EncodeIntentHookData()/empty for Phase A, EncodeSettlementHookData(...) for
// Phase B.
func EncodeSwapCalldata(pk PoolKeyArgs, zeroForOne bool, amountIn uint64, hookData []byte) []byte {
	// Head: selector + 5 PoolKey words + 3 SwapParams words + 1 hookData offset
	// word = 4 + 9*32. Tail: hookData length word + padded data.
	const headWords = 5 + 3 + 1
	head := make([]byte, 4+headWords*32)
	binary.BigEndian.PutUint32(head[0:4], SelectorSwap)
	off := 4
	put := func(w abiWord) {
		copy(head[off:off+32], w[:])
		off += 32
	}
	// PoolKey tuple (inline — fixed-size members).
	put(wordAddr(pk.Currency0))
	put(wordAddr(pk.Currency1))
	put(wordU24(pk.Fee))
	put(wordI24(pk.TickSpacing))
	put(wordAddr(pk.Hooks))
	// SwapParams tuple (inline — fixed-size members).
	put(wordBool(zeroForOne))
	put(wordI256FromNegU64(amountIn)) // exact input = -amountIn
	put(wordU160Zero())               // sqrtPriceLimit: 0 (no on-chain limit)
	// hookData dynamic offset: bytes start right after the head (offset measured
	// from the first argument word, i.e. after the selector). The 9 head words are
	// the args; the dynamic tail begins at 9*32.
	put(wordU256FromU64(uint64(headWords * 32)))

	// Tail: length word + right-padded data to a 32-byte boundary.
	tail := encodeDynamicBytes(hookData)
	return append(head, tail...)
}

// wordU256FromU64 right-aligns a uint64 into an ABI word.
func wordU256FromU64(v uint64) abiWord {
	var w abiWord
	binary.BigEndian.PutUint64(w[24:32], v)
	return w
}

// encodeDynamicBytes ABI-encodes a `bytes` value: a 32-byte length word followed
// by the bytes right-padded to a 32-byte multiple.
func encodeDynamicBytes(b []byte) []byte {
	padded := (len(b) + 31) / 32 * 32
	out := make([]byte, 32+padded)
	binary.BigEndian.PutUint64(out[24:32], uint64(len(b)))
	copy(out[32:], b)
	return out
}
