// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"crypto/sha256"
	"encoding/binary"
)

// v4liquidity.go reproduces the 0x9999 modifyLiquidity CALLDATA byte format and the
// route-intent path encoding, as pure functions over values — the same "three homes"
// discipline calldata.go uses for the swap selector. The precompile (luxfi/precompile/
// dex) is the authority on these encodings; dexsession reproduces them so a session
// can hand a wallet the exact bytes to sign. v4 parity tests pin every constant.
//
// WHY THESE BELONG WITH THE SWAP CALLDATA: the V4 ABI has exactly two value-moving
// kernels at 0x9999 — swap (SelectorSwap, calldata.go) and modifyLiquidity
// (SelectorModifyLiquidity, here). The 0x9996 position facade (mint/increase/
// decrease/collect/burn/placeLimit/cancelLimit) ALL route into 0x9999
// modifyLiquidity (+delta to add/commit, -delta to remove/collect/cancel), so the
// liquidity/collect/cancel sessions build modifyLiquidity calldata directly and let
// the ONE kernel hold custody. The CREDIT side of any remove (collect/decrease/
// cancel) is the SAME DS01 Phase-B settlement as a swap (calldata.go), because every
// D->C export — swap output, collected fees, withdrawn liquidity, cancelled-order
// refund — is consumed by the one settlement path. There is exactly ONE credit path.
//
// These are VALUES, not authority: emitting calldata reserves nothing and credits
// nothing; only the user signing it and the chain consuming the resulting atomic
// object move value.

// SelectorModifyLiquidity is the V4 modifyLiquidity selector — IDENTICAL to
// precompile/dex/module.go SelectorModifyLiquidity (0x5A6BCFDA):
//
//	modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)
//
// The ModifyLiquidityParams tuple is (tickLower int24, tickUpper int24, liquidityDelta
// int256, salt bytes32). A POSITIVE liquidityDelta adds (commit C->D funds); a
// NEGATIVE delta removes (collect/decrease/cancel -> D->C export -> DS01 credit).
const SelectorModifyLiquidity uint32 = 0x5A6BCFDA

// ModifyLiquidityArgs are the V4 ModifyLiquidityParams tuple fields. LiquidityDelta
// is signed: >0 add, <0 remove. The session sets the sign per action (commit vs
// collect/cancel); the SIGN is what distinguishes a funding C->D commit from a
// value-returning D->C removal — both ride this one selector, exactly as the
// position facade does.
type ModifyLiquidityArgs struct {
	TickLower      int32 // int24
	TickUpper      int32 // int24
	LiquidityDelta int64 // int256 (we carry the int64 magnitude+sign; ABI sign-extends)
	Salt           ID    // bytes32 position salt
}

// EncodeModifyLiquidityCalldata builds the full 0x9999 modifyLiquidity calldata:
//
//	selector(4) || PoolKey(5 words) || ModifyParams(4 words: tickLower, tickUpper,
//	liquidityDelta, salt) || offset(1 word) || hookData(length word + padded bytes)
//
// Standard Solidity ABI encoding of the modifyLiquidity signature. The dynamic
// `bytes hookData` is tail-encoded with a head offset word. hookData selects the
// phase exactly as for swap: empty / DI01 for the commit intent, DS01 for settling a
// removal's D->C export (though a removal's settlement is built via the swap-shaped
// EncodeSwapCalldata + DS01, since the credit kernel is the swap path — see
// v4session.go collect/cancel).
func EncodeModifyLiquidityCalldata(pk PoolKeyArgs, args ModifyLiquidityArgs, hookData []byte) []byte {
	// Head: selector + 5 PoolKey words + 4 ModifyParams words + 1 hookData offset
	// word = 4 + 10*32. Tail: hookData length word + padded data.
	const headWords = 5 + 4 + 1
	head := make([]byte, 4+headWords*32)
	binary.BigEndian.PutUint32(head[0:4], SelectorModifyLiquidity)
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
	// ModifyLiquidityParams tuple (inline — fixed-size members).
	put(wordI24(args.TickLower))
	put(wordI24(args.TickUpper))
	put(wordI256FromInt64(args.LiquidityDelta)) // signed: +add / -remove
	put(abiWord(args.Salt))
	// hookData dynamic offset: bytes start right after the 10 head words.
	put(wordU256FromU64(uint64(headWords * 32)))

	tail := encodeDynamicBytes(hookData)
	return append(head, tail...)
}

// wordI256FromInt64 encodes a signed int64 into a two's-complement int256 ABI word
// (sign-extended to 32 bytes). Used for the signed liquidityDelta.
func wordI256FromInt64(v int64) abiWord {
	var w abiWord
	u := uint64(v)
	binary.BigEndian.PutUint64(w[24:32], u)
	if v < 0 {
		for i := 0; i < 24; i++ {
			w[i] = 0xff
		}
	}
	return w
}

// ----------------------------------------------------------------------------
// Route-intent path encoding.
// ----------------------------------------------------------------------------
//
// A V4 route is a SWAP INTENT (DI01 / Phase A) whose hookData body carries the
// multi-market PATH the D-Chain router walks. The V4 hookData is DESIGNED to carry a
// routing payload, and the precompile's decodeSwapPhase returns the bytes after the
// DI01 tag as the phase body — so a route rides the EXISTING swap selector and the
// EXISTING intent phase, with the path as the body. No new on-chain selector or tag
// is invented: to the C-side lock, a route intent is a plain intent that creates ONE
// C->D input object; the D-Chain router reads the path body to walk A->B->C and
// produces ONE final D->C export.
//
// This is the structural reason multi-hop "stays on D": there is ONE C->D object
// (the input) and ONE D->C object (the final output / refund). Intermediate hops are
// D-internal matching state; they never create a C-side object, so the money plane
// sees exactly 1-in / 1-out regardless of hop count.

// routePathDomain tags the route-path body inside a DI01 intent hookData. It follows
// the DI01 tag so the precompile still classifies the hookData as a Phase-A intent
// (the tag is DI01); the route marker + path are the intent BODY the D router reads.
var routePathMarker = [4]byte{'R', 'T', '0', '1'}

// EncodeRouteIntentHookData builds a route-intent hookData: the DI01 intent tag,
// then a route marker, then the path (an ordered list of marketIDs A->B->C the D
// router walks). The leading DI01 keeps the on-chain phase classification as INTENT
// (creates ONE C->D object); the body is the path for D's router.
//
//	DI01(4) || RT01(4) || hopCount(4, big-endian) || marketID[0](32) || ... || marketID[n-1](32)
//
// The body is the ROUTING PAYLOAD — orchestration the D matcher consumes. It moves no
// value; it only directs how D walks the single input through markets to one output.
func EncodeRouteIntentHookData(path []ID) []byte {
	out := make([]byte, 0, 4+4+4+len(path)*32)
	out = append(out, intentPhaseTag[:]...)  // DI01: Phase-A intent classification
	out = append(out, routePathMarker[:]...) // RT01: route body marker
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], uint32(len(path)))
	out = append(out, c[:]...)
	for _, m := range path {
		out = append(out, m[:]...)
	}
	return out
}

// DecodeRouteIntentHookData is the inverse: it extracts the route path from a
// route-intent hookData, or ok=false if the bytes are not a DI01+RT01 route body.
// The D router uses this to recover the path; the session uses it to verify the
// calldata it built carries exactly the requested path (defence against a corrupted
// build). It reads only — it moves nothing.
func DecodeRouteIntentHookData(hookData []byte) (path []ID, ok bool) {
	const hdr = 4 + 4 + 4
	if len(hookData) < hdr {
		return nil, false
	}
	if string(hookData[0:4]) != string(intentPhaseTag[:]) {
		return nil, false
	}
	if string(hookData[4:8]) != string(routePathMarker[:]) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint32(hookData[8:12]))
	if n < 0 || hdr+n*32 != len(hookData) {
		return nil, false
	}
	path = make([]ID, n)
	for i := 0; i < n; i++ {
		copy(path[i][:], hookData[hdr+i*32:hdr+(i+1)*32])
	}
	return path, true
}

// DeriveRoutePathHash hashes a route path (the ordered marketID list) into a scope
// PoolKeyHash. Two routes with different paths derive different session ids, so a
// route capability is confined to its exact path.
func DeriveRoutePathHash(path []ID) ID {
	h := sha256.New()
	h.Write([]byte("lux.dex.v4.routepath.v1"))
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], uint32(len(path)))
	h.Write(c[:])
	for _, m := range path {
		h.Write(m[:])
	}
	var out ID
	copy(out[:], h.Sum(nil))
	return out
}
