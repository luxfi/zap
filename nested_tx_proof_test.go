// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// nested_tx_proof_test.go — DECOMPLECT PROOF: an X-chain 2-in/2-out money-move
// tx built as ONE native-nested ZAP object (SetObject + AddObjectPtr object
// lists + an inline uint16 fx-discriminator field), vs the byte-blob envelope
// pattern it replaces. fx polymorphism is preserved by the discriminator FIELD,
// so a mixed output list (secp256k1 / mldsa / nft) still self-dispatches — with
// zero per-subobject buffers, zero envelope-prefix make+copy, zero concat.
//
// This is the reference design for dropping utxo/wire's byte-blob envelopes.
package zap

import (
	"bytes"
	"testing"
)

// fx discriminators (would be the wire.TypeKind today, now an inline field).
const fxSecp256k1 uint16 = 0x90

// output object layout: {fxKind u16 @0, amount u64 @8, assetID 32B @16, addr 20B @48}
const (
	oFxKind = 0
	oAmount = 8
	oAsset  = 16
	oAddr   = 48
	oSize   = 68
)

// input object: {fxKind u16 @0, amount u64 @8, txID 32B @16, outIdx u32 @48, assetID 32B @52}
const (
	iFxKind  = 0
	iAmount  = 8
	iTxID    = 16
	iOutIdx  = 48
	iAsset   = 52
	iSize    = 84
)

// root XVMBaseTx: {networkID u32 @0, blockchainID 32B @8, outs list @40, ins list @48, memo bytes @56}
const (
	rNetwork = 0
	rChain   = 8
	rOuts    = 40
	rIns     = 48
	rMemo    = 56
	rSize    = 64
)

type outVal struct {
	amount uint64
	asset  [32]byte
	addr   [20]byte
}
type inVal struct {
	amount uint64
	txID   [32]byte
	outIdx uint32
	asset  [32]byte
}

// buildNestedXVMBaseTx builds the whole tx in ONE buffer, one Finish, native
// nesting only. Returns bytes aliasing the (pooled) builder buffer.
func buildNestedXVMBaseTx(b *Builder, networkID uint32, chain [32]byte, outs []outVal, ins []inVal, memo []byte) []byte {
	// 1. tail each output/input object; collect absolute offsets.
	outOffs := make([]int, len(outs))
	for i, o := range outs {
		ob := b.StartObject(oSize)
		ob.SetUint16(oFxKind, fxSecp256k1)
		ob.SetUint64(oAmount, o.amount)
		ob.SetBytesFixed(oAsset, o.asset[:])
		ob.SetBytesFixed(oAddr, o.addr[:])
		outOffs[i] = ob.Finish()
	}
	inOffs := make([]int, len(ins))
	for i, in := range ins {
		ob := b.StartObject(iSize)
		ob.SetUint16(iFxKind, fxSecp256k1)
		ob.SetUint64(iAmount, in.amount)
		ob.SetBytesFixed(iTxID, in.txID[:])
		ob.SetUint32(iOutIdx, in.outIdx)
		ob.SetBytesFixed(iAsset, in.asset[:])
		inOffs[i] = ob.Finish()
	}
	// 2. object-ptr lists over those offsets.
	ol := b.StartList(4)
	for _, off := range outOffs {
		ol.AddObjectPtr(off)
	}
	outsOff, outsLen := ol.Finish()
	il := b.StartList(4)
	for _, off := range inOffs {
		il.AddObjectPtr(off)
	}
	insOff, insLen := il.Finish()
	// 3. root object.
	ob := b.StartObject(rSize)
	ob.SetUint32(rNetwork, networkID)
	ob.SetBytesFixed(rChain, chain[:])
	ob.SetList(rOuts, outsOff, outsLen)
	ob.SetList(rIns, insOff, insLen)
	ob.SetBytes(rMemo, memo)
	ob.FinishAsRoot()
	return b.Finish()
}

// parseNestedXVMBaseTx reads it back — zero-copy navigation, dispatch on the
// inline fx discriminator.
func parseNestedXVMBaseTx(data []byte) (uint32, []outVal, []inVal, error) {
	msg, err := Parse(data)
	if err != nil {
		return 0, nil, nil, err
	}
	r := msg.Root()
	networkID := r.Uint32(rNetwork)
	ol := r.List(rOuts)
	outs := make([]outVal, ol.Len())
	for i := range outs {
		o := ol.ObjectPtr(i)
		if o.Uint16(oFxKind) != fxSecp256k1 {
			return 0, nil, nil, errUnknownFx
		}
		outs[i].amount = o.Uint64(oAmount)
		copy(outs[i].asset[:], o.BytesFixedSlice(oAsset, 32))
		copy(outs[i].addr[:], o.BytesFixedSlice(oAddr, 20))
	}
	il := r.List(rIns)
	ins := make([]inVal, il.Len())
	for i := range ins {
		o := il.ObjectPtr(i)
		ins[i].amount = o.Uint64(iAmount)
		copy(ins[i].txID[:], o.BytesFixedSlice(iTxID, 32))
		ins[i].outIdx = o.Uint32(iOutIdx)
		copy(ins[i].asset[:], o.BytesFixedSlice(iAsset, 32))
	}
	return networkID, outs, ins, nil
}

var errUnknownFx = &fxErr{}

type fxErr struct{}

func (*fxErr) Error() string { return "unknown fx discriminator" }

func sampleTx() (uint32, [32]byte, []outVal, []inVal) {
	asset := [32]byte{0x51, 0xc2, 0x4f, 0xe7}
	txID := [32]byte{0xaa, 0xbb}
	addr := [20]byte{0x01, 0x02, 0x03}
	outs := []outVal{{1_000_000, asset, addr}, {1_000_001, asset, addr}}
	ins := []inVal{{2_000_000, txID, 0, asset}, {2_000_001, txID, 1, asset}}
	return 1, [32]byte{0x01}, outs, ins
}

func TestNested_RoundTrip(t *testing.T) {
	net, chain, outs, ins := sampleTx()
	raw := append([]byte(nil), buildNestedXVMBaseTx(NewBuilder(512), net, chain, outs, ins, nil)...)

	// canonical: parses with exact size, no trailing slack.
	msg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Size() != len(raw) {
		t.Fatalf("size %d != len %d", msg.Size(), len(raw))
	}
	gotNet, gotOuts, gotIns, err := parseNestedXVMBaseTx(raw)
	if err != nil {
		t.Fatal(err)
	}
	if gotNet != net {
		t.Fatalf("net %d != %d", gotNet, net)
	}
	if len(gotOuts) != len(outs) || len(gotIns) != len(ins) {
		t.Fatalf("counts: %d/%d outs, %d/%d ins", len(gotOuts), len(outs), len(gotIns), len(ins))
	}
	for i := range outs {
		if gotOuts[i] != outs[i] {
			t.Fatalf("out[%d] %+v != %+v", i, gotOuts[i], outs[i])
		}
	}
	for i := range ins {
		if gotIns[i] != ins[i] {
			t.Fatalf("in[%d] %+v != %+v", i, gotIns[i], ins[i])
		}
	}

	// pooled builder emits byte-identical bytes.
	pb := GetBuilder()
	reused := append([]byte(nil), buildNestedXVMBaseTx(pb, net, chain, outs, ins, nil)...)
	PutBuilder(pb)
	if !bytes.Equal(raw, reused) {
		t.Fatalf("pooled != fresh:\n%x\n%x", raw, reused)
	}
}

func BenchmarkNested_Build(b *testing.B) {
	net, chain, outs, ins := sampleTx()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pb := GetBuilder()
		raw := buildNestedXVMBaseTx(pb, net, chain, outs, ins, nil)
		if len(raw) == 0 {
			b.Fatal("empty")
		}
		PutBuilder(pb)
	}
}

func BenchmarkNested_Parse(b *testing.B) {
	net, chain, outs, ins := sampleTx()
	raw := append([]byte(nil), buildNestedXVMBaseTx(NewBuilder(512), net, chain, outs, ins, nil)...)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := parseNestedXVMBaseTx(raw); err != nil {
			b.Fatal(err)
		}
	}
}
