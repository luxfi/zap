// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package examples

import (
	"github.com/luxfi/zap/v2"
)

// KindBatch is the wire discriminator for BatchTx. Distinct from
// KindAdvanceTime so Registry dispatch can tell them apart.
const KindBatch zapv2.KindByte = 0x21

// BatchSchema is a small, multi-element schema used to exercise the
// generic [zapv2.List] iter.Seq path in tests. Object layout:
//
//	@0: KindBatch (uint8)
//	@1: BatchID   (uint64)
//	@9: Items     (list pointer: relOffset uint32 + length uint32)
//
// Each list element is an [ItemSchema] (16 bytes: id uint64 + value
// uint64).
type BatchSchema struct{}

func (BatchSchema) Kind() zapv2.KindByte { return KindBatch }
func (BatchSchema) Size() int            { return 17 }
func (BatchSchema) Name() string         { return "BatchTx" }

// KindItem identifies ItemSchema. Items live inside BatchTx lists; an
// Item is never a top-level message, but it has a Kind anyway so the
// generic List[Item] code can use the same machinery.
const KindItem zapv2.KindByte = 0x22

// ItemSchema is the per-element schema for BatchTx.Items.
type ItemSchema struct{}

func (ItemSchema) Kind() zapv2.KindByte { return KindItem }
func (ItemSchema) Size() int            { return 16 } // 8 + 8
func (ItemSchema) Name() string         { return "BatchItem" }

// BatchFields declares the offsets for BatchSchema.
var BatchFields = struct {
	ID zapv2.Field[BatchSchema, uint64]
}{
	ID: zapv2.At[BatchSchema, uint64](1),
}

// ItemFields declares the offsets for ItemSchema.
var ItemFields = struct {
	ID    zapv2.Field[ItemSchema, uint64]
	Value zapv2.Field[ItemSchema, uint64]
}{
	ID:    zapv2.At[ItemSchema, uint64](0),
	Value: zapv2.At[ItemSchema, uint64](8),
}

// OffsetBatchItems is the byte offset of the list pointer for Items
// within the BatchSchema fixed payload. Items is a variable-length
// list, so it lives outside the [zapv2.Field] generic vocabulary; it
// is read via [zapv2.ListAt] instead.
const OffsetBatchItems uint32 = 9

// Items returns the list of items in the batch as an [iter.Seq]-ready
// [zapv2.List][ItemSchema]. Range-over-func:
//
//	for item := range examples.Items(batchView).All() {
//	    id    := zapv2.Read(item, examples.ItemFields.ID)
//	    value := zapv2.Read(item, examples.ItemFields.Value)
//	    // ...
//	}
func Items(v zapv2.View[BatchSchema]) zapv2.List[ItemSchema] {
	return zapv2.ListAt[BatchSchema, ItemSchema](v, OffsetBatchItems)
}

// Item is a value-shaped helper for batch-construction tests.
type Item struct {
	ID    uint64
	Value uint64
}

// NewBatch builds a BatchTx with the given ID and items.
func NewBatch(id uint64, items []Item) (zapv2.View[BatchSchema], []byte) {
	return zapv2.Build[BatchSchema](func(s zapv2.Setter[BatchSchema]) {
		zapv2.Write(s, BatchFields.ID, id)
		zapv2.WriteList[BatchSchema, ItemSchema](s, OffsetBatchItems,
			func(es *zapv2.ElemSetter[ItemSchema]) {
				for _, it := range items {
					es.Append(func(e zapv2.Setter[ItemSchema]) {
						zapv2.Write(e, ItemFields.ID, it.ID)
						zapv2.Write(e, ItemFields.Value, it.Value)
					})
				}
			})
	})
}

func init() {
	zapv2.Register[BatchSchema](zapv2.DefaultRegistry)
	zapv2.Register[ItemSchema](zapv2.DefaultRegistry)
}
