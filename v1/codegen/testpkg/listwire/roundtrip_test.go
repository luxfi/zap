// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package listwire

import (
	"testing"

	zapv1 "github.com/luxfi/zap/v1"
)

// TestRoundTrip_List proves the generated list code works on the wire:
// build a BatchTx with a scalar + a list of items, wrap the bytes back,
// and read every element zero-copy via the generated ListAt accessor.
func TestRoundTrip_List(t *testing.T) {
	t.Parallel()

	items := []Item{
		{ID: 10, Value: 100},
		{ID: 20, Value: 200},
		{ID: 30, Value: 300},
	}
	view, buf := NewBatchTx(0xCAFE, items)
	_ = view

	got, err := WrapBatchTx(buf)
	if err != nil {
		t.Fatalf("WrapBatchTx: %v", err)
	}

	// Scalar field round-trips.
	if id := zapv1.Read(got, BatchSchemaFields.ID); id != 0xCAFE {
		t.Errorf("ID = %#x, want 0xCAFE", id)
	}

	// List length + every element, via the generated zero-copy accessor.
	list := BatchTxItems(got)
	if list.Len() != len(items) {
		t.Fatalf("list len = %d, want %d", list.Len(), len(items))
	}
	i := 0
	for it := range list.All() {
		wantID, wantVal := items[i].ID, items[i].Value
		if gotID := zapv1.Read(it, ItemSchemaFields.ID); gotID != wantID {
			t.Errorf("item[%d].ID = %d, want %d", i, gotID, wantID)
		}
		if gotVal := zapv1.Read(it, ItemSchemaFields.Value); gotVal != wantVal {
			t.Errorf("item[%d].Value = %d, want %d", i, gotVal, wantVal)
		}
		i++
	}
	if i != len(items) {
		t.Errorf("iterated %d elements, want %d", i, len(items))
	}

	// Empty list round-trips to a zero-length list (null pointer).
	_, emptyBuf := NewBatchTx(1, nil)
	empty, err := WrapBatchTx(emptyBuf)
	if err != nil {
		t.Fatalf("WrapBatchTx(empty): %v", err)
	}
	if n := BatchTxItems(empty).Len(); n != 0 {
		t.Errorf("empty list len = %d, want 0", n)
	}
}
