// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"encoding/binary"
	"sync"
	"testing"
)

// TestSessionBidirectionalConcurrent stresses Send/Recv on both sides
// simultaneously. Run with -race to verify there are no read/write
// races on the per-direction state.
//
// Pattern: client and server each send N indexed payloads while
// concurrently receiving the other side's stream. Each side asserts
// monotonically increasing indexes — Recv returns frames in send
// order on each direction.
func TestSessionBidirectionalConcurrent(t *testing.T) {
	const N = 64
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(4)

	// Client sender.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(i))
			if err := client.Send(buf[:]); err != nil {
				t.Errorf("client send[%d]: %v", i, err)
				return
			}
		}
	}()
	// Server sender.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(i))
			if err := server.Send(buf[:]); err != nil {
				t.Errorf("server send[%d]: %v", i, err)
				return
			}
		}
	}()
	// Client receiver.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			got, err := client.Recv()
			if err != nil {
				t.Errorf("client recv[%d]: %v", i, err)
				return
			}
			if len(got) != 4 {
				t.Errorf("client recv[%d] len %d", i, len(got))
				return
			}
			if binary.BigEndian.Uint32(got) != uint32(i) {
				t.Errorf("client recv[%d] mismatch %d", i, binary.BigEndian.Uint32(got))
				return
			}
		}
	}()
	// Server receiver.
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			got, err := server.Recv()
			if err != nil {
				t.Errorf("server recv[%d]: %v", i, err)
				return
			}
			if len(got) != 4 || binary.BigEndian.Uint32(got) != uint32(i) {
				t.Errorf("server recv[%d] mismatch", i)
				return
			}
		}
	}()

	wg.Wait()
}

// TestSessionSerializedSendOrder confirms Session.Send is internally
// serialised — concurrent Sends from the same side land on the wire
// in some order without corrupting frame boundaries. The receiver
// gets the full multiset of payloads (order may interleave but no
// truncation).
func TestSessionSerializedSendOrder(t *testing.T) {
	const N = 128
	client, server := pqPair(t)
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(i))
			if err := client.Send(buf[:]); err != nil {
				t.Errorf("send[%d]: %v", i, err)
			}
		}()
	}

	seen := make(map[uint32]bool, N)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(seen) < N {
			got, err := server.Recv()
			if err != nil {
				t.Errorf("recv: %v", err)
				return
			}
			if len(got) != 4 {
				t.Errorf("recv len %d", len(got))
				return
			}
			seen[binary.BigEndian.Uint32(got)] = true
		}
	}()
	wg.Wait()
	<-done
	if len(seen) != N {
		t.Fatalf("seen %d, want %d", len(seen), N)
	}
}
