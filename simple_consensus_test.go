// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SimpleConsensus is a simplified consensus test using direct channels
type SimpleConsensus struct {
	id       int
	inbox    chan *Message
	peers    []*SimpleConsensus
	votes    map[uint64]int
	commits  atomic.Int32
	mu       sync.Mutex
}

func newSimpleConsensus(id int) *SimpleConsensus {
	return &SimpleConsensus{
		id:    id,
		inbox: make(chan *Message, 100),
		votes: make(map[uint64]int),
	}
}

func (c *SimpleConsensus) broadcast(msg *Message) {
	for _, peer := range c.peers {
		if peer.id != c.id {
			peer.inbox <- msg
		}
	}
}

func (c *SimpleConsensus) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-c.inbox:
			c.handleMessage(msg)
		}
	}
}

func (c *SimpleConsensus) handleMessage(msg *Message) {
	msgType := msg.Flags() >> 8
	root := msg.Root()

	switch msgType {
	case 1: // Propose
		round := root.Uint64(0)
		proposer := root.Uint32(8)

		// Vote for the proposal
		b := NewBuilder(64)
		obj := b.StartObject(16)
		obj.SetUint64(0, round)
		obj.SetUint32(8, proposer)
		obj.SetUint32(12, uint32(c.id))
		obj.FinishAsRoot()

		voteMsg, _ := Parse(b.FinishWithFlags(2 << 8)) // MsgTypeVote = 2
		c.broadcast(voteMsg)

	case 2: // Vote
		round := root.Uint64(0)

		c.mu.Lock()
		c.votes[round]++
		if c.votes[round] >= 3 { // Majority of 5
			c.commits.Add(1)
		}
		c.mu.Unlock()
	}
}

func (c *SimpleConsensus) propose(round uint64) {
	b := NewBuilder(64)
	obj := b.StartObject(16)
	obj.SetUint64(0, round)
	obj.SetUint32(8, uint32(c.id))
	obj.FinishAsRoot()

	msg, _ := Parse(b.FinishWithFlags(1 << 8)) // MsgTypePropose = 1
	c.broadcast(msg)
}

// TestSimpleConsensus tests consensus without network
func TestSimpleConsensus(t *testing.T) {
	// Create 5 nodes
	nodes := make([]*SimpleConsensus, 5)
	for i := 0; i < 5; i++ {
		nodes[i] = newSimpleConsensus(i)
	}

	// Connect all nodes
	for i := 0; i < 5; i++ {
		nodes[i].peers = nodes
	}

	// Start all nodes
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, node := range nodes {
		go node.run(ctx)
	}

	// Node 0 proposes
	start := time.Now()
	nodes[0].propose(1)

	// Wait for commits
	time.Sleep(100 * time.Millisecond)

	// Check results
	totalCommits := 0
	for i, node := range nodes {
		commits := int(node.commits.Load())
		totalCommits += commits
		t.Logf("Node %d: commits=%d votes=%v", i, commits, node.votes)
	}

	elapsed := time.Since(start)
	t.Logf("Total commits: %d in %v", totalCommits, elapsed)

	if totalCommits < 3 {
		t.Errorf("Expected at least 3 commits, got %d", totalCommits)
	} else {
		t.Logf("SUCCESS: Consensus reached in %v", elapsed)
	}
}

// BenchmarkSimpleConsensusRound benchmarks consensus without network overhead
func BenchmarkSimpleConsensusRound(b *testing.B) {
	// Build propose message
	proposeBuf := NewBuilder(64)
	pObj := proposeBuf.StartObject(16)
	pObj.SetUint64(0, 1) // round
	pObj.SetUint32(8, 0) // proposer
	pObj.FinishAsRoot()
	proposeData := proposeBuf.FinishWithFlags(1 << 8)

	// Build vote message
	voteBuf := NewBuilder(64)
	vObj := voteBuf.StartObject(16)
	vObj.SetUint64(0, 1)  // round
	vObj.SetUint32(8, 0)  // proposer
	vObj.SetUint32(12, 1) // voter
	vObj.FinishAsRoot()
	voteData := voteBuf.FinishWithFlags(2 << 8)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate full consensus round (1 propose + 4 votes + processing)
		proposeMsg, _ := Parse(proposeData)
		root := proposeMsg.Root()
		_ = root.Uint64(0)
		_ = root.Uint32(8)

		// Process 4 votes (from other nodes)
		for j := 0; j < 4; j++ {
			voteMsg, _ := Parse(voteData)
			vRoot := voteMsg.Root()
			_ = vRoot.Uint64(0)
			_ = vRoot.Uint32(8)
			_ = vRoot.Uint32(12)
		}
	}
}
