// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Message types for consensus
const (
	MsgTypePropose uint16 = 1
	MsgTypeVote    uint16 = 2
	MsgTypeCommit  uint16 = 3
)

// ConsensusNode wraps a ZAP node with consensus logic
type ConsensusNode struct {
	*Node
	id        int
	peers     []string
	proposals map[uint64][]string // round -> votes received
	committed map[uint64]bool     // round -> committed
	mu        sync.Mutex

	proposalCount atomic.Int64
	voteCount     atomic.Int64
	commitCount   atomic.Int64
}

// Field offsets for consensus messages
const (
	FieldRound   = 0  // uint64
	FieldNodeID  = 8  // uint32
	FieldValue   = 12 // uint64 (proposal value)
	FieldVoteFor = 20 // uint32 (voted for node ID)
)

func newConsensusNode(id int, port int, logger *slog.Logger, noDiscovery bool) *ConsensusNode {
	node := NewNode(NodeConfig{
		NodeID:      fmt.Sprintf("node-%d", id),
		ServiceType: "_consensus-test._tcp",
		Port:        port,
		Logger:      logger,
		NoDiscovery: noDiscovery,
	})

	cn := &ConsensusNode{
		Node:      node,
		id:        id,
		proposals: make(map[uint64][]string),
		committed: make(map[uint64]bool),
	}

	// Register handlers
	node.Handle(MsgTypePropose, cn.handlePropose)
	node.Handle(MsgTypeVote, cn.handleVote)
	node.Handle(MsgTypeCommit, cn.handleCommit)

	return cn
}

func (cn *ConsensusNode) handlePropose(ctx context.Context, from string, msg *Message) (*Message, error) {
	cn.proposalCount.Add(1)
	root := msg.Root()
	round := root.Uint64(FieldRound)
	nodeID := root.Uint32(FieldNodeID)

	cn.mu.Lock()
	alreadyVoted := len(cn.proposals[round]) > 0
	if !alreadyVoted {
		if cn.proposals[round] == nil {
			cn.proposals[round] = make([]string, 0)
		}
		cn.proposals[round] = append(cn.proposals[round], from)
	}
	cn.mu.Unlock()

	// Vote for first proposal in round - broadcast to ALL peers
	if !alreadyVoted {
		b := NewBuilder(64)
		obj := b.StartObject(32)
		obj.SetUint64(FieldRound, round)
		obj.SetUint32(FieldNodeID, uint32(cn.id))
		obj.SetUint32(FieldVoteFor, nodeID)
		obj.FinishAsRoot()

		voteMsg, _ := Parse(b.FinishWithFlags(MsgTypeVote << 8))
		// Broadcast vote to all peers (not just the proposer)
		go cn.Broadcast(ctx, voteMsg)
	}

	return nil, nil
}

func (cn *ConsensusNode) handleVote(ctx context.Context, from string, msg *Message) (*Message, error) {
	cn.voteCount.Add(1)
	root := msg.Root()
	round := root.Uint64(FieldRound)

	cn.mu.Lock()
	if cn.proposals[round] == nil {
		cn.proposals[round] = make([]string, 0)
	}
	cn.proposals[round] = append(cn.proposals[round], from)
	voteCount := len(cn.proposals[round])
	alreadyCommitted := cn.committed[round]

	// Check majority (3 of 5)
	shouldCommit := voteCount >= 3 && !alreadyCommitted
	if shouldCommit {
		cn.committed[round] = true
		cn.commitCount.Add(1)
	}
	cn.mu.Unlock()

	if shouldCommit {
		// Broadcast commit to all peers
		b := NewBuilder(64)
		obj := b.StartObject(32)
		obj.SetUint64(FieldRound, round)
		obj.SetUint32(FieldNodeID, uint32(cn.id))
		obj.FinishAsRoot()

		commitMsg, _ := Parse(b.FinishWithFlags(MsgTypeCommit << 8))
		go cn.Broadcast(ctx, commitMsg)
	}

	return nil, nil
}

func (cn *ConsensusNode) handleCommit(ctx context.Context, from string, msg *Message) (*Message, error) {
	root := msg.Root()
	round := root.Uint64(FieldRound)

	cn.mu.Lock()
	if !cn.committed[round] {
		cn.committed[round] = true
		cn.commitCount.Add(1)
	}
	cn.mu.Unlock()

	return nil, nil
}

func (cn *ConsensusNode) propose(ctx context.Context, round uint64, value uint64) error {
	b := NewBuilder(64)
	obj := b.StartObject(32)
	obj.SetUint64(FieldRound, round)
	obj.SetUint32(FieldNodeID, uint32(cn.id))
	obj.SetUint64(FieldValue, value)
	obj.FinishAsRoot()

	msg, err := Parse(b.FinishWithFlags(MsgTypePropose << 8))
	if err != nil {
		return err
	}

	// Broadcast to all peers
	cn.Broadcast(ctx, msg)
	return nil
}

func (cn *ConsensusNode) isCommitted(round uint64) bool {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.committed[round]
}

// TestFiveNodeConsensus tests bootstrapping consensus with 5 nodes
func TestFiveNodeConsensus(t *testing.T) {
	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create 5 nodes with mDNS disabled (use ConnectDirect only for reliable testing)
	nodes := make([]*ConsensusNode, 5)
	basePort := 19000

	for i := 0; i < 5; i++ {
		nodes[i] = newConsensusNode(i, basePort+i, logger, true)
	}

	// Start all nodes
	for i, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", i, err)
		}
		defer node.Stop()
	}

	// Wait for listeners to be ready
	time.Sleep(100 * time.Millisecond)

	// Connect nodes using ConnectDirect (mesh topology: each node connects to higher-numbered nodes)
	t.Log("Connecting nodes...")
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			addr := fmt.Sprintf("127.0.0.1:%d", basePort+j)
			if err := nodes[i].ConnectDirect(addr); err != nil {
				t.Logf("Warning: node %d failed to connect to node %d: %v", i, j, err)
			}
		}
	}

	// Wait for connections to establish
	time.Sleep(100 * time.Millisecond)

	// Check peer counts
	for i, node := range nodes {
		t.Logf("Node %d has %d peers: %v", i, len(node.Peers()), node.Peers())
	}

	// Verify all nodes have full mesh connectivity
	for i, node := range nodes {
		if len(node.Peers()) < 4 {
			t.Fatalf("Node %d has only %d peers, expected 4", i, len(node.Peers()))
		}
	}

	// Node 0 proposes round 1
	ctx := context.Background()
	t.Log("Node 0 proposing round 1...")

	start := time.Now()
	if err := nodes[0].propose(ctx, 1, 42); err != nil {
		t.Fatalf("Failed to propose: %v", err)
	}

	// Wait for consensus with microsecond-precision polling
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Microsecond) // Poll every 100µs for accurate timing
	defer ticker.Stop()

	committed := 0
	for {
		select {
		case <-timeout:
			t.Logf("Timeout - %d nodes committed", committed)
			goto done
		case <-ticker.C:
			committed = 0
			for _, node := range nodes {
				if node.isCommitted(1) {
					committed++
				}
			}
			if committed >= 3 {
				elapsed := time.Since(start)
				t.Logf("Consensus reached! %d nodes committed in %v", committed, elapsed)
				goto done
			}
		}
	}

done:
	// Print stats
	t.Log("\n=== Consensus Stats ===")
	for i, node := range nodes {
		t.Logf("Node %d: proposals=%d votes=%d commits=%d committed=%v",
			i,
			node.proposalCount.Load(),
			node.voteCount.Load(),
			node.commitCount.Load(),
			node.isCommitted(1),
		)
	}

	if committed < 3 {
		t.Errorf("Failed to reach consensus: only %d nodes committed", committed)
	}
}

// BenchmarkConsensusRound benchmarks a single consensus round
func BenchmarkConsensusRound(b *testing.B) {
	// Build propose message
	proposeBuf := NewBuilder(64)
	obj := proposeBuf.StartObject(32)
	obj.SetUint64(FieldRound, 1)
	obj.SetUint32(FieldNodeID, 0)
	obj.SetUint64(FieldValue, 42)
	obj.FinishAsRoot()
	proposeData := proposeBuf.Finish()

	// Build vote message
	voteBuf := NewBuilder(64)
	voteObj := voteBuf.StartObject(32)
	voteObj.SetUint64(FieldRound, 1)
	voteObj.SetUint32(FieldNodeID, 1)
	voteObj.SetUint32(FieldVoteFor, 0)
	voteObj.FinishAsRoot()
	voteData := voteBuf.Finish()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate receiving and processing propose
		proposeMsg, _ := Parse(proposeData)
		root := proposeMsg.Root()
		_ = root.Uint64(FieldRound)
		_ = root.Uint32(FieldNodeID)
		_ = root.Uint64(FieldValue)

		// Simulate receiving and processing vote
		voteMsg, _ := Parse(voteData)
		voteRoot := voteMsg.Root()
		_ = voteRoot.Uint64(FieldRound)
		_ = voteRoot.Uint32(FieldNodeID)
		_ = voteRoot.Uint32(FieldVoteFor)
	}
}
