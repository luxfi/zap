// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// LocalConsensusNode is a simplified node for local testing without mDNS
type LocalConsensusNode struct {
	id       int
	nodeID   string
	port     int
	listener net.Listener
	conns    map[string]*localConn
	connsMu  sync.RWMutex

	handlers   map[uint16]Handler
	handlersMu sync.RWMutex

	proposals map[uint64][]string
	committed map[uint64]bool
	mu        sync.Mutex

	proposalCount atomic.Int64
	voteCount     atomic.Int64
	commitCount   atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger
}

type localConn struct {
	nodeID string
	conn   net.Conn
	mu     sync.Mutex
}

func newLocalConsensusNode(id int, port int, logger *slog.Logger) *LocalConsensusNode {
	ctx, cancel := context.WithCancel(context.Background())
	cn := &LocalConsensusNode{
		id:        id,
		nodeID:    fmt.Sprintf("node-%d", id),
		port:      port,
		conns:     make(map[string]*localConn),
		handlers:  make(map[uint16]Handler),
		proposals: make(map[uint64][]string),
		committed: make(map[uint64]bool),
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger,
	}

	// Register handlers
	cn.handlers[MsgTypePropose] = cn.handlePropose
	cn.handlers[MsgTypeVote] = cn.handleVote
	cn.handlers[MsgTypeCommit] = cn.handleCommit

	return cn
}

func (cn *LocalConsensusNode) start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cn.port))
	if err != nil {
		return err
	}
	cn.listener = listener

	cn.wg.Add(1)
	go cn.acceptLoop()

	return nil
}

func (cn *LocalConsensusNode) stop() {
	cn.cancel()
	if cn.listener != nil {
		cn.listener.Close()
	}
	cn.connsMu.Lock()
	for _, c := range cn.conns {
		c.conn.Close()
	}
	cn.connsMu.Unlock()
	cn.wg.Wait()
}

func (cn *LocalConsensusNode) acceptLoop() {
	defer cn.wg.Done()

	for {
		conn, err := cn.listener.Accept()
		if err != nil {
			select {
			case <-cn.ctx.Done():
				return
			default:
				continue
			}
		}

		cn.wg.Add(1)
		go cn.handleConn(conn)
	}
}

func (cn *LocalConsensusNode) handleConn(netConn net.Conn) {
	defer cn.wg.Done()
	defer netConn.Close()

	// Read handshake
	var peerID string
	{
		msg, err := readMessage(netConn)
		if err != nil {
			return
		}
		root := msg.Root()
		idLen := root.Uint32(60)
		if idLen > 0 && idLen <= 60 {
			idBytes := make([]byte, idLen)
			for i := uint32(0); i < idLen; i++ {
				idBytes[i] = root.Uint8(int(i))
			}
			peerID = string(idBytes)
		}
	}

	// Send our handshake
	{
		b := NewBuilder(128)
		obj := b.StartObject(64)
		idBytes := []byte(cn.nodeID)
		for i, c := range idBytes {
			if i >= 60 {
				break
			}
			obj.SetUint8(i, c)
		}
		obj.SetUint32(60, uint32(len(idBytes)))
		obj.FinishAsRoot()
		if err := writeMessage(netConn, b.Finish()); err != nil {
			return
		}
	}

	lc := &localConn{
		nodeID: peerID,
		conn:   netConn,
	}

	cn.connsMu.Lock()
	cn.conns[peerID] = lc
	cn.connsMu.Unlock()

	cn.logger.Debug("Peer connected", "peer", peerID)

	defer func() {
		cn.connsMu.Lock()
		delete(cn.conns, peerID)
		cn.connsMu.Unlock()
	}()

	// Message loop
	for {
		select {
		case <-cn.ctx.Done():
			return
		default:
		}

		msg, err := readMessage(netConn)
		if err != nil {
			return
		}

		msgType := msg.Flags() >> 8

		cn.handlersMu.RLock()
		handler, ok := cn.handlers[msgType]
		cn.handlersMu.RUnlock()

		if ok {
			resp, err := handler(cn.ctx, peerID, msg)
			if err != nil {
				continue
			}
			if resp != nil {
				if err := writeMessage(netConn, resp.Bytes()); err != nil {
					return
				}
			}
		}
	}
}

func (cn *LocalConsensusNode) connectTo(addr string) error {
	netConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}

	// Send our handshake
	{
		b := NewBuilder(128)
		obj := b.StartObject(64)
		idBytes := []byte(cn.nodeID)
		for i, c := range idBytes {
			if i >= 60 {
				break
			}
			obj.SetUint8(i, c)
		}
		obj.SetUint32(60, uint32(len(idBytes)))
		obj.FinishAsRoot()
		if err := writeMessage(netConn, b.Finish()); err != nil {
			netConn.Close()
			return err
		}
	}

	// Read response
	var peerID string
	{
		msg, err := readMessage(netConn)
		if err != nil {
			netConn.Close()
			return err
		}
		root := msg.Root()
		idLen := root.Uint32(60)
		if idLen > 0 && idLen <= 60 {
			idBytes := make([]byte, idLen)
			for i := uint32(0); i < idLen; i++ {
				idBytes[i] = root.Uint8(int(i))
			}
			peerID = string(idBytes)
		}
	}

	lc := &localConn{
		nodeID: peerID,
		conn:   netConn,
	}

	cn.connsMu.Lock()
	cn.conns[peerID] = lc
	cn.connsMu.Unlock()

	cn.logger.Debug("Connected to peer", "peer", peerID)

	// Start receive loop
	cn.wg.Add(1)
	go func() {
		defer cn.wg.Done()
		defer func() {
			cn.connsMu.Lock()
			delete(cn.conns, peerID)
			cn.connsMu.Unlock()
		}()

		for {
			select {
			case <-cn.ctx.Done():
				return
			default:
			}

			msg, err := readMessage(netConn)
			if err != nil {
				return
			}

			msgType := msg.Flags() >> 8
			cn.handlersMu.RLock()
			handler, ok := cn.handlers[msgType]
			cn.handlersMu.RUnlock()

			if ok {
				handler(cn.ctx, peerID, msg)
			}
		}
	}()

	return nil
}

func (cn *LocalConsensusNode) broadcast(msg *Message) {
	cn.connsMu.RLock()
	peers := make([]*localConn, 0, len(cn.conns))
	for _, c := range cn.conns {
		peers = append(peers, c)
	}
	cn.connsMu.RUnlock()

	for _, c := range peers {
		c.mu.Lock()
		writeMessage(c.conn, msg.Bytes())
		c.mu.Unlock()
	}
}

func (cn *LocalConsensusNode) handlePropose(ctx context.Context, from string, msg *Message) (*Message, error) {
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
		go cn.broadcast(voteMsg)
	}

	return nil, nil
}

func (cn *LocalConsensusNode) handleVote(ctx context.Context, from string, msg *Message) (*Message, error) {
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
		go cn.broadcast(commitMsg)
	}

	return nil, nil
}

func (cn *LocalConsensusNode) handleCommit(ctx context.Context, from string, msg *Message) (*Message, error) {
	root := msg.Root()
	round := root.Uint64(FieldRound)

	cn.mu.Lock()
	cn.committed[round] = true
	cn.mu.Unlock()

	cn.commitCount.Add(1)
	return nil, nil
}

func (cn *LocalConsensusNode) propose(round uint64, value uint64) error {
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

	cn.broadcast(msg)
	return nil
}

func (cn *LocalConsensusNode) isCommitted(round uint64) bool {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.committed[round]
}

func (cn *LocalConsensusNode) peers() []string {
	cn.connsMu.RLock()
	defer cn.connsMu.RUnlock()
	result := make([]string, 0, len(cn.conns))
	for id := range cn.conns {
		result = append(result, id)
	}
	return result
}

// TestLocalFiveNodeConsensus tests 5-node consensus with direct TCP connections
func TestLocalFiveNodeConsensus(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create 5 nodes
	nodes := make([]*LocalConsensusNode, 5)
	basePort := 19100

	for i := 0; i < 5; i++ {
		nodes[i] = newLocalConsensusNode(i, basePort+i, logger)
	}

	// Start all nodes
	for i, node := range nodes {
		if err := node.start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", i, err)
		}
		defer node.stop()
	}

	// Give listeners time to start
	time.Sleep(100 * time.Millisecond)

	// Connect nodes in a mesh (node i connects to nodes i+1 to 4)
	t.Log("Connecting nodes...")
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			addr := fmt.Sprintf("127.0.0.1:%d", basePort+j)
			if err := nodes[i].connectTo(addr); err != nil {
				t.Logf("Warning: node %d failed to connect to node %d: %v", i, j, err)
			}
		}
	}

	// Wait for connections
	time.Sleep(200 * time.Millisecond)

	// Check peer counts
	for i, node := range nodes {
		t.Logf("Node %d has %d peers: %v", i, len(node.peers()), node.peers())
	}

	// Node 0 proposes
	t.Log("Node 0 proposing round 1...")
	start := time.Now()
	if err := nodes[0].propose(1, 42); err != nil {
		t.Fatalf("Failed to propose: %v", err)
	}

	// Wait for consensus
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
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
