// Multi-Agent LLM Consensus via ZAP Protocol
//
// This example demonstrates a network of AI agents communicating via ZAP,
// each querying different LLM backends and reaching consensus on responses.
//
// Architecture:
//   - 5 Agent nodes (Claude, GPT, Copilot, Qwen, Gemini)
//   - ZAP protocol for zero-copy message passing
//   - Broadcast-based voting and consensus
//   - Gemini as final summarizer/arbiter
//
// Usage:
//   go run main.go
//
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/zap"
)

// Message types for agent consensus
const (
	MsgTypeQuery    uint16 = 10 // Query broadcast
	MsgTypeResponse uint16 = 11 // LLM response
	MsgTypeVote     uint16 = 12 // Vote for a response
	MsgTypeSummary  uint16 = 13 // Final consensus summary
)

// Field offsets for agent messages
const (
	FieldQueryID   = 0  // uint64: query identifier
	FieldAgentID   = 8  // uint32: agent ID
	FieldTimestamp = 12 // uint64: unix timestamp
	FieldPayload   = 20 // variable: query/response text start
	FieldVoteFor   = 20 // uint32: voted for agent ID
	FieldVoteScore = 24 // uint32: confidence score (0-100)
)

// AgentConfig defines an AI agent's configuration
type AgentConfig struct {
	ID       int
	Name     string
	Model    string
	Endpoint string // API endpoint
	APIKey   string // API key env var name
}

// Predefined agent configurations
var AgentConfigs = []AgentConfig{
	{0, "Claude", "claude-3-5-sonnet", "https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"},
	{1, "GPT", "gpt-4o", "https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"},
	{2, "Copilot", "gpt-4o", "https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY"}, // Simulated
	{3, "Qwen", "qwen-max", "https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation", "DASHSCOPE_API_KEY"},
	{4, "Gemini", "gemini-1.5-pro", "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent", "GOOGLE_API_KEY"},
}

// AgentNode is an AI agent that communicates via ZAP
type AgentNode struct {
	config   AgentConfig
	nodeID   string
	port     int
	listener net.Listener
	conns    map[string]*agentConn
	connsMu  sync.RWMutex

	// Consensus state
	responses map[uint64]map[int]string  // queryID -> agentID -> response
	votes     map[uint64]map[int][]int   // queryID -> agentID -> list of voters
	summaries map[uint64]string          // queryID -> final summary
	mu        sync.Mutex

	// Stats
	queryCount    atomic.Int64
	responseCount atomic.Int64
	voteCount     atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger
}

type agentConn struct {
	nodeID string
	conn   net.Conn
	mu     sync.Mutex
}

func newAgentNode(config AgentConfig, port int, logger *slog.Logger) *AgentNode {
	ctx, cancel := context.WithCancel(context.Background())
	return &AgentNode{
		config:    config,
		nodeID:    fmt.Sprintf("agent-%s-%d", config.Name, config.ID),
		port:      port,
		conns:     make(map[string]*agentConn),
		responses: make(map[uint64]map[int]string),
		votes:     make(map[uint64]map[int][]int),
		summaries: make(map[uint64]string),
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger,
	}
}

func (a *AgentNode) start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.port))
	if err != nil {
		return err
	}
	a.listener = listener

	a.wg.Add(1)
	go a.acceptLoop()

	a.logger.Info("Agent started", "name", a.config.Name, "model", a.config.Model, "port", a.port)
	return nil
}

func (a *AgentNode) stop() {
	a.cancel()
	if a.listener != nil {
		a.listener.Close()
	}
	a.connsMu.Lock()
	for _, c := range a.conns {
		c.conn.Close()
	}
	a.connsMu.Unlock()
	a.wg.Wait()
}

func (a *AgentNode) acceptLoop() {
	defer a.wg.Done()
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				return
			default:
				continue
			}
		}
		a.wg.Add(1)
		go a.handleConn(conn)
	}
}

func (a *AgentNode) handleConn(netConn net.Conn) {
	defer a.wg.Done()
	defer netConn.Close()

	// Handshake
	peerID, err := a.doHandshake(netConn, false)
	if err != nil {
		return
	}

	ac := &agentConn{nodeID: peerID, conn: netConn}
	a.connsMu.Lock()
	a.conns[peerID] = ac
	a.connsMu.Unlock()

	defer func() {
		a.connsMu.Lock()
		delete(a.conns, peerID)
		a.connsMu.Unlock()
	}()

	// Message loop
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		msg, err := readMessage(netConn)
		if err != nil {
			return
		}
		a.handleMessage(peerID, msg)
	}
}

func (a *AgentNode) connectTo(addr string) error {
	netConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}

	peerID, err := a.doHandshake(netConn, true)
	if err != nil {
		netConn.Close()
		return err
	}

	ac := &agentConn{nodeID: peerID, conn: netConn}
	a.connsMu.Lock()
	a.conns[peerID] = ac
	a.connsMu.Unlock()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			a.connsMu.Lock()
			delete(a.conns, peerID)
			a.connsMu.Unlock()
		}()

		for {
			select {
			case <-a.ctx.Done():
				return
			default:
			}

			msg, err := readMessage(netConn)
			if err != nil {
				return
			}
			a.handleMessage(peerID, msg)
		}
	}()

	return nil
}

func (a *AgentNode) doHandshake(conn net.Conn, initiator bool) (string, error) {
	if initiator {
		// Send first
		if err := a.sendHandshake(conn); err != nil {
			return "", err
		}
		return a.recvHandshake(conn)
	}
	// Receive first
	peerID, err := a.recvHandshake(conn)
	if err != nil {
		return "", err
	}
	if err := a.sendHandshake(conn); err != nil {
		return "", err
	}
	return peerID, nil
}

func (a *AgentNode) sendHandshake(conn net.Conn) error {
	b := zap.NewBuilder(128)
	obj := b.StartObject(64)
	idBytes := []byte(a.nodeID)
	for i, c := range idBytes {
		if i >= 60 {
			break
		}
		obj.SetUint8(i, c)
	}
	obj.SetUint32(60, uint32(len(idBytes)))
	obj.FinishAsRoot()
	return writeMessage(conn, b.Finish())
}

func (a *AgentNode) recvHandshake(conn net.Conn) (string, error) {
	msg, err := readMessage(conn)
	if err != nil {
		return "", err
	}
	root := msg.Root()
	idLen := root.Uint32(60)
	if idLen > 0 && idLen <= 60 {
		idBytes := make([]byte, idLen)
		for i := uint32(0); i < idLen; i++ {
			idBytes[i] = root.Uint8(int(i))
		}
		return string(idBytes), nil
	}
	return "", fmt.Errorf("invalid handshake")
}

func (a *AgentNode) handleMessage(from string, msg *zap.Message) {
	msgType := msg.Flags() >> 8
	root := msg.Root()

	switch msgType {
	case MsgTypeQuery:
		a.handleQuery(from, root)
	case MsgTypeResponse:
		a.handleResponse(from, root)
	case MsgTypeVote:
		a.handleVote(from, root)
	case MsgTypeSummary:
		a.handleSummary(from, root)
	}
}

func (a *AgentNode) handleQuery(from string, root zap.Object) {
	a.queryCount.Add(1)
	queryID := root.Uint64(FieldQueryID)

	// Extract query text
	queryLen := int(root.Uint32(FieldPayload))
	queryBytes := make([]byte, queryLen)
	for i := 0; i < queryLen && i < 1000; i++ {
		queryBytes[i] = root.Uint8(FieldPayload + 4 + i)
	}
	query := string(queryBytes)

	a.logger.Info("Received query", "from", from, "queryID", queryID, "query", truncate(query, 50))

	// Query our LLM backend
	go func() {
		response, err := a.queryLLM(query)
		if err != nil {
			a.logger.Error("LLM query failed", "error", err)
			response = fmt.Sprintf("[%s error: %v]", a.config.Name, err)
		}

		// Broadcast response
		a.broadcastResponse(queryID, response)
	}()
}

func (a *AgentNode) handleResponse(from string, root zap.Object) {
	a.responseCount.Add(1)
	queryID := root.Uint64(FieldQueryID)
	agentID := int(root.Uint32(FieldAgentID))

	// Extract response text
	respLen := int(root.Uint32(FieldPayload))
	respBytes := make([]byte, respLen)
	for i := 0; i < respLen && i < 4096; i++ {
		respBytes[i] = root.Uint8(FieldPayload + 4 + i)
	}
	response := string(respBytes)

	a.mu.Lock()
	if a.responses[queryID] == nil {
		a.responses[queryID] = make(map[int]string)
	}
	a.responses[queryID][agentID] = response
	responseCount := len(a.responses[queryID])
	a.mu.Unlock()

	a.logger.Info("Received response", "from", from, "agentID", agentID, "queryID", queryID, "responses", responseCount)

	// When we have all responses, vote
	if responseCount >= 4 { // At least 4 of 5 agents responded
		go a.castVote(queryID)
	}
}

func (a *AgentNode) handleVote(from string, root zap.Object) {
	a.voteCount.Add(1)
	queryID := root.Uint64(FieldQueryID)
	voterID := int(root.Uint32(FieldAgentID))
	voteFor := int(root.Uint32(FieldVoteFor))

	a.mu.Lock()
	if a.votes[queryID] == nil {
		a.votes[queryID] = make(map[int][]int)
	}
	a.votes[queryID][voteFor] = append(a.votes[queryID][voteFor], voterID)
	totalVotes := 0
	for _, voters := range a.votes[queryID] {
		totalVotes += len(voters)
	}
	a.mu.Unlock()

	a.logger.Info("Received vote", "from", from, "voter", voterID, "voteFor", voteFor, "totalVotes", totalVotes)

	// Gemini (agent 4) summarizes when we have enough votes
	if a.config.ID == 4 && totalVotes >= 4 {
		go a.summarizeConsensus(queryID)
	}
}

func (a *AgentNode) handleSummary(from string, root zap.Object) {
	queryID := root.Uint64(FieldQueryID)

	summaryLen := int(root.Uint32(FieldPayload))
	summaryBytes := make([]byte, summaryLen)
	for i := 0; i < summaryLen && i < 4096; i++ {
		summaryBytes[i] = root.Uint8(FieldPayload + 4 + i)
	}
	summary := string(summaryBytes)

	a.mu.Lock()
	a.summaries[queryID] = summary
	a.mu.Unlock()

	a.logger.Info("CONSENSUS REACHED", "queryID", queryID)
	fmt.Printf("\n=== CONSENSUS SUMMARY (Query %d) ===\n%s\n", queryID, summary)
}

func (a *AgentNode) broadcastQuery(queryID uint64, query string) {
	b := zap.NewBuilder(2048)
	obj := b.StartObject(1024)
	obj.SetUint64(FieldQueryID, queryID)
	obj.SetUint32(FieldAgentID, uint32(a.config.ID))
	obj.SetUint64(FieldTimestamp, uint64(time.Now().Unix()))

	// Store query text
	queryBytes := []byte(query)
	obj.SetUint32(FieldPayload, uint32(len(queryBytes)))
	for i, c := range queryBytes {
		if i >= 1000 {
			break
		}
		obj.SetUint8(FieldPayload+4+i, c)
	}
	obj.FinishAsRoot()

	msg, _ := zap.Parse(b.FinishWithFlags(MsgTypeQuery << 8))
	a.broadcast(msg)
}

func (a *AgentNode) broadcastResponse(queryID uint64, response string) {
	b := zap.NewBuilder(8192)
	obj := b.StartObject(4096)
	obj.SetUint64(FieldQueryID, queryID)
	obj.SetUint32(FieldAgentID, uint32(a.config.ID))
	obj.SetUint64(FieldTimestamp, uint64(time.Now().Unix()))

	// Store response text
	respBytes := []byte(response)
	obj.SetUint32(FieldPayload, uint32(len(respBytes)))
	for i, c := range respBytes {
		if i >= 4000 {
			break
		}
		obj.SetUint8(FieldPayload+4+i, c)
	}
	obj.FinishAsRoot()

	msg, _ := zap.Parse(b.FinishWithFlags(MsgTypeResponse << 8))
	a.broadcast(msg)

	// Also store our own response
	a.mu.Lock()
	if a.responses[queryID] == nil {
		a.responses[queryID] = make(map[int]string)
	}
	a.responses[queryID][a.config.ID] = response
	a.mu.Unlock()
}

func (a *AgentNode) castVote(queryID uint64) {
	a.mu.Lock()
	responses := make(map[int]string)
	for k, v := range a.responses[queryID] {
		responses[k] = v
	}
	a.mu.Unlock()

	// Simple voting: vote for the longest response (as a heuristic for quality)
	// In production, this would use semantic similarity or quality scoring
	bestAgent := -1
	bestLen := 0
	for agentID, resp := range responses {
		if len(resp) > bestLen {
			bestLen = len(resp)
			bestAgent = agentID
		}
	}

	if bestAgent == -1 {
		return
	}

	// Broadcast vote
	b := zap.NewBuilder(128)
	obj := b.StartObject(64)
	obj.SetUint64(FieldQueryID, queryID)
	obj.SetUint32(FieldAgentID, uint32(a.config.ID))
	obj.SetUint32(FieldVoteFor, uint32(bestAgent))
	obj.SetUint32(FieldVoteScore, 80) // Confidence
	obj.FinishAsRoot()

	msg, _ := zap.Parse(b.FinishWithFlags(MsgTypeVote << 8))
	a.broadcast(msg)

	// Record own vote
	a.mu.Lock()
	if a.votes[queryID] == nil {
		a.votes[queryID] = make(map[int][]int)
	}
	a.votes[queryID][bestAgent] = append(a.votes[queryID][bestAgent], a.config.ID)
	a.mu.Unlock()

	a.logger.Info("Cast vote", "queryID", queryID, "voteFor", bestAgent)
}

func (a *AgentNode) summarizeConsensus(queryID uint64) {
	a.mu.Lock()
	if _, exists := a.summaries[queryID]; exists {
		a.mu.Unlock()
		return // Already summarized
	}
	a.summaries[queryID] = "pending" // Mark as in-progress

	responses := make(map[int]string)
	for k, v := range a.responses[queryID] {
		responses[k] = v
	}
	votes := make(map[int][]int)
	for k, v := range a.votes[queryID] {
		votes[k] = v
	}
	a.mu.Unlock()

	// Find winner
	winner := -1
	maxVotes := 0
	for agentID, voters := range votes {
		if len(voters) > maxVotes {
			maxVotes = len(voters)
			winner = agentID
		}
	}

	// Build summary
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Consensus reached with %d votes for Agent %d (%s)\n\n",
		maxVotes, winner, AgentConfigs[winner].Name))
	summary.WriteString("Vote distribution:\n")
	for agentID, voters := range votes {
		summary.WriteString(fmt.Sprintf("  - Agent %d (%s): %d votes from %v\n",
			agentID, AgentConfigs[agentID].Name, len(voters), voters))
	}
	summary.WriteString(fmt.Sprintf("\nWinning response from %s:\n%s\n",
		AgentConfigs[winner].Name, truncate(responses[winner], 500)))

	summaryText := summary.String()
	a.mu.Lock()
	a.summaries[queryID] = summaryText
	a.mu.Unlock()

	// Broadcast summary
	b := zap.NewBuilder(8192)
	obj := b.StartObject(4096)
	obj.SetUint64(FieldQueryID, queryID)
	obj.SetUint32(FieldAgentID, uint32(a.config.ID))

	summaryBytes := []byte(summaryText)
	obj.SetUint32(FieldPayload, uint32(len(summaryBytes)))
	for i, c := range summaryBytes {
		if i >= 4000 {
			break
		}
		obj.SetUint8(FieldPayload+4+i, c)
	}
	obj.FinishAsRoot()

	msg, _ := zap.Parse(b.FinishWithFlags(MsgTypeSummary << 8))
	a.broadcast(msg)
}

func (a *AgentNode) queryLLM(query string) (string, error) {
	apiKey := os.Getenv(a.config.APIKey)
	if apiKey == "" {
		// Simulate response if no API key
		return a.simulateLLMResponse(query), nil
	}

	// Real API calls would go here
	// For now, simulate responses
	return a.simulateLLMResponse(query), nil
}

func (a *AgentNode) simulateLLMResponse(query string) string {
	// Simulate different agent personalities/responses
	personalities := map[string]string{
		"Claude":  "From a careful analysis perspective, ",
		"GPT":     "Based on my comprehensive knowledge, ",
		"Copilot": "Looking at this from a coding angle, ",
		"Qwen":    "Considering multiple viewpoints, ",
		"Gemini":  "Synthesizing available information, ",
	}

	prefix := personalities[a.config.Name]
	if prefix == "" {
		prefix = "In my analysis, "
	}

	// Simulate thinking time
	time.Sleep(time.Duration(100+a.config.ID*50) * time.Millisecond)

	return fmt.Sprintf("%sthe answer to '%s' involves understanding the underlying principles. "+
		"Agent %s (%s model) recommends a thoughtful approach that considers both "+
		"technical accuracy and practical applicability. Key factors include: "+
		"1) Understanding context, 2) Applying relevant knowledge, 3) Validating assumptions.",
		prefix, truncate(query, 30), a.config.Name, a.config.Model)
}

func (a *AgentNode) broadcast(msg *zap.Message) {
	a.connsMu.RLock()
	peers := make([]*agentConn, 0, len(a.conns))
	for _, c := range a.conns {
		peers = append(peers, c)
	}
	a.connsMu.RUnlock()

	for _, c := range peers {
		c.mu.Lock()
		writeMessage(c.conn, msg.Bytes())
		c.mu.Unlock()
	}
}

func (a *AgentNode) peers() []string {
	a.connsMu.RLock()
	defer a.connsMu.RUnlock()
	result := make([]string, 0, len(a.conns))
	for id := range a.conns {
		result = append(result, id)
	}
	return result
}

// Wire format helpers
func writeMessage(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(data))
	lenBuf[1] = byte(len(data) >> 8)
	lenBuf[2] = byte(len(data) >> 16)
	lenBuf[3] = byte(len(data) >> 24)
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readMessage(r io.Reader) (*zap.Message, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := uint32(lenBuf[0]) | uint32(lenBuf[1])<<8 | uint32(lenBuf[2])<<16 | uint32(lenBuf[3])<<24
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return zap.Parse(data)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	fmt.Println("=== Multi-Agent LLM Consensus via ZAP Protocol ===")
	fmt.Println()
	fmt.Println("Agents:")
	for _, cfg := range AgentConfigs {
		fmt.Printf("  [%d] %s (%s)\n", cfg.ID, cfg.Name, cfg.Model)
	}
	fmt.Println()

	// Create agents
	agents := make([]*AgentNode, 5)
	basePort := 20000

	for i := 0; i < 5; i++ {
		agents[i] = newAgentNode(AgentConfigs[i], basePort+i, logger)
	}

	// Start all agents
	for i, agent := range agents {
		if err := agent.start(); err != nil {
			fmt.Printf("Failed to start agent %d: %v\n", i, err)
			return
		}
		defer agent.stop()
	}

	time.Sleep(100 * time.Millisecond)

	// Connect agents in mesh
	fmt.Println("Connecting agents via ZAP...")
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			addr := fmt.Sprintf("127.0.0.1:%d", basePort+j)
			if err := agents[i].connectTo(addr); err != nil {
				fmt.Printf("Warning: agent %d failed to connect to agent %d: %v\n", i, j, err)
			}
		}
	}

	time.Sleep(200 * time.Millisecond)

	// Verify connections
	fmt.Println("\nAgent connections:")
	for _, agent := range agents {
		fmt.Printf("  %s: %d peers\n", agent.config.Name, len(agent.peers()))
	}
	fmt.Println()

	// Start consensus query
	query := "What is the most important principle in software engineering?"
	if len(os.Args) > 1 {
		query = strings.Join(os.Args[1:], " ")
	}

	fmt.Printf("Query: %s\n", query)
	fmt.Println("\nBroadcasting query to all agents...")
	fmt.Println()

	// Claude (agent 0) initiates the query
	start := time.Now()
	agents[0].broadcastQuery(1, query)

	// Also process locally
	go func() {
		response := agents[0].simulateLLMResponse(query)
		agents[0].broadcastResponse(1, response)
	}()

	// Wait for consensus
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			fmt.Println("\nTimeout waiting for consensus")
			goto done
		case <-ticker.C:
			// Check if Gemini has summarized
			agents[4].mu.Lock()
			summary, ok := agents[4].summaries[1]
			agents[4].mu.Unlock()
			if ok && summary != "pending" {
				elapsed := time.Since(start)
				fmt.Printf("\nConsensus achieved in %v\n", elapsed)
				goto done
			}
		}
	}

done:
	// Print final stats
	fmt.Println("\n=== Agent Stats ===")
	for _, agent := range agents {
		fmt.Printf("  %s: queries=%d responses=%d votes=%d\n",
			agent.config.Name,
			agent.queryCount.Load(),
			agent.responseCount.Load(),
			agent.voteCount.Load(),
		)
	}
}

// Unused but available for real API integration
var _ = http.Client{}
var _ = json.Marshal
