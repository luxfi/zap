// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// MCP-style JSON-RPC Tool Calling (traditional approach)
// ============================================================================

// MCPRequest represents a JSON-RPC 2.0 request (what MCP uses)
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// MCPResponse represents a JSON-RPC 2.0 response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPToolParams represents typical tool call parameters
type MCPToolParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
}

// MCPToolResult represents typical tool result
type MCPToolResult struct {
	Content []MCPContent `json:"content"`
}

type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// simulateMCPToolCall simulates the full MCP protocol overhead
func simulateMCPToolCall(toolName string, args map[string]string) ([]byte, error) {
	// 1. Marshal request (JSON serialization)
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: MCPToolParams{
			Name:      toolName,
			Arguments: args,
		},
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// 2. "Send" over network (simulated - in real MCP this goes through stdio/HTTP)
	_ = reqBytes

	// 3. "Process" on server side - unmarshal
	var serverReq MCPRequest
	if err := json.Unmarshal(reqBytes, &serverReq); err != nil {
		return nil, err
	}

	// 4. Execute tool (simulated - just create response)
	result := MCPToolResult{
		Content: []MCPContent{{
			Type: "text",
			Text: fmt.Sprintf("Result from %s", toolName),
		}},
	}

	// 5. Marshal response
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      serverReq.ID,
		Result:  result,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	// 6. "Send" response back
	_ = respBytes

	// 7. Client unmarshals response
	var clientResp MCPResponse
	if err := json.Unmarshal(respBytes, &clientResp); err != nil {
		return nil, err
	}

	return respBytes, nil
}

// ============================================================================
// ZAP Tool Calling (unified zero-copy approach)
// ============================================================================

const (
	MsgTypeToolCall   uint16 = 10
	MsgTypeToolResult uint16 = 11

	// Field offsets for tool messages
	FieldToolID     = 0  // uint32 - tool identifier
	FieldToolNameLen = 4  // uint32 - tool name length
	FieldToolName   = 8  // bytes - tool name (up to 32 bytes)
	FieldArgCount   = 40 // uint32 - number of arguments
	FieldResultLen  = 44 // uint32 - result length
	FieldResult     = 48 // bytes - result data
)

// simulateZAPToolCall simulates ZAP tool calling with zero-copy
func simulateZAPToolCall(toolID uint32, toolName string) ([]byte, error) {
	// 1. Build request (zero-copy, no JSON)
	b := NewBuilder(128)
	obj := b.StartObject(64)
	obj.SetUint32(FieldToolID, toolID)
	obj.SetUint32(FieldToolNameLen, uint32(len(toolName)))
	for i := 0; i < len(toolName) && i < 32; i++ {
		obj.SetUint8(FieldToolName+i, toolName[i])
	}
	obj.SetUint32(FieldArgCount, 2) // 2 args
	obj.FinishAsRoot()
	reqData := b.FinishWithFlags(MsgTypeToolCall << 8)

	// 2. "Send" over network (simulated)
	_ = reqData

	// 3. Parse on server (zero-copy - just pointer arithmetic)
	msg, err := Parse(reqData)
	if err != nil {
		return nil, err
	}
	root := msg.Root()
	_ = root.Uint32(FieldToolID)
	nameLen := root.Uint32(FieldToolNameLen)
	_ = nameLen

	// 4. Build response (zero-copy)
	rb := NewBuilder(128)
	robj := rb.StartObject(64)
	robj.SetUint32(FieldToolID, toolID)
	resultStr := "Result from tool"
	robj.SetUint32(FieldResultLen, uint32(len(resultStr)))
	for i := 0; i < len(resultStr); i++ {
		robj.SetUint8(FieldResult+i, resultStr[i])
	}
	robj.FinishAsRoot()
	respData := rb.FinishWithFlags(MsgTypeToolResult << 8)

	// 5. "Send" response back
	_ = respData

	// 6. Parse response (zero-copy)
	respMsg, err := Parse(respData)
	if err != nil {
		return nil, err
	}
	_ = respMsg.Root().Uint32(FieldToolID)

	return respData, nil
}

// ============================================================================
// Benchmarks
// ============================================================================

// BenchmarkMCPToolCall benchmarks traditional MCP JSON-RPC tool calling
func BenchmarkMCPToolCall(b *testing.B) {
	args := map[string]string{
		"query": "test query",
		"limit": "10",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := simulateMCPToolCall("search_tool", args)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkZAPToolCall benchmarks ZAP zero-copy tool calling
func BenchmarkZAPToolCall(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := simulateZAPToolCall(1, "search_tool")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMCPOrchestrator simulates orchestrator calling 20 MCP tools
func BenchmarkMCPOrchestrator20Tools(b *testing.B) {
	tools := make([]string, 20)
	for i := 0; i < 20; i++ {
		tools[i] = fmt.Sprintf("tool_%d", i)
	}
	args := map[string]string{"input": "test"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, tool := range tools {
			_, err := simulateMCPToolCall(tool, args)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkZAPOrchestrator simulates orchestrator calling 20 ZAP tools
func BenchmarkZAPOrchestrator20Tools(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 20; j++ {
			_, err := simulateZAPToolCall(uint32(j), fmt.Sprintf("tool_%d", j))
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// ============================================================================
// Real Network Comparison Test
// ============================================================================

// TestAgenticWorkflow compares MCP vs ZAP in a realistic agentic scenario
func TestAgenticWorkflow(t *testing.T) {
	const numTools = 20
	const numCalls = 100

	// ========== MCP-style (simulated, no real network) ==========
	t.Log("=== MCP-style Tool Calling (JSON-RPC) ===")
	mcpStart := time.Now()
	mcpOps := int64(0)

	for i := 0; i < numCalls; i++ {
		for j := 0; j < numTools; j++ {
			_, err := simulateMCPToolCall(fmt.Sprintf("tool_%d", j), map[string]string{"input": "test"})
			if err != nil {
				t.Fatal(err)
			}
			mcpOps++
		}
	}
	mcpDuration := time.Since(mcpStart)
	t.Logf("MCP: %d tool calls in %v (%.0f calls/sec)", mcpOps, mcpDuration, float64(mcpOps)/mcpDuration.Seconds())

	// ========== ZAP-style (simulated, no real network) ==========
	t.Log("\n=== ZAP-style Tool Calling (Zero-copy) ===")
	zapStart := time.Now()
	zapOps := int64(0)

	for i := 0; i < numCalls; i++ {
		for j := 0; j < numTools; j++ {
			_, err := simulateZAPToolCall(uint32(j), fmt.Sprintf("tool_%d", j))
			if err != nil {
				t.Fatal(err)
			}
			zapOps++
		}
	}
	zapDuration := time.Since(zapStart)
	t.Logf("ZAP: %d tool calls in %v (%.0f calls/sec)", zapOps, zapDuration, float64(zapOps)/zapDuration.Seconds())

	// ========== Real ZAP Network Test ==========
	t.Log("\n=== ZAP Real Network (20 Tool Servers) ===")

	// Create 20 tool servers + 1 orchestrator
	nodes := make([]*Node, numTools+1)
	basePort := 20000

	for i := 0; i <= numTools; i++ {
		nodes[i] = NewNode(NodeConfig{
			NodeID:      fmt.Sprintf("node-%d", i),
			ServiceType: "_tools._tcp",
			Port:        basePort + i,
			NoDiscovery: true,
		})
	}

	// Tool handler - responds immediately
	toolHandler := func(ctx context.Context, from string, msg *Message) (*Message, error) {
		root := msg.Root()
		toolID := root.Uint32(FieldToolID)

		rb := NewBuilder(128)
		robj := rb.StartObject(64)
		robj.SetUint32(FieldToolID, toolID)
		robj.SetUint32(FieldResultLen, 16)
		robj.FinishAsRoot()

		resp, _ := Parse(rb.FinishWithFlags(MsgTypeToolResult << 8))
		return resp, nil
	}

	// Register handlers on tool servers (nodes 1-20)
	for i := 1; i <= numTools; i++ {
		nodes[i].Handle(MsgTypeToolCall, toolHandler)
	}

	// Start all nodes
	for i, node := range nodes {
		if err := node.Start(); err != nil {
			t.Fatalf("Failed to start node %d: %v", i, err)
		}
		defer node.Stop()
	}

	time.Sleep(50 * time.Millisecond)

	// Orchestrator (node 0) connects to all tool servers
	orchestrator := nodes[0]
	for i := 1; i <= numTools; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", basePort+i)
		if err := orchestrator.ConnectDirect(addr); err != nil {
			t.Fatalf("Failed to connect to tool %d: %v", i, err)
		}
	}

	time.Sleep(50 * time.Millisecond)
	t.Logf("Orchestrator connected to %d tool servers", len(orchestrator.Peers()))

	// Benchmark: Orchestrator calls all 20 tools (sequential to each tool, parallel across tools)
	var totalCalls atomic.Int64
	netStart := time.Now()
	ctx := context.Background()

	// Pre-build all messages
	msgs := make([]*Message, numTools+1)
	for i := 1; i <= numTools; i++ {
		b := NewBuilder(128)
		obj := b.StartObject(64)
		obj.SetUint32(FieldToolID, uint32(i))
		obj.SetUint32(FieldToolNameLen, 8)
		obj.FinishAsRoot()
		msgs[i], _ = Parse(b.FinishWithFlags(MsgTypeToolCall << 8))
	}

	// Each tool gets its own goroutine to handle sequential calls
	var wg sync.WaitGroup
	for toolNum := 1; toolNum <= numTools; toolNum++ {
		wg.Add(1)
		go func(toolID int) {
			defer wg.Done()
			peerID := fmt.Sprintf("node-%d", toolID)
			for round := 0; round < numCalls; round++ {
				_, err := orchestrator.Call(ctx, peerID, msgs[toolID])
				if err != nil {
					return
				}
				totalCalls.Add(1)
			}
		}(toolNum)
	}
	wg.Wait()

	netDuration := time.Since(netStart)
	t.Logf("ZAP Network: %d tool calls in %v (%.0f calls/sec)",
		totalCalls.Load(), netDuration, float64(totalCalls.Load())/netDuration.Seconds())

	// Summary
	t.Log("\n=== Performance Summary ===")
	t.Logf("MCP JSON-RPC:  %.0f calls/sec", float64(mcpOps)/mcpDuration.Seconds())
	t.Logf("ZAP Zero-copy: %.0f calls/sec (simulated)", float64(zapOps)/zapDuration.Seconds())
	t.Logf("ZAP Network:   %.0f calls/sec (real TCP)", float64(totalCalls.Load())/netDuration.Seconds())

	speedup := (float64(zapOps) / zapDuration.Seconds()) / (float64(mcpOps) / mcpDuration.Seconds())
	t.Logf("\nZAP is %.1fx faster than MCP for serialization", speedup)
}
