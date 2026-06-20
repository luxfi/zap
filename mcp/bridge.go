// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mcp provides a bridge between MCP (Model Context Protocol) servers
// and ZAP for high-performance tool calling.
//
// This bridge auto-discovers MCP servers and exposes their capabilities via ZAP,
// providing 10-30x performance improvement over native MCP JSON-RPC.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/luxfi/zap"
)

// Message types for MCP-ZAP bridge
const (
	MsgTypeToolList   uint16 = 100 // List available tools
	MsgTypeToolCall   uint16 = 101 // Call a tool
	MsgTypeToolResult uint16 = 102 // Tool result

	// Field offsets
	FieldToolCount  = 0  // uint32 - number of tools
	FieldToolID     = 0  // uint32 - tool ID
	FieldToolName   = 4  // 64 bytes - tool name
	FieldArgsLen    = 68 // uint32 - arguments JSON length
	FieldArgs       = 72 // bytes - arguments JSON
	FieldResultLen  = 0  // uint32 - result length
	FieldResultData = 4  // bytes - result data
)

// Tool represents an MCP tool capability
type Tool struct {
	ID          uint32                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// MCPServer represents a connection to an MCP server
type MCPServer struct {
	Name    string
	Command string
	Args    []string
	Tools   []Tool

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
	reqID  int
}

// Bridge manages multiple MCP servers and exposes them via ZAP
type Bridge struct {
	node    *zap.Node
	servers map[string]*MCPServer
	tools   map[uint32]*Tool      // toolID -> tool
	toolMCP map[uint32]*MCPServer // toolID -> server
	mu      sync.RWMutex
	nextID  uint32
}

// NewBridge creates a new MCP-ZAP bridge
func NewBridge(node *zap.Node) *Bridge {
	b := &Bridge{
		node:    node,
		servers: make(map[string]*MCPServer),
		tools:   make(map[uint32]*Tool),
		toolMCP: make(map[uint32]*MCPServer),
		nextID:  1,
	}

	// Register handlers
	node.Handle(MsgTypeToolList, b.handleToolList)
	node.Handle(MsgTypeToolCall, b.handleToolCall)

	return b
}

// AddServer adds and starts an MCP server
func (b *Bridge) AddServer(name, command string, args ...string) error {
	server := &MCPServer{
		Name:    name,
		Command: command,
		Args:    args,
	}

	// Start the MCP server process
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start MCP server %s: %w", name, err)
	}

	// Discover tools
	tools, err := server.ListTools()
	if err != nil {
		server.Stop()
		return fmt.Errorf("failed to list tools from %s: %w", name, err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Assign IDs and register tools
	for i := range tools {
		tools[i].ID = b.nextID
		b.nextID++
		b.tools[tools[i].ID] = &tools[i]
		b.toolMCP[tools[i].ID] = server
	}
	server.Tools = tools
	b.servers[name] = server

	return nil
}

// AddServerConfig adds a server from a config
func (b *Bridge) AddServerConfig(cfg ServerConfig) error {
	return b.AddServer(cfg.Name, cfg.Command, cfg.Args...)
}

// ServerConfig configures an MCP server
type ServerConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Env     []string `json:"env,omitempty"`
}

// GetTools returns all registered tools
func (b *Bridge) GetTools() []Tool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	tools := make([]Tool, 0, len(b.tools))
	for _, t := range b.tools {
		tools = append(tools, *t)
	}
	return tools
}

// CallTool calls a tool by ID
func (b *Bridge) CallTool(ctx context.Context, toolID uint32, args map[string]interface{}) (interface{}, error) {
	b.mu.RLock()
	tool, ok := b.tools[toolID]
	server := b.toolMCP[toolID]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("tool not found: %d", toolID)
	}

	return server.CallTool(tool.Name, args)
}

// CallToolByName calls a tool by name
func (b *Bridge) CallToolByName(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	b.mu.RLock()
	var tool *Tool
	var server *MCPServer
	for _, t := range b.tools {
		if t.Name == name {
			tool = t
			server = b.toolMCP[t.ID]
			break
		}
	}
	b.mu.RUnlock()

	if tool == nil {
		return nil, fmt.Errorf("tool not found: %s", name)
	}

	return server.CallTool(name, args)
}

// handleToolList returns all available tools
func (b *Bridge) handleToolList(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	tools := b.GetTools()

	// Build response with tool list
	builder := zap.NewBuilder(1024)
	obj := builder.StartObject(512)
	obj.SetUint32(FieldToolCount, uint32(len(tools)))

	// Encode tools as JSON in the message (for simplicity)
	toolsJSON, _ := json.Marshal(tools)
	for i, c := range toolsJSON {
		if i >= 500 {
			break
		}
		obj.SetUint8(4+i, c)
	}
	obj.FinishAsRoot()

	resp, _ := zap.Parse(builder.FinishWithFlags(MsgTypeToolList << 8))
	return resp, nil
}

// handleToolCall handles a tool call request
func (b *Bridge) handleToolCall(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	toolID := root.Uint32(FieldToolID)

	// Extract tool name
	var toolName string
	nameBytes := make([]byte, 64)
	for i := 0; i < 64; i++ {
		c := root.Uint8(FieldToolName + i)
		if c == 0 {
			toolName = string(nameBytes[:i])
			break
		}
		nameBytes[i] = c
	}

	// Extract args JSON
	argsLen := root.Uint32(FieldArgsLen)
	argsBytes := make([]byte, argsLen)
	for i := uint32(0); i < argsLen; i++ {
		argsBytes[i] = root.Uint8(int(FieldArgs + int(i)))
	}

	var args map[string]interface{}
	json.Unmarshal(argsBytes, &args)

	// Call the tool
	var result interface{}
	var err error
	if toolID > 0 {
		result, err = b.CallTool(ctx, toolID, args)
	} else {
		result, err = b.CallToolByName(ctx, toolName, args)
	}

	// Build response
	builder := zap.NewBuilder(4096)
	obj := builder.StartObject(4000)

	if err != nil {
		errStr := err.Error()
		obj.SetUint32(FieldResultLen, uint32(len(errStr)))
		for i, c := range []byte(errStr) {
			obj.SetUint8(FieldResultData+i, c)
		}
	} else {
		resultJSON, _ := json.Marshal(result)
		obj.SetUint32(FieldResultLen, uint32(len(resultJSON)))
		for i, c := range resultJSON {
			if i >= 3900 {
				break
			}
			obj.SetUint8(FieldResultData+i, c)
		}
	}
	obj.FinishAsRoot()

	resp, _ := zap.Parse(builder.FinishWithFlags(MsgTypeToolResult << 8))
	return resp, nil
}

// Stop stops all MCP servers
func (b *Bridge) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, server := range b.servers {
		server.Stop()
	}
}

// ============================================================================
// MCP Server Process Management
// ============================================================================

// Start starts the MCP server process
func (s *MCPServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cmd = exec.Command(s.Command, s.Args...)
	s.cmd.Stderr = os.Stderr

	var err error
	s.stdin, err = s.cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	s.stdout = bufio.NewReader(stdout)

	if err := s.cmd.Start(); err != nil {
		return err
	}

	// Initialize MCP connection
	return s.initialize()
}

// Stop stops the MCP server process
func (s *MCPServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stdin != nil {
		s.stdin.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
}

// initialize performs MCP handshake
func (s *MCPServer) initialize() error {
	// Send initialize request
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      s.nextReqID(),
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "zap-mcp-bridge",
				"version": "1.0.0",
			},
		},
	}

	if _, err := s.call(req); err != nil {
		return err
	}

	// Send initialized notification
	notif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	return s.send(notif)
}

// ListTools discovers available tools from the MCP server
func (s *MCPServer) ListTools() ([]Tool, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      s.nextReqID(),
		"method":  "tools/list",
	}

	resp, err := s.call(req)
	if err != nil {
		return nil, err
	}

	result, ok := resp["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response")
	}

	toolsRaw, ok := result["tools"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("no tools in response")
	}

	tools := make([]Tool, len(toolsRaw))
	for i, t := range toolsRaw {
		tm := t.(map[string]interface{})
		tools[i] = Tool{
			Name:        tm["name"].(string),
			Description: getString(tm, "description"),
		}
		if schema, ok := tm["inputSchema"].(map[string]interface{}); ok {
			tools[i].InputSchema = schema
		}
	}

	return tools, nil
}

// CallTool calls a tool on the MCP server
func (s *MCPServer) CallTool(name string, args map[string]interface{}) (interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      s.nextReqID(),
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      name,
			"arguments": args,
		},
	}

	resp, err := s.call(req)
	if err != nil {
		return nil, err
	}

	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		return nil, fmt.Errorf("MCP error: %v", errObj["message"])
	}

	return resp["result"], nil
}

func (s *MCPServer) call(req map[string]interface{}) (map[string]interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.sendLocked(req); err != nil {
		return nil, err
	}

	return s.readLocked()
}

func (s *MCPServer) send(msg map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendLocked(msg)
}

func (s *MCPServer) sendLocked(msg map[string]interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(s.stdin, "%s\n", data)
	return err
}

func (s *MCPServer) readLocked() (map[string]interface{}, error) {
	line, err := s.stdout.ReadString('\n')
	if err != nil {
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *MCPServer) nextReqID() int {
	s.reqID++
	return s.reqID
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
