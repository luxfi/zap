// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/luxfi/zap"
)

// buildToolCallMessage builds a valid ZAP message representing an MCP tool call.
// The message has: toolID (uint32 at 0), toolName (64 bytes at 4), argsLen (uint32 at 68), args (bytes at 72).
func buildToolCallMessage(toolID uint32, toolName string, args map[string]interface{}) []byte {
	b := zap.NewBuilder(4096)

	// We need enough space: 72 (fixed fields before args) + argsJSON length
	argsJSON, _ := json.Marshal(args)
	objSize := FieldArgs + len(argsJSON)
	// Align to 8
	objSize = (objSize + 7) &^ 7

	ob := b.StartObject(objSize)
	ob.SetUint32(FieldToolID, toolID)

	// Write tool name as fixed 64-byte field
	nameBytes := []byte(toolName)
	for i := 0; i < 64 && i < len(nameBytes); i++ {
		ob.SetUint8(FieldToolName+i, nameBytes[i])
	}

	// Write args length and args bytes
	ob.SetUint32(FieldArgsLen, uint32(len(argsJSON)))
	for i, c := range argsJSON {
		ob.SetUint8(FieldArgs+i, c)
	}
	ob.FinishAsRoot()

	return b.Finish()
}

// buildToolResultMessage builds a valid ZAP message representing an MCP tool result.
// The message has: resultLen (uint32 at 0), resultData (bytes at 4).
func buildToolResultMessage(result interface{}) []byte {
	b := zap.NewBuilder(4096)

	resultJSON, _ := json.Marshal(result)
	objSize := FieldResultData + len(resultJSON)
	objSize = (objSize + 7) &^ 7

	ob := b.StartObject(objSize)
	ob.SetUint32(FieldResultLen, uint32(len(resultJSON)))
	for i, c := range resultJSON {
		ob.SetUint8(FieldResultData+i, c)
	}
	ob.FinishAsRoot()

	return b.Finish()
}

// FuzzMCPBridgeToolCall parses arbitrary bytes as a ZAP-encoded MCP tool call
// message. Extracts toolID, toolName, and args JSON exactly as handleToolCall
// does. Must never panic.
func FuzzMCPBridgeToolCall(f *testing.F) {
	// Seed 1: valid tool call
	f.Add(buildToolCallMessage(1, "read_file", map[string]interface{}{
		"path": "/tmp/test.txt",
	}))

	// Seed 2: tool call by name only (ID=0)
	f.Add(buildToolCallMessage(0, "search", map[string]interface{}{
		"query": "hello world",
		"limit": 10,
	}))

	// Seed 3: empty args
	f.Add(buildToolCallMessage(42, "list_tools", map[string]interface{}{}))

	// Seed 4: long tool name (truncated to 64 bytes by builder)
	f.Add(buildToolCallMessage(99, "this_is_a_very_long_tool_name_that_exceeds_the_64_byte_fixed_field_limit_in_the_protocol", map[string]interface{}{
		"a": "b",
	}))

	// Seed 5: empty bytes
	f.Add([]byte{})

	// Seed 6: just a header
	header := make([]byte, zap.HeaderSize)
	copy(header[0:4], zap.Magic)
	binary.LittleEndian.PutUint16(header[4:6], zap.Version)
	binary.LittleEndian.PutUint32(header[12:16], zap.HeaderSize)
	f.Add(header)

	// Seed 7: nested JSON args with special characters
	f.Add(buildToolCallMessage(5, "exec", map[string]interface{}{
		"cmd":   "echo 'hello\"world'",
		"args":  []string{"--flag", "-v"},
		"env":   map[string]interface{}{"PATH": "/usr/bin"},
		"empty": nil,
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := zap.Parse(data)
		if err != nil {
			return // invalid ZAP message, that's fine
		}

		root := msg.Root()

		// Extract tool ID -- same as handleToolCall
		toolID := root.Uint32(FieldToolID)
		_ = toolID

		// Extract tool name from fixed 64-byte field
		nameBytes := make([]byte, 64)
		var toolName string
		for i := 0; i < 64; i++ {
			c := root.Uint8(FieldToolName + i)
			if c == 0 {
				toolName = string(nameBytes[:i])
				break
			}
			nameBytes[i] = c
		}
		if toolName == "" && nameBytes[0] != 0 {
			toolName = string(nameBytes)
		}
		_ = toolName

		// Extract args JSON
		argsLen := root.Uint32(FieldArgsLen)

		// Cap to prevent OOM -- real handler would also need this
		if argsLen > 1<<20 {
			argsLen = 1 << 20
		}

		argsBytes := make([]byte, argsLen)
		for i := uint32(0); i < argsLen; i++ {
			argsBytes[i] = root.Uint8(int(FieldArgs + int(i)))
		}

		// Attempt JSON parse -- errors are fine, panics are not
		var args map[string]interface{}
		_ = json.Unmarshal(argsBytes, &args)
	})
}

// FuzzMCPBridgeToolResult parses arbitrary bytes as a ZAP-encoded MCP tool
// result message. Extracts resultLen and resultData exactly as the bridge
// protocol defines. Must never panic.
func FuzzMCPBridgeToolResult(f *testing.F) {
	// Seed 1: simple string result
	f.Add(buildToolResultMessage("file contents here"))

	// Seed 2: structured result
	f.Add(buildToolResultMessage(map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": "result data"},
		},
		"isError": false,
	}))

	// Seed 3: error result
	f.Add(buildToolResultMessage(map[string]interface{}{
		"error": "tool execution failed",
	}))

	// Seed 4: empty result
	f.Add(buildToolResultMessage(nil))

	// Seed 5: large result
	bigData := make([]byte, 4000)
	for i := range bigData {
		bigData[i] = byte(i % 256)
	}
	f.Add(buildToolResultMessage(string(bigData)))

	// Seed 6: empty bytes
	f.Add([]byte{})

	// Seed 7: just a header
	header := make([]byte, zap.HeaderSize)
	copy(header[0:4], zap.Magic)
	binary.LittleEndian.PutUint16(header[4:6], zap.Version)
	binary.LittleEndian.PutUint32(header[12:16], zap.HeaderSize)
	f.Add(header)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := zap.Parse(data)
		if err != nil {
			return
		}

		root := msg.Root()

		// Extract result length
		resultLen := root.Uint32(FieldResultLen)

		// Cap to prevent OOM
		if resultLen > 1<<20 {
			resultLen = 1 << 20
		}

		// Extract result data byte-by-byte, same as handleToolCall response pattern
		resultBytes := make([]byte, resultLen)
		for i := uint32(0); i < resultLen; i++ {
			resultBytes[i] = root.Uint8(int(FieldResultData + int(i)))
		}

		// Attempt JSON parse
		var result interface{}
		_ = json.Unmarshal(resultBytes, &result)

		// Also try as string
		_ = string(resultBytes)

		// Verify the message flags accessor doesn't panic
		_ = msg.Flags()
	})
}
