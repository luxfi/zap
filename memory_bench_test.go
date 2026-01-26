// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
)

// ============================================================================
// Real Memory Usage Profiling
// ============================================================================

func getMemStats() runtime.MemStats {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// TestMemoryUsageComparison shows real heap memory differences
func TestMemoryUsageComparison(t *testing.T) {
	const numOps = 100000

	t.Log("=== Real Memory Usage Comparison ===")
	t.Log("Simulating 100,000 tool call round-trips\n")

	// ========== MCP-style Memory Usage ==========
	t.Log("--- MCP JSON-RPC Style ---")
	runtime.GC()
	runtime.GC()
	beforeMCP := getMemStats()

	// Simulate MCP tool calls (keep some data alive to measure heap)
	mcpResults := make([][]byte, 0, numOps)
	for i := 0; i < numOps; i++ {
		result, _ := simulateMCPToolCall("search_tool", map[string]string{
			"query": "test query",
			"limit": "10",
		})
		if i%10 == 0 { // Keep 10% of results to simulate real usage
			mcpResults = append(mcpResults, result)
		}
	}

	afterMCP := getMemStats()
	mcpHeapAlloc := afterMCP.TotalAlloc - beforeMCP.TotalAlloc
	mcpHeapInUse := afterMCP.HeapInuse - beforeMCP.HeapInuse
	mcpMallocs := afterMCP.Mallocs - beforeMCP.Mallocs

	t.Logf("Total Allocated: %s", formatBytes(mcpHeapAlloc))
	t.Logf("Heap In Use:     %s", formatBytes(mcpHeapInUse))
	t.Logf("Malloc Count:    %d", mcpMallocs)
	t.Logf("Bytes/Op:        %d", mcpHeapAlloc/numOps)
	t.Logf("Mallocs/Op:      %d", mcpMallocs/numOps)

	// Clear MCP results
	mcpResults = nil
	runtime.GC()
	runtime.GC()

	// ========== ZAP-style Memory Usage ==========
	t.Log("\n--- ZAP Zero-Copy Style ---")
	runtime.GC()
	runtime.GC()
	beforeZAP := getMemStats()

	// Simulate ZAP tool calls
	zapResults := make([][]byte, 0, numOps)
	for i := 0; i < numOps; i++ {
		result, _ := simulateZAPToolCall(uint32(i), "search_tool")
		if i%10 == 0 { // Keep 10% of results
			zapResults = append(zapResults, result)
		}
	}

	afterZAP := getMemStats()
	zapHeapAlloc := afterZAP.TotalAlloc - beforeZAP.TotalAlloc
	zapHeapInUse := afterZAP.HeapInuse - beforeZAP.HeapInuse
	zapMallocs := afterZAP.Mallocs - beforeZAP.Mallocs

	t.Logf("Total Allocated: %s", formatBytes(zapHeapAlloc))
	t.Logf("Heap In Use:     %s", formatBytes(zapHeapInUse))
	t.Logf("Malloc Count:    %d", zapMallocs)
	t.Logf("Bytes/Op:        %d", zapHeapAlloc/numOps)
	t.Logf("Mallocs/Op:      %d", zapMallocs/numOps)

	// Clear ZAP results
	zapResults = nil

	// ========== Summary ==========
	t.Log("\n=== Efficiency Summary ===")
	memSavings := float64(mcpHeapAlloc-zapHeapAlloc) / float64(mcpHeapAlloc) * 100
	mallocSavings := float64(mcpMallocs-zapMallocs) / float64(mcpMallocs) * 100

	t.Logf("Memory Saved:     %s (%.1f%%)", formatBytes(mcpHeapAlloc-zapHeapAlloc), memSavings)
	t.Logf("Allocations Saved: %d (%.1f%%)", mcpMallocs-zapMallocs, mallocSavings)
	t.Logf("Memory Ratio:     %.1fx less", float64(mcpHeapAlloc)/float64(zapHeapAlloc))
	t.Logf("Malloc Ratio:     %.1fx fewer", float64(mcpMallocs)/float64(zapMallocs))

	// Energy/Carbon estimate (rough: 1 GB memory = ~0.5W, allocations cause cache misses)
	t.Log("\n=== Environmental Impact (per 1M ops) ===")
	mcpMemMB := float64(mcpHeapAlloc) * 10 / 1024 / 1024 // Scale to 1M ops
	zapMemMB := float64(zapHeapAlloc) * 10 / 1024 / 1024
	t.Logf("MCP Memory Footprint:  %.1f MB", mcpMemMB)
	t.Logf("ZAP Memory Footprint:  %.1f MB", zapMemMB)
	t.Logf("Memory Saved per 1M:   %.1f MB", mcpMemMB-zapMemMB)

	// Rough energy estimate: memory bandwidth + allocation overhead
	// ~0.1 nJ per byte transferred, ~100 nJ per malloc (cache miss + syscall amortized)
	mcpEnergyJ := (float64(mcpHeapAlloc)*0.1 + float64(mcpMallocs)*100) * 10 / 1e9
	zapEnergyJ := (float64(zapHeapAlloc)*0.1 + float64(zapMallocs)*100) * 10 / 1e9
	t.Logf("MCP Energy (est):      %.3f J per 1M ops", mcpEnergyJ)
	t.Logf("ZAP Energy (est):      %.3f J per 1M ops", zapEnergyJ)
	t.Logf("Energy Saved:          %.1f%% reduction", (mcpEnergyJ-zapEnergyJ)/mcpEnergyJ*100)

	// At scale
	t.Log("\n=== At Scale (1B ops/day - typical AI agent cluster) ===")
	dailyOps := 1e9
	mcpDailyMem := mcpMemMB * dailyOps / 1e6 / 1024 // GB
	zapDailyMem := zapMemMB * dailyOps / 1e6 / 1024
	mcpDailyEnergy := mcpEnergyJ * dailyOps / 1e6 / 3600 // kWh
	zapDailyEnergy := zapEnergyJ * dailyOps / 1e6 / 3600
	co2PerKwh := 0.4 // kg CO2 per kWh (global average)

	t.Logf("MCP Daily Memory:      %.1f TB throughput", mcpDailyMem/1024)
	t.Logf("ZAP Daily Memory:      %.1f TB throughput", zapDailyMem/1024)
	t.Logf("Memory Saved Daily:    %.1f TB", (mcpDailyMem-zapDailyMem)/1024)
	t.Logf("MCP Daily Energy:      %.1f kWh", mcpDailyEnergy)
	t.Logf("ZAP Daily Energy:      %.1f kWh", zapDailyEnergy)
	t.Logf("Energy Saved Daily:    %.1f kWh (%.1f%%)", mcpDailyEnergy-zapDailyEnergy, (mcpDailyEnergy-zapDailyEnergy)/mcpDailyEnergy*100)
	t.Logf("CO2 Saved Daily:       %.1f kg", (mcpDailyEnergy-zapDailyEnergy)*co2PerKwh)
	t.Logf("CO2 Saved Yearly:      %.1f tonnes", (mcpDailyEnergy-zapDailyEnergy)*co2PerKwh*365/1000)
}

// TestGCPressure measures garbage collection impact
func TestGCPressure(t *testing.T) {
	const numOps = 50000

	t.Log("=== GC Pressure Comparison ===\n")

	// MCP GC pressure
	runtime.GC()
	var mcpGCStats runtime.MemStats
	runtime.ReadMemStats(&mcpGCStats)
	mcpGCBefore := mcpGCStats.NumGC

	for i := 0; i < numOps; i++ {
		simulateMCPToolCall("tool", map[string]string{"k": "v"})
	}

	runtime.ReadMemStats(&mcpGCStats)
	mcpGCAfter := mcpGCStats.NumGC
	mcpGCRuns := mcpGCAfter - mcpGCBefore

	t.Logf("MCP: %d GC runs for %d ops (1 GC per %d ops)", mcpGCRuns, numOps, numOps/max(mcpGCRuns, 1))

	// ZAP GC pressure
	runtime.GC()
	var zapGCStats runtime.MemStats
	runtime.ReadMemStats(&zapGCStats)
	zapGCBefore := zapGCStats.NumGC

	for i := 0; i < numOps; i++ {
		simulateZAPToolCall(uint32(i), "tool")
	}

	runtime.ReadMemStats(&zapGCStats)
	zapGCAfter := zapGCStats.NumGC
	zapGCRuns := zapGCAfter - zapGCBefore

	t.Logf("ZAP: %d GC runs for %d ops (1 GC per %d ops)", zapGCRuns, numOps, numOps/max(zapGCRuns, 1))

	if mcpGCRuns > 0 {
		t.Logf("\nZAP reduces GC pressure by %.1fx", float64(mcpGCRuns)/float64(max(zapGCRuns, 1)))
	}
}

// TestRealisticAgentWorkload simulates a real agent doing tool calls
func TestRealisticAgentWorkload(t *testing.T) {
	t.Log("=== Realistic Agent Workload ===")
	t.Log("Simulating agent making 1000 tool calls with mixed payloads\n")

	tools := []struct {
		name string
		args map[string]string
	}{
		{"search", map[string]string{"query": "find all users", "limit": "100"}},
		{"read_file", map[string]string{"path": "/etc/config.json"}},
		{"write_file", map[string]string{"path": "/tmp/out.txt", "content": "data"}},
		{"http_get", map[string]string{"url": "https://api.example.com/data"}},
		{"database_query", map[string]string{"sql": "SELECT * FROM users WHERE active=true"}},
		{"shell_exec", map[string]string{"cmd": "ls -la /var/log"}},
		{"image_analyze", map[string]string{"path": "/tmp/img.png", "model": "gpt-4-vision"}},
		{"vector_search", map[string]string{"query": "semantic search", "k": "10"}},
		{"code_complete", map[string]string{"prefix": "func main() {", "lang": "go"}},
		{"translate", map[string]string{"text": "Hello world", "to": "es"}},
	}

	const iterations = 1000

	// MCP workload
	runtime.GC()
	mcpBefore := getMemStats()

	for i := 0; i < iterations; i++ {
		tool := tools[i%len(tools)]
		simulateMCPToolCall(tool.name, tool.args)
	}

	mcpAfter := getMemStats()

	// ZAP workload
	runtime.GC()
	zapBefore := getMemStats()

	for i := 0; i < iterations; i++ {
		tool := tools[i%len(tools)]
		_ = tool // ZAP uses numeric IDs
		simulateZAPToolCall(uint32(i%len(tools)), tools[i%len(tools)].name)
	}

	zapAfter := getMemStats()

	t.Logf("MCP: %s allocated, %d mallocs",
		formatBytes(mcpAfter.TotalAlloc-mcpBefore.TotalAlloc),
		mcpAfter.Mallocs-mcpBefore.Mallocs)
	t.Logf("ZAP: %s allocated, %d mallocs",
		formatBytes(zapAfter.TotalAlloc-zapBefore.TotalAlloc),
		zapAfter.Mallocs-zapBefore.Mallocs)

	memRatio := float64(mcpAfter.TotalAlloc-mcpBefore.TotalAlloc) / float64(zapAfter.TotalAlloc-zapBefore.TotalAlloc)
	t.Logf("\nZAP uses %.1fx less memory for realistic agent workload", memRatio)
}

// Helper for simulateMCPToolCall - make sure it allocates like real MCP
func simulateMCPToolCallRealistic(toolName string, args map[string]interface{}) ([]byte, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      toolName,
			"arguments": args,
		},
	}

	// Full JSON round-trip
	reqBytes, _ := json.Marshal(req)
	var serverReq map[string]interface{}
	json.Unmarshal(reqBytes, &serverReq)

	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"content": []map[string]string{
				{"type": "text", "text": "Result from " + toolName},
			},
		},
	}

	respBytes, _ := json.Marshal(resp)
	var clientResp map[string]interface{}
	json.Unmarshal(respBytes, &clientResp)

	return respBytes, nil
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
