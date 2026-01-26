# ZAP

**Z**ero-copy **A**pplication **P**rotocol for Lux.

<p align="center">
  <img src="https://img.shields.io/badge/performance-17x_faster-brightgreen" alt="17x faster">
  <img src="https://img.shields.io/badge/memory-11x_less-blue" alt="11x less memory">
  <img src="https://img.shields.io/badge/allocations-29x_fewer-purple" alt="29x fewer allocations">
  <img src="https://img.shields.io/badge/GC_pressure-14x_lower-orange" alt="14x lower GC">
</p>

```go
import "github.com/luxfi/zap"
```

ZAP is a high-performance binary protocol for AI agent communication and inter-process messaging. It provides **17x faster serialization** and **11x less memory** than MCP JSON-RPC, while maintaining full compatibility with existing MCP tools.

## Features

- **Zero-copy reads** - Access data directly from byte buffers (2.9ns parse time)
- **Zero allocation** - No heap allocations during deserialization
- **MCP Bridge** - Auto-discover and accelerate existing MCP servers
- **mDNS Discovery** - Automatic peer discovery for distributed systems
- **Request/Response** - Built-in correlation for async RPC calls
- **Environmental** - 96% energy reduction vs JSON-RPC at scale

## Quick Start

```go
// Build a message
b := zap.NewBuilder(256)

ob := b.StartObject(24)
ob.SetUint32(0, 42)           // Field at offset 0
ob.SetUint64(8, 0xDEADBEEF)   // Field at offset 8
ob.SetBool(16, true)          // Field at offset 16
ob.FinishAsRoot()

data := b.Finish()  // Wire-ready bytes

// Read zero-copy
msg, _ := zap.Parse(data)
root := msg.Root()

fmt.Println(root.Uint32(0))   // 42
fmt.Println(root.Uint64(8))   // 0xDEADBEEF
fmt.Println(root.Bool(16))    // true
```

## Wire Format

```
┌─────────────────────────────────────────────────┐
│ Header (16 bytes)                               │
│  ├─ Magic (4 bytes): "ZAP\x00"                  │
│  ├─ Version (2 bytes): 1                        │
│  ├─ Flags (2 bytes): compression, etc.          │
│  ├─ Root Offset (4 bytes): offset to root       │
│  └─ Size (4 bytes): total message size          │
├─────────────────────────────────────────────────┤
│ Data Segment (variable)                         │
│  └─ Structs, lists, text, bytes...             │
└─────────────────────────────────────────────────┘
```

## Types

| Type | Size | Description |
|------|------|-------------|
| Bool | 1 | Boolean (0 or 1) |
| Int8/Uint8 | 1 | 8-bit integer |
| Int16/Uint16 | 2 | 16-bit integer |
| Int32/Uint32 | 4 | 32-bit integer |
| Int64/Uint64 | 8 | 64-bit integer |
| Float32 | 4 | IEEE 754 float |
| Float64 | 8 | IEEE 754 double |
| Text | 8 | String (offset + length) |
| Bytes | 8 | Byte slice (offset + length) |
| List | 8 | Array (offset + length) |
| Struct | 4 | Nested object (offset) |

## Lists

```go
// Build a list
lb := b.StartList(4)  // 4-byte elements
lb.AddUint32(100)
lb.AddUint32(200)
lb.AddUint32(300)
listOffset, listLen := lb.Finish()

// Reference from object
ob.SetList(fieldOffset, listOffset, listLen)

// Read
list := obj.List(fieldOffset)
for i := 0; i < list.Len(); i++ {
    fmt.Println(list.Uint32(i))
}
```

## Nested Objects

```go
// Build inner object
inner := b.StartObject(8)
inner.SetUint32(0, 111)
innerOffset := inner.Finish()

// Reference from outer
outer := b.StartObject(16)
outer.SetObject(4, innerOffset)
outer.FinishAsRoot()

// Read
innerObj := root.Object(4)
fmt.Println(innerObj.Uint32(0))  // 111
```

## Schema Definition

```go
schema := zap.NewSchema("myapp")

person := zap.NewStructBuilder("Person").
    Uint32("id").
    Text("name").
    Int32("age").
    Bool("active").
    List("tags", zap.TypeText).
    Build()

schema.AddStruct(person)

// Use generated offsets
const (
    PersonID     = 0
    PersonName   = 4
    PersonAge    = 12
    PersonActive = 16
    PersonTags   = 20
)
```

## Performance

### Core Operations
```
BenchmarkZAPParse-10          411944325     2.9 ns/op    0 B/op    0 allocs/op
BenchmarkZAPBuild-10           26375461    44.0 ns/op    0 B/op    0 allocs/op
BenchmarkConsensusRound-10    203780178     5.5 ns/op    0 B/op    0 allocs/op
```

### ZAP vs MCP JSON-RPC (Tool Calling)

| Metric | MCP JSON-RPC | ZAP | Improvement |
|--------|--------------|-----|-------------|
| **Serialization** | 5,579 ns/op | 322 ns/op | **17x faster** |
| **Memory/call** | 2,826 bytes | 256 bytes | **11x less** |
| **Allocations** | 58/op | 2/op | **29x fewer** |
| **Parse time** | ~1,000 ns | 2.9 ns | **345x faster** |
| **GC runs** | 41 per 50K ops | 3 per 50K ops | **14x less** |

### 20-Tool Orchestrator Benchmark
```
BenchmarkMCPOrchestrator20Tools    10000    109175 ns/op    54292 B/op    1060 allocs/op
BenchmarkZAPOrchestrator20Tools   150036      8195 ns/op     5282 B/op      60 allocs/op
```

### Real Network Performance
```
MCP JSON-RPC (simulated):  ~140,000 calls/sec
ZAP Zero-copy (simulated): ~4,200,000 calls/sec  (30x faster)
ZAP Network (real TCP):    ~34,000 calls/sec     (20 tool servers)
```

### Memory Profile (100K operations)
```
=== MCP JSON-RPC ===                 === ZAP Zero-Copy ===
Total Allocated: 304.01 MB           Total Allocated: 26.70 MB
Malloc Count:    6,001,513           Malloc Count:    200,003
Bytes/Op:        3,187               Bytes/Op:        280
Mallocs/Op:      60                  Mallocs/Op:      2

Memory Saved: 277.30 MB (91.2%)
Allocations Saved: 5,801,510 (96.7%)
```

## MCP Bridge

Auto-discover MCP servers and accelerate them with ZAP:

```go
import (
    "github.com/luxfi/zap"
    "github.com/luxfi/zap/mcp"
)

func main() {
    node := zap.NewNode(zap.NodeConfig{
        NodeID: "orchestrator",
        Port:   9000,
    })
    node.Start()

    // Create bridge - auto-discovers MCP server tools
    bridge := mcp.NewBridge(node)
    bridge.AddServer("filesystem", "npx", "-y", "@anthropic/mcp-filesystem")
    bridge.AddServer("github", "npx", "-y", "@anthropic/mcp-github")

    // List all discovered tools
    for _, tool := range bridge.GetTools() {
        fmt.Printf("[%d] %s - %s\n", tool.ID, tool.Name, tool.Description)
    }

    // Call tools (17x faster than native MCP)
    result, _ := bridge.CallToolByName(ctx, "read_file", map[string]interface{}{
        "path": "/etc/hosts",
    })
}
```

## Environmental Impact

At scale (1 billion tool calls/day):

| Metric | MCP JSON-RPC | ZAP | Savings |
|--------|--------------|-----|---------|
| Memory throughput | 2.9 TB/day | 0.3 TB/day | **2.6 TB/day** |
| Energy consumption | 1.8 kWh/day | 0.1 kWh/day | **96% reduction** |
| CO2 emissions | ~0.7 kg/day | ~0.03 kg/day | **~0.67 kg/day** |
| **Yearly CO2 savings** | - | - | **~245 kg** |

## Comparison

| Feature | ZAP | Cap'n Proto | FlatBuffers | Protobuf |
|---------|-----|-------------|-------------|----------|
| Zero-copy read | ✓ | ✓ | ✓ | ✗ |
| Schema required | ✗ | ✓ | ✓ | ✓ |
| Code generation | Optional | Required | Required | Required |
| Random access | ✓ | ✓ | ✓ | ✗ |
| Mutable | Build only | ✓ | ✗ | ✓ |

## EVM Types

Built-in support for Ethereum/EVM types:

```go
// Read EVM types zero-copy
addr := obj.Address(0)      // 20-byte address
hash := obj.Hash(20)        // 32-byte hash
sig := obj.Signature(52)    // 65-byte signature

// Build with EVM types
ob.SetAddress(0, addr)
ob.SetHash(20, hash)

// Parse from hex
addr, _ := zap.AddressFromHex("0x742d35Cc6634C0532925a3b844Bc9e7595f...")
hash, _ := zap.HashFromHex("0xabc123...")
```

Predefined schemas: `TransactionSchema`, `BlockHeaderSchema`, `LogSchema`

## Node Discovery

Auto-discover peers via mDNS and communicate with ZAP:

```go
node := zap.NewNode(zap.NodeConfig{
    NodeID:      "node-1",
    ServiceType: "_luxd._tcp",
    Port:        9651,
})

// Handle incoming messages
node.Handle(MsgTypePing, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
    // Process ping, return pong
    return buildPong(), nil
})

node.Start()
defer node.Stop()

// Send to peer
node.Send(ctx, "node-2", msg)

// Broadcast to all
node.Broadcast(ctx, msg)

// List peers
for _, peer := range node.Peers() {
    fmt.Println(peer)
}
```

## Use Cases

### AI Agent Orchestration
```go
// Orchestrator managing 20 tool servers
orchestrator := NewOrchestrator("agent", 9000)
for i := 1; i <= 20; i++ {
    orchestrator.ConnectToolServer(fmt.Sprintf("127.0.0.1:%d", 9000+i))
}

// Call tools with automatic routing
result, _ := orchestrator.CallTool(ctx, "search_code", args)
```

### GPU Cluster / FHE Kernel Communication
```go
// GPU nodes discovering each other via mDNS
gpuNode := zap.NewNode(zap.NodeConfig{
    NodeID:      "gpu-node-1",
    ServiceType: "_lux-gpu._tcp",
    Port:        7000,
})

// Handle FHE ciphertext operations
gpuNode.Handle(MsgTypeFHEOp, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
    root := msg.Root()
    opType := root.Uint32(0)          // Operation type
    ctLen := root.Uint32(4)           // Ciphertext length

    // Zero-copy access to ciphertext data
    // Process with GPU kernel...

    return buildResult(resultCiphertext), nil
})

// Cross-VM kernel-to-kernel communication
resp, _ := gpuNode.Call(ctx, "vm-fhe-2", encryptedPayload)
```

### VM-to-VM Communication (Lux Network)
```go
// Cross-VM calls for crypto operations
vmNode := zap.NewNode(zap.NodeConfig{
    NodeID:      "vm-evm-1",
    ServiceType: "_lux-vm._tcp",
    Port:        8545,
})

// Route messages between VMs
vmNode.Handle(MsgTypeCrossVM, func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
    // Zero-copy message routing
    return forwardToTargetVM(msg)
})
```

### High-Performance Consensus
```go
// 5-node consensus reaching agreement in ~450µs
nodes := make([]*ConsensusNode, 5)
for i := range nodes {
    nodes[i] = newConsensusNode(i, 19000+i)
    nodes[i].Start()
}

// Propose and reach consensus
nodes[0].propose(ctx, round, value)
// Consensus reached in ~0.45ms (local network)
```

## Running the Examples

```bash
# Run the 20-tool MCP bridge example
cd examples/mcp-bridge
go run main.go

# Run benchmarks
go test -bench=. -benchmem

# Run memory profiling
go test -v -run TestMemoryUsage
```

## License

Copyright (C) 2025, Lux Industries Inc. All rights reserved.
