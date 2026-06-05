// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

// uma.go is the cross-platform doc comment for the UMA transport. The
// real factory lives in:
//
//	uma_linux_cuda.go — //go:build cgo && linux && cuda
//	    Real cudaMallocManaged-backed slab pool.
//	uma_linux.go      — //go:build cgo && linux && !cuda
//	    Clean "not available" so Pick() falls through.
//	uma_darwin.go     — //go:build cgo && darwin
//	    Metal-backed UMA shim (hook for the Apple Silicon path).
//	uma_other.go      — //go:build !cgo || (!darwin && !linux)
//	    Clean "not available" for every other combo.
//
// What UMA means here: CPU and GPU share physical memory. Packet bytes
// land in shared RAM (cudaMallocManaged on Grace-Hopper / GB10, Metal-
// shared MTLBuffer on Apple Silicon). The GPU kernel parses the ZAP
// message in place. No memcpy from kernel space to GPU. This is the
// fast path on Lux validator nodes that ship with the GB10 or M3 Ultra
// hosts (per LP-203).
//
// Build matrix:
//   linux+cuda      → real UMA (lcudart, slab pool, GPU-resident Recv)
//   linux+!cuda     → not available (factory returns error)
//   darwin (cgo)    → metal hook (current state: stub, will land with M3 wire-up)
//   anything else   → not available
