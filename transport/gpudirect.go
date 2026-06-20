// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

// gpudirect.go is the cross-platform doc comment for the NVIDIA
// GPUDirect RDMA transport. The factory lives in:
//
//	gpudirect_linux_real.go — //go:build cgo && linux && gpudirect && cuda
//	    Real ibverbs + nvidia-peermem probe, DMA-buf MR registration.
//	gpudirect_linux.go      — //go:build cgo && linux && !(gpudirect && cuda)
//	    Clean "not available" when the tags aren't set.
//	gpudirect_other.go      — //go:build !cgo || !linux
//	    Clean "not available" off-Linux or without cgo.
//
// Hardware prerequisites (probed at construction; missing prereqs cause
// a clean fall-through to the next-best transport):
//
//   - NVIDIA GPU with GPUDirect RDMA support (Hopper, Ada, Ampere; GB10
//     does NOT have GPUDirect RDMA — falls through to UMA, which is fine
//     because GB10 has UMA at the chip level via NVLink-C2C).
//   - Mellanox / NVIDIA ConnectX-6+ HCA. Required for IBV_DEVICE_RAW_
//     PACKET, which is the gate for putting the NIC into raw mode.
//   - Linux kernel with nvidia_peermem module loaded (`modprobe
//     nvidia-peermem`). Without this, ibv_reg_dmabuf_mr will fail.
//   - libibverbs userspace (`apt install libibverbs-dev` on Ubuntu).
//
// Reference architecture: NVIDIA DOCA GPUNetIO + Holoscan transport.
// Packets DMA from NIC into VRAM, GPU kernel parses ZAP header in place,
// CPU is never touched on the receive path.
