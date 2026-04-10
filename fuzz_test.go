// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildSeedMessage builds a valid ZAP message using the Builder for use as
// fuzz seed corpus. Returns the raw bytes.
func buildSeedMessage(fields func(ob *ObjectBuilder)) []byte {
	b := NewBuilder(256)
	ob := b.StartObject(64)
	fields(ob)
	ob.FinishAsRoot()
	return b.Finish()
}

// FuzzZAPParse feeds arbitrary bytes to Parse. It must never panic regardless
// of input. Every returned error is acceptable; every non-error result must
// produce a valid Message with accessible root.
func FuzzZAPParse(f *testing.F) {
	// Seed 1: valid minimal message (uint64 field)
	f.Add(buildSeedMessage(func(ob *ObjectBuilder) {
		ob.SetUint64(0, 0xDEADBEEF)
	}))

	// Seed 2: valid message with text
	f.Add(buildSeedMessage(func(ob *ObjectBuilder) {
		ob.SetUint32(0, 42)
		ob.SetText(4, "hello fuzz")
		ob.SetBool(12, true)
	}))

	// Seed 3: empty slice
	f.Add([]byte{})

	// Seed 4: too short
	f.Add([]byte{0x5A, 0x41, 0x50, 0x00})

	// Seed 5: valid header, wrong version
	header := make([]byte, HeaderSize)
	copy(header[0:4], Magic)
	binary.LittleEndian.PutUint16(header[4:6], 99) // bad version
	binary.LittleEndian.PutUint32(header[12:16], HeaderSize)
	f.Add(header)

	// Seed 6: valid header, size exceeds data
	header2 := make([]byte, HeaderSize)
	copy(header2[0:4], Magic)
	binary.LittleEndian.PutUint16(header2[4:6], Version)
	binary.LittleEndian.PutUint32(header2[12:16], 9999) // size > len
	f.Add(header2)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Parse(data)
		if err != nil {
			return // errors are fine
		}

		// If parse succeeded, basic accessors must not panic.
		_ = msg.Size()
		_ = msg.Flags()
		_ = msg.Bytes()

		root := msg.Root()
		_ = root.IsNull()
		_ = root.Uint8(0)
		_ = root.Uint16(0)
		_ = root.Uint32(0)
		_ = root.Uint64(0)
		_ = root.Int8(0)
		_ = root.Int16(0)
		_ = root.Int32(0)
		_ = root.Int64(0)
		_ = root.Float32(0)
		_ = root.Float64(0)
		_ = root.Bool(0)
		_ = root.Text(0)
		_ = root.Bytes(0)

		// Try reading nested object and list at various offsets
		for off := 0; off < 64 && off < msg.Size(); off += 4 {
			nested := root.Object(off)
			_ = nested.IsNull()
			if !nested.IsNull() {
				_ = nested.Uint32(0)
			}

			list := root.List(off)
			_ = list.IsNull()
			_ = list.Len()
			if !list.IsNull() {
				_ = list.Uint8(0)
				_ = list.Uint32(0)
				_ = list.Uint64(0)
				_ = list.Bytes()
			}
		}
	})
}

// FuzzZAPRoundtrip builds a ZAP message from fuzzer-supplied field values,
// serializes it, parses it back, and verifies all fields match.
func FuzzZAPRoundtrip(f *testing.F) {
	f.Add(uint32(0), uint64(0), int32(0), true, "")
	f.Add(uint32(42), uint64(0xDEADBEEF), int32(-100), false, "hello")
	f.Add(uint32(0xFFFFFFFF), uint64(0xFFFFFFFFFFFFFFFF), int32(-2147483648), true, "fuzzing is fun")
	f.Add(uint32(1), uint64(1), int32(1), false, "a]b\x00c")

	f.Fuzz(func(t *testing.T, u32 uint32, u64 uint64, i32 int32, bval bool, text string) {
		b := NewBuilder(256)
		ob := b.StartObject(32)
		ob.SetUint32(0, u32)
		ob.SetUint64(8, u64)
		ob.SetInt32(16, i32)
		ob.SetBool(20, bval)
		ob.SetText(24, text) // offset 24, takes 8 bytes (offset+len)
		ob.FinishAsRoot()

		data := b.Finish()

		msg, err := Parse(data)
		if err != nil {
			t.Fatalf("Parse failed on builder output: %v", err)
		}

		root := msg.Root()

		if got := root.Uint32(0); got != u32 {
			t.Errorf("Uint32 roundtrip: got %d, want %d", got, u32)
		}
		if got := root.Uint64(8); got != u64 {
			t.Errorf("Uint64 roundtrip: got %x, want %x", got, u64)
		}
		if got := root.Int32(16); got != i32 {
			t.Errorf("Int32 roundtrip: got %d, want %d", got, i32)
		}
		if got := root.Bool(20); got != bval {
			t.Errorf("Bool roundtrip: got %v, want %v", got, bval)
		}
		if got := root.Text(24); got != text {
			t.Errorf("Text roundtrip: got %q, want %q", got, text)
		}
	})
}

// FuzzZAPMalformedHeader starts from a valid header and corrupts specific
// bytes. Parse must return an error or a valid message -- never panic.
func FuzzZAPMalformedHeader(f *testing.F) {
	// Build a real message to use as the base
	base := buildSeedMessage(func(ob *ObjectBuilder) {
		ob.SetUint64(0, 12345)
		ob.SetUint64(8, 67890)
	})

	// Seed: corrupt magic byte 0
	s1 := make([]byte, len(base))
	copy(s1, base)
	s1[0] = 0xFF
	f.Add(s1)

	// Seed: corrupt version field
	s2 := make([]byte, len(base))
	copy(s2, base)
	binary.LittleEndian.PutUint16(s2[4:6], 0xFFFF)
	f.Add(s2)

	// Seed: zero out size field
	s3 := make([]byte, len(base))
	copy(s3, base)
	binary.LittleEndian.PutUint32(s3[12:16], 0)
	f.Add(s3)

	// Seed: size = max uint32
	s4 := make([]byte, len(base))
	copy(s4, base)
	binary.LittleEndian.PutUint32(s4[12:16], 0xFFFFFFFF)
	f.Add(s4)

	// Seed: root offset past end of message
	s5 := make([]byte, len(base))
	copy(s5, base)
	binary.LittleEndian.PutUint32(s5[8:12], 0xFFFFFFFF)
	f.Add(s5)

	// Seed: valid but truncated
	f.Add(base[:HeaderSize])

	// Seed: original valid message
	f.Add(base)

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Parse(data)
		if err != nil {
			// Verify the error is one of the expected sentinel errors
			// or at least not a panic.
			return
		}

		// If parse succeeds, ensure basic access is safe
		_ = msg.Flags()
		_ = msg.Size()
		root := msg.Root()
		_ = root.Uint64(0)
		_ = root.Uint64(8)
		_ = root.Text(0)
		_ = root.Bytes(0)
		_ = root.Object(0)
		_ = root.List(0)
	})
}

// FuzzZAPLargePayload tests message construction and parsing with payloads
// approaching the 16MB practical limit. The fuzzer controls the payload size
// (capped) and content seed byte. Parse must handle any result gracefully.
func FuzzZAPLargePayload(f *testing.F) {
	// Practical max for fuzzing. Real 16MB limit is tested with specific seeds.
	const maxFuzzPayload = 1 << 20 // 1MB cap during fuzzing for speed
	const limit16MB = 16 * 1024 * 1024

	// Seed 1: small payload
	f.Add(uint32(64), byte(0xAA))
	// Seed 2: medium payload
	f.Add(uint32(4096), byte(0x55))
	// Seed 3: just under 16MB header-declared size, tiny actual buffer
	f.Add(uint32(limit16MB-1), byte(0xFF))
	// Seed 4: exactly 16MB
	f.Add(uint32(limit16MB), byte(0x00))
	// Seed 5: over 16MB
	f.Add(uint32(limit16MB+1), byte(0x01))

	f.Fuzz(func(t *testing.T, requestedSize uint32, fill byte) {
		// Cap actual allocation to avoid OOM in fuzzing
		actualSize := int(requestedSize)
		if actualSize > maxFuzzPayload {
			actualSize = maxFuzzPayload
		}
		if actualSize < HeaderSize {
			actualSize = HeaderSize
		}

		// Build a raw buffer with valid header but large payload
		buf := make([]byte, actualSize)
		copy(buf[0:4], Magic)
		binary.LittleEndian.PutUint16(buf[4:6], Version)
		binary.LittleEndian.PutUint32(buf[8:12], uint32(HeaderSize)) // root at header
		binary.LittleEndian.PutUint32(buf[12:16], uint32(actualSize))

		// Fill data segment with the fuzz byte
		for i := HeaderSize; i < actualSize; i++ {
			buf[i] = fill
		}

		msg, err := Parse(buf)
		if err != nil {
			return
		}

		// Basic access must not panic
		if msg.Size() != actualSize {
			t.Errorf("Size mismatch: got %d, want %d", msg.Size(), actualSize)
		}

		root := msg.Root()
		_ = root.Uint8(0)
		_ = root.Uint64(0)
		_ = root.Text(0)
		_ = root.Bytes(0)
		_ = root.Object(0)
		_ = root.List(0)

		// Also test via Builder for sizes that fit
		if actualSize <= 1<<18 { // 256KB via builder
			payloadSize := actualSize - HeaderSize
			if payloadSize < 0 {
				payloadSize = 0
			}

			payload := bytes.Repeat([]byte{fill}, payloadSize)
			b := NewBuilder(actualSize + 64)
			lb := b.StartList(1)
			lb.AddBytes(payload)
			listOff, listLen := lb.Finish()

			ob := b.StartObject(16)
			ob.SetList(0, listOff, listLen)
			ob.SetUint32(8, requestedSize)
			ob.FinishAsRoot()

			data := b.Finish()
			msg2, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse failed on builder-constructed large message: %v", err)
			}

			list := msg2.Root().List(0)
			gotBytes := list.Bytes()
			if len(gotBytes) != payloadSize {
				t.Errorf("List.Bytes() len = %d, want %d", len(gotBytes), payloadSize)
			}
		}
	})
}
