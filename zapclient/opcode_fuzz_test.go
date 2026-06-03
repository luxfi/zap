// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapclient

import (
	"testing"
)

// FuzzProcedureOpcode asserts the documented invariants of ProcedureOpcode
// against arbitrary procedure names:
//
//   1. Empty name returns an error.
//   2. Non-empty name never errors and never returns 0x0000 or 0xFF00 as
//      the high byte (both reserved per codec.go's contract).
//   3. The low byte is always zero (preserves the MsgType<<8 layout used
//      by lux/zap consensus tests).
//   4. The result is deterministic for the same input.
//
// codec.go has unit tests for a handful of curated names; this target
// drives it against arbitrary bytes (including embedded NULs, very long
// strings, and non-ASCII input).
func FuzzProcedureOpcode(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("ListSecurity")
	f.Add("DelistSecurity")
	f.Add("AddIdentitiesBulk")
	f.Add("Settle")
	f.Add("name with\x00embedded null")
	f.Add("unicode ☃ \U0001F600")
	f.Add("very-long-procedure-name-that-exceeds-typical-bounds-1234567890")

	f.Fuzz(func(t *testing.T, name string) {
		op, err := ProcedureOpcode(name)

		if name == "" {
			if err == nil {
				t.Errorf("empty name: expected error, got opcode %#x", op)
			}
			return
		}

		if err != nil {
			t.Fatalf("ProcedureOpcode(%q) unexpected err: %v", name, err)
		}

		// Low byte must be zero (MsgType<<8 layout).
		if low := byte(op & 0xFF); low != 0 {
			t.Errorf("low byte of opcode %#x = %#x, want 0", op, low)
		}

		// High byte must NOT be reserved.
		hi := byte(op >> 8)
		if hi == 0x00 || hi == 0xFF {
			t.Errorf("opcode %#x for %q falls in reserved high byte %#x", op, name, hi)
		}

		// Determinism: second call returns the same value.
		op2, err2 := ProcedureOpcode(name)
		if err2 != nil {
			t.Fatalf("second ProcedureOpcode(%q) err: %v", name, err2)
		}
		if op != op2 {
			t.Errorf("nondeterministic opcode for %q: %#x vs %#x", name, op, op2)
		}
	})
}
