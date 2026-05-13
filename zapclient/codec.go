// codec.go — procedure-name ↔ uint16 opcode mapping.
//
// ZAP messages carry a uint16 flags field that this package uses to
// route procedure calls. To let callers write `Call(ctx, "ListSecurity",
// req)` we hash the procedure name to a stable opcode.
//
// Scheme: FNV-1a 32-bit hash, truncated to the upper 8 bits of the
// uint16 (the lower 8 bits are kept zero for compatibility with the
// existing MsgTypeXxx<<8 convention in lux/zap consensus tests).
//
// Collision policy: at registration time, Server.Register MUST refuse
// to bind a procedure whose opcode collides with an already-registered
// procedure. Callers should re-name (e.g. add a version suffix) until
// the hash differs. With 8 bits the codespace is 256, so collisions
// are not exceedingly rare — services SHOULD keep their procedure set
// under ~30 names per service to stay below the birthday bound.
//
// Reserved opcodes:
//   0x00 — control / unknown (rejected by the server router)
//   0xFF — reserved for ZAP's own keepalive / control frames

package zapclient

import (
	"errors"
	"hash/fnv"
)

// ErrReservedOpcode is returned when ProcedureOpcode collides with a
// reserved value. The procedure must be re-named to avoid the conflict.
var ErrReservedOpcode = errors.New("zapclient: procedure name hashes to a reserved opcode")

// ProcedureOpcode returns the uint16 opcode for a procedure name.
// The lower 8 bits are zero (matching the existing MsgType<<8 shape
// in lux/zap); the upper 8 bits are FNV-1a(name) modulo 254 + 1.
//
// Returns ErrReservedOpcode if the hash lands on 0x00 or 0xFF.
func ProcedureOpcode(name string) (uint16, error) {
	if name == "" {
		return 0, errors.New("zapclient: empty procedure name")
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	// Map FNV-1a(name) to 1..254 (skipping 0 and 255 — both reserved).
	b := byte((h.Sum32() % 254) + 1)
	// Encode in the high byte; the low byte stays zero to keep
	// MsgType<<8 compatibility for consumers reading legacy bytes.
	return uint16(b) << 8, nil
}

// MustOpcode is ProcedureOpcode that panics on error. Use in
// package-level var initialisers where a bad procedure name is a
// build-time bug.
func MustOpcode(name string) uint16 {
	op, err := ProcedureOpcode(name)
	if err != nil {
		panic(err)
	}
	return op
}
