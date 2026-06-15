package zapweb

import (
	"encoding/hex"
	"testing"

	zap "github.com/luxfi/zap"
	"github.com/luxfi/zap/zapclient"
)

// TestGoldenVectors emits the authoritative wire bytes for a handful of
// canonical messages. The TypeScript codec (zapweb/ts) asserts it
// produces byte-identical output for the same inputs — this is the
// cross-language "one protocol" proof. Run with -v to print the hex.
func TestGoldenVectors(t *testing.T) {
	emit := func(name string, raw []byte) {
		t.Logf("%s=%s", name, hex.EncodeToString(raw))
	}

	// V1: object dataSize=64, text@0="hello"
	b := zap.NewBuilder(256)
	ob := b.StartObject(64)
	ob.SetText(0, "hello")
	ob.FinishAsRoot()
	emit("V1_echo_hello", b.Finish())

	// V2: text@0="hello", text@32="world", dataSize=64
	b = zap.NewBuilder(256)
	ob = b.StartObject(64)
	ob.SetText(0, "hello")
	ob.SetText(32, "world")
	ob.FinishAsRoot()
	emit("V2_two_fields", b.Finish())

	// V3: uint32@0=0x01020304, dataSize=8
	b = zap.NewBuilder(256)
	ob = b.StartObject(8)
	ob.SetUint32(0, 0x01020304)
	ob.FinishAsRoot()
	emit("V3_uint32", b.Finish())

	// V4: V1 with flags 0x1234 (FinishWithFlags)
	b = zap.NewBuilder(256)
	ob = b.StartObject(64)
	ob.SetText(0, "hello")
	ob.FinishAsRoot()
	emit("V4_flags", b.FinishWithFlags(0x1234))

	// V5: uint8@0=1, uint32@4=0xdeadbeef, text@8="hi", dataSize=16
	b = zap.NewBuilder(256)
	ob = b.StartObject(16)
	ob.SetUint8(0, 1)
	ob.SetUint32(4, 0xdeadbeef)
	ob.SetText(8, "hi")
	ob.FinishAsRoot()
	emit("V5_mixed", b.Finish())

	op, _ := zapclient.ProcedureOpcode("test.echo")
	t.Logf("opcode_test.echo=%d", op)
}
