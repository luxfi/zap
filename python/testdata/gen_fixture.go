// Build a deterministic ZAP message used by the Python interop test.
//
//	go run ./python/testdata/gen_fixture.go > /tmp/zap_fixture.bin
//	ZAP_GO_FIXTURE=/tmp/zap_fixture.bin pytest python/tests
//
//go:build ignore

package main

import (
	"os"

	"github.com/luxfi/zap"
)

func main() {
	b := zap.NewBuilder(512)

	inner := b.StartObject(24)
	inner.SetUint32(0, 7)
	inner.SetText(8, "nested")
	innerOffset := inner.Finish()

	lb := b.StartList(4)
	lb.AddUint32(10)
	lb.AddUint32(20)
	lb.AddUint32(30)
	lb.AddUint32(40)
	listOffset, listLen := lb.Finish()

	root := b.StartObject(56)
	root.SetUint32(0, 42)
	root.SetUint64(8, 0xDEADBEEFCAFEBABE)
	root.SetText(16, "from go")
	root.SetBytes(24, []byte{0x01, 0x02, 0x03, 0x04})
	root.SetObject(32, innerOffset)
	root.SetList(40, listOffset, listLen)
	root.FinishAsRoot()

	if _, err := os.Stdout.Write(b.Finish()); err != nil {
		panic(err)
	}
}
