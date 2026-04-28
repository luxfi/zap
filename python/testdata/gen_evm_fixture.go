// Build a deterministic EVM-typed ZAP message used by the Python EVM
// interop test.
//
//	go run ./python/testdata/gen_evm_fixture.go > /tmp/zap_evm_fixture.bin
//	ZAP_GO_EVM_FIXTURE=/tmp/zap_evm_fixture.bin pytest python/tests/test_evm.py
//
//go:build ignore

package main

import (
	"os"

	"github.com/luxfi/zap"
)

func main() {
	addr, err := zap.AddressFromHex("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
	if err != nil {
		panic(err)
	}
	usdc, err := zap.AddressFromHex("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	if err != nil {
		panic(err)
	}
	hash, err := zap.HashFromHex("0x" +
		"abababababababababababababababababababababababababababababababab")
	if err != nil {
		panic(err)
	}
	var sig zap.Signature
	for i := range sig {
		sig[i] = byte(i)
	}

	b := zap.NewBuilder(512)

	// List of addresses (built before the root so its offset is known).
	lb := b.StartList(zap.AddressSize)
	lb.AddBytes(addr[:])
	lb.AddBytes(usdc[:])
	listOffset, listBytes := lb.Finish()
	listLen := listBytes / zap.AddressSize

	root := b.StartObject(zap.AddressSize + zap.HashSize + zap.SignatureSize + 8)
	root.SetAddress(0, addr)
	root.SetHash(zap.AddressSize, hash)
	root.SetSignature(zap.AddressSize+zap.HashSize, sig)
	root.SetList(zap.AddressSize+zap.HashSize+zap.SignatureSize, listOffset, listLen)
	root.FinishAsRoot()

	if _, err := os.Stdout.Write(b.Finish()); err != nil {
		panic(err)
	}
}
