// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap_test

import (
	"os"
	"testing"

	"github.com/luxfi/zap"
)

// TestPythonFixture verifies the Go reader accepts a message built by
// python/zap_py. Generate the fixture with:
//
//	python python/testdata/gen_python_fixture.py > /tmp/zap_python_fixture.bin
//	ZAP_PYTHON_FIXTURE=/tmp/zap_python_fixture.bin go test -run TestPythonFixture
//
// Skipped when the env var is unset so the suite stays Go-only by default.
func TestPythonFixture(t *testing.T) {
	path := os.Getenv("ZAP_PYTHON_FIXTURE")
	if path == "" {
		t.Skip("set ZAP_PYTHON_FIXTURE=path/to/fixture.bin (built with gen_python_fixture.py)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	msg, err := zap.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := msg.Root()

	if got := root.Uint32(0); got != 42 {
		t.Errorf("root.Uint32(0): got %d, want 42", got)
	}
	if got := root.Uint64(8); got != 0xDEADBEEFCAFEBABE {
		t.Errorf("root.Uint64(8): got %#x, want 0xDEADBEEFCAFEBABE", got)
	}
	if got := root.Text(16); got != "from py" {
		t.Errorf("root.Text(16): got %q, want %q", got, "from py")
	}
	if got := string(root.Bytes(24)); got != "\x01\x02\x03\x04" {
		t.Errorf("root.Bytes(24): got %x, want 01020304", got)
	}

	inner := root.Object(32)
	if inner.IsNull() {
		t.Fatal("root.Object(32) is null")
	}
	if got := inner.Uint32(0); got != 7 {
		t.Errorf("inner.Uint32(0): got %d, want 7", got)
	}
	if got := inner.Text(8); got != "nested" {
		t.Errorf("inner.Text(8): got %q, want %q", got, "nested")
	}

	list := root.List(40)
	if list.Len() != 4 {
		t.Fatalf("list.Len(): got %d, want 4", list.Len())
	}
	want := []uint32{10, 20, 30, 40}
	for i, w := range want {
		if got := list.Uint32(i); got != w {
			t.Errorf("list[%d]: got %d, want %d", i, got, w)
		}
	}
}
