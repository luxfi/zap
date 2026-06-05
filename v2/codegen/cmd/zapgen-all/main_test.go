// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBulkEmit_AllBundles: load every *.json bundle under the
// canonical schemas directory, emit each declared schema into a temp
// dir, and verify every emitted file parses with go/parser. This is
// the codegen's parse-time gate: an emitted file that fails go/parser
// is unfit to ship — the bulk emitter MUST refuse to silently
// continue past such a failure.
//
// This test does NOT compile the emitted files (that would require a
// go-tool round trip and a test-time module). Compile-time is gated
// by `go build` on the testpkg/ in-tree fixture; parse-time is gated
// here for the full 31-schema batch.
func TestBulkEmit_AllBundles(t *testing.T) {
	t.Parallel()

	// Locate the canonical schemas dir relative to this test.
	schemasDir := filepath.Join("..", "..", "schemas")
	if _, err := os.Stat(schemasDir); err != nil {
		t.Skipf("schemas dir %s not present: %v", schemasDir, err)
	}

	bundles, err := loadBundles(schemasDir)
	if err != nil {
		t.Fatalf("loadBundles: %v", err)
	}
	if len(bundles) == 0 {
		t.Fatal("no bundles found in schemas dir")
	}

	outDir := t.TempDir()
	totalSchemas := 0
	for _, b := range bundles {
		for _, s := range b.Schemas {
			totalSchemas++
			if err := emitOne(outDir, b.LP, s); err != nil {
				t.Errorf("emitOne(%s/%s): %v", b.LP, s.WireName, err)
				continue
			}
			// Parse the emitted file.
			outPath := filepath.Join(outDir, s.Out)
			fset := token.NewFileSet()
			_, perr := parser.ParseFile(fset, outPath, nil, parser.ParseComments)
			if perr != nil {
				t.Errorf("parse %s: %v", outPath, perr)
			}
		}
	}
	t.Logf("zapgen-all: %d bundles, %d schemas, all parse clean",
		len(bundles), totalSchemas)
}

// TestParseKind_HexAndDecimal: the kind-byte parser accepts both
// "0xC1" hex and "193" decimal forms.
func TestParseKind_HexAndDecimal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want uint8
		err  bool
	}{
		{"0x00", 0x00, false},
		{"0x01", 0x01, false},
		{"0xC1", 0xC1, false},
		{"0xff", 0xFF, false},
		{"0XFF", 0xFF, false},
		{"0", 0, false},
		{"1", 1, false},
		{"255", 0xFF, false},
		{"256", 0, true},
		{"0x100", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := parseKind(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseKind(%q) = %d, nil; want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKind(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseKind(%q) = 0x%02x; want 0x%02x",
				c.in, got, c.want)
		}
	}
}

// TestBundleLoad_MissingDir: an absent schemas dir surfaces as a
// load error rather than an empty result.
func TestBundleLoad_MissingDir(t *testing.T) {
	t.Parallel()
	_, err := loadBundles(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error on missing schemas dir")
	}
}

// TestBundleLoad_IgnoresNonJSON: files that don't end in .json are
// silently skipped (e.g., a README in the schemas dir).
func TestBundleLoad_IgnoresNonJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "valid.json"),
		[]byte(`{"lp":"test","schemas":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bundles, err := loadBundles(dir)
	if err != nil {
		t.Fatalf("loadBundles: %v", err)
	}
	if len(bundles) != 1 {
		t.Errorf("loadBundles returned %d bundles; want 1", len(bundles))
	}
	if !strings.EqualFold(bundles[0].LP, "test") {
		t.Errorf("bundle lp = %q; want \"test\"", bundles[0].LP)
	}
}
