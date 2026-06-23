// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command gennest generates the nestwire test package: a singular nested
// object (Outer carrying an Inner that itself has a string tail). It is the
// nested-field peer of the one-off that produced testpkg/listwire, and
// proves the codegen's WriteNested/NestedAt emission round-trips on the
// wire (see testpkg/nestwire/roundtrip_test.go).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/zap/v1/codegen"
)

func main() {
	inner := codegen.Schema{
		GoName:   "InnerSchema",
		WireName: "Inner",
		Kind:     0x52,
		Size:     16, // ID @0 (u64), Label @8 (string tail-ptr)
		Package:  "nestwire",
		Element:  true,
		Fields: []codegen.Field{
			{Name: "ID", Type: "uint64", Offset: 0},
			{Name: "Label", Type: "string", Offset: 8},
		},
	}
	outer := codegen.Schema{
		GoName:   "OuterSchema",
		WireName: "Outer",
		Kind:     0x51,
		Size:     13, // kind@0, Seq@1 (u64), Inner@9 (object-ptr, 4 bytes)
		Package:  "nestwire",
		Fields: []codegen.Field{
			{Name: "Seq", Type: "uint64", Offset: 1},
			{Name: "Inner", Offset: 9, Nested: &codegen.NestedMsg{
				Schema: "InnerSchema",
				Wire:   "Inner",
				Value:  "Inner",
				Fields: []codegen.Field{
					{Name: "ID", Type: "uint64", Offset: 0},
					{Name: "Label", Type: "string", Offset: 8},
				},
			}},
		},
	}

	dir := filepath.Join("v1", "codegen", "testpkg", "nestwire")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, sc := range []struct {
		s   codegen.Schema
		out string
	}{
		{inner, "inner_zap.go"},
		{outer, "outer_zap.go"},
	} {
		f, err := os.Create(filepath.Join(dir, sc.out))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := codegen.Emit(f, sc.s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		f.Close()
		fmt.Println("wrote", filepath.Join(dir, sc.out))
	}
}
