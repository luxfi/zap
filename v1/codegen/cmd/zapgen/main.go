// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command zapgen emits per-schema ZAP v2 accessors from a declarative
// schema description.
//
// Usage:
//
//	zapgen -name AdvanceTimeTx -go-name AdvanceTimeSchema -kind 1 \
//	       -size 9 -package examples -field Time:uint64:1 \
//	       -out v2/examples/advance_time_zap.go
//
// The emitted file's Wrap/New functions use v1 primitives directly so
// the Go compiler inlines them into the caller — matching v1
// hand-rolled performance to within compiler noise.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/luxfi/zap/v1/codegen"
)

type fieldFlag struct {
	fields *[]codegen.Field
}

func (f *fieldFlag) String() string { return "" }
func (f *fieldFlag) Set(spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 {
		return fmt.Errorf("field spec %q must be Name:Type:Offset", spec)
	}
	off, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return fmt.Errorf("field %q offset %q: %v", parts[0], parts[2], err)
	}
	*f.fields = append(*f.fields, codegen.Field{
		Name:   parts[0],
		Type:   parts[1],
		Offset: uint32(off),
	})
	return nil
}

func main() {
	var s codegen.Schema
	var kind uint
	var size int
	var outPath string

	flag.StringVar(&s.WireName, "name", "", "wire-name (e.g. AdvanceTimeTx)")
	flag.StringVar(&s.GoName, "go-name", "", "Go schema marker type name (e.g. AdvanceTimeSchema)")
	flag.UintVar(&kind, "kind", 0, "kind discriminator byte (0x01..0xff)")
	flag.IntVar(&size, "size", 0, "fixed payload size in bytes")
	flag.StringVar(&s.Package, "package", "", "output Go package name")
	flag.Var(&fieldFlag{&s.Fields}, "field", "field spec Name:Type:Offset (repeatable)")
	flag.StringVar(&outPath, "out", "", "output file path (default: stdout)")
	flag.BoolVar(&s.SkipRegistry, "skip-registry", false, "do not emit init() global Register — for a PRIVATE kind namespace (e.g. a per-service schema set whose kind bytes are unique only within that service, not the shared zapv1.DefaultRegistry)")
	flag.Parse()

	if s.WireName == "" || s.GoName == "" || s.Package == "" || kind == 0 || size <= 0 {
		fmt.Fprintln(os.Stderr, "zapgen: missing required flags (see -h)")
		os.Exit(2)
	}
	s.Kind = uint8(kind)
	s.Size = size

	var out *os.File
	if outPath == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "zapgen: create %s: %v\n", outPath, err)
			os.Exit(1)
		}
		out = f
		defer f.Close()
	}

	if err := codegen.Emit(out, s); err != nil {
		fmt.Fprintf(os.Stderr, "zapgen: emit: %v\n", err)
		os.Exit(1)
	}
}
