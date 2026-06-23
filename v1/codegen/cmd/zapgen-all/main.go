// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command zapgen-all bulk-emits per-schema ZAP v2 accessor files
// from a directory of JSON schema declarations.
//
// Each *.json file in the schemas directory declares one or more
// schemas in a single LP-aligned bundle. The bundle's top-level
// "schemas" array contains entries with the same fields as a
// codegen.Schema plus an "out" field naming the relative output path:
//
//	{
//	  "lp": "lp-201",
//	  "description": "ZAP P2P transport (LP-201 §Wire schemas)",
//	  "schemas": [
//	    {
//	      "wire_name": "ConsensusVote",
//	      "go_name":   "ConsensusVoteSchema",
//	      "kind":      "0xD0",
//	      "size":      62,
//	      "package":   "p2pwire",
//	      "out":       "lp-201/consensus_vote_zap.go",
//	      "fields": [
//	        { "name": "Round",     "type": "uint64",  "offset": 1  },
//	        { "name": "BlockID",   "type": "bytes32", "offset": 9  },
//	        { "name": "SignerID",  "type": "bytes20", "offset": 41 },
//	        { "name": "SigOff",    "type": "uint32",  "offset": 61 }
//	      ]
//	    }
//	  ]
//	}
//
// Usage:
//
//	zapgen-all -schemas ./schemas -out ./generated
//
// The tool walks schemas/, parses every *.json file, validates every
// schema, and emits one *.go file per schema under -out at the path
// declared by the schema's "out" field. Existing files are overwritten.
//
// Exit codes: 0 = all schemas emitted; 1 = at least one schema failed
// to parse/validate/emit.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/luxfi/zap/v1/codegen"
)

// schemaSpec is the JSON wire shape for a single schema. It is the
// JSON-marshaling counterpart of codegen.Schema plus the output path
// field. Kept distinct from codegen.Schema so the JSON form can use
// hex-string Kind (more readable for humans) without losing the
// strongly-typed uint8 inside codegen.
type schemaSpec struct {
	WireName     string      `json:"wire_name"`
	GoName       string      `json:"go_name"`
	Kind         string      `json:"kind"`           // hex string "0xC1", or decimal "1"
	Size         int         `json:"size"`
	Package      string      `json:"package"`
	Out          string      `json:"out"`            // relative path under -out dir
	Fields       []fieldSpec `json:"fields"`
	SkipRegistry bool        `json:"skip_registry"`  // suppress init() registration (private Kind namespace)
}

// fieldSpec is the JSON wire shape for a single field. Matches
// codegen.Field 1:1.
type fieldSpec struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
}

// bundle is the JSON wire shape for one LP-aligned schema bundle.
type bundle struct {
	LP          string       `json:"lp"`
	Description string       `json:"description"`
	// SkipRegistry, when true, applies to every schema in the bundle as
	// the default for their per-schema SkipRegistry field. Per-schema
	// SkipRegistry overrides this (when explicitly set to false). Used
	// for schema families with private Kind namespaces (LP-182, LP-186).
	SkipRegistry bool         `json:"skip_registry"`
	Schemas      []schemaSpec `json:"schemas"`
}

func main() {
	var schemasDir, outDir string
	flag.StringVar(&schemasDir, "schemas", "schemas", "directory containing *.json schema bundles")
	flag.StringVar(&outDir, "out", "generated", "output directory for emitted *.go files")
	flag.Parse()

	bundles, err := loadBundles(schemasDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zapgen-all: load bundles: %v\n", err)
		os.Exit(1)
	}

	// Stable ordering for reproducible builds.
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].LP < bundles[j].LP })

	var (
		emitted int
		failed  int
	)
	for _, b := range bundles {
		for _, s := range b.Schemas {
			// Bundle-level SkipRegistry propagates to every schema in the
			// bundle as a default. Per-schema true wins; per-schema false
			// (the zero value) cannot override a bundle-level true — use
			// "skip_registry": false explicitly per-schema if needed
			// (handled by JSON unmarshal — present-and-false reads as
			// false, absent reads as false too; bundle-level true forces
			// true for absent entries).
			if b.SkipRegistry {
				s.SkipRegistry = true
			}
			if err := emitOne(outDir, b.LP, s); err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "  FAIL %s/%s: %v\n", b.LP, s.WireName, err)
				continue
			}
			emitted++
			fmt.Fprintf(os.Stderr, "  emit %s/%s -> %s\n", b.LP, s.WireName, s.Out)
		}
	}
	fmt.Fprintf(os.Stderr, "zapgen-all: %d schemas emitted, %d failed\n", emitted, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// loadBundles walks the schemas directory and parses every *.json file.
func loadBundles(dir string) ([]bundle, error) {
	var out []bundle
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		f, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var b bundle
		if err := json.Unmarshal(f, &b); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		out = append(out, b)
		return nil
	})
	return out, err
}

// emitOne converts a JSON schemaSpec to a codegen.Schema and emits
// the resulting *.go file under outDir/s.Out.
func emitOne(outDir, lp string, s schemaSpec) error {
	kind, err := parseKind(s.Kind)
	if err != nil {
		return fmt.Errorf("kind %q: %w", s.Kind, err)
	}

	cs := codegen.Schema{
		WireName:     s.WireName,
		GoName:       s.GoName,
		Kind:         kind,
		Size:         s.Size,
		Package:      s.Package,
		SkipRegistry: s.SkipRegistry,
	}
	for _, f := range s.Fields {
		cs.Fields = append(cs.Fields, codegen.Field{
			Name:   f.Name,
			Type:   f.Type,
			Offset: f.Offset,
		})
	}

	if s.Out == "" {
		return fmt.Errorf("missing 'out' field")
	}
	outPath := filepath.Join(outDir, s.Out)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
	}
	w, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer w.Close()
	if err := codegen.Emit(w, cs); err != nil {
		return fmt.Errorf("emit: %w", err)
	}
	return nil
}

// parseKind accepts "0xC1" (hex) or "193" (decimal) and returns a uint8.
func parseKind(s string) (uint8, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 8)
		if err != nil {
			return 0, err
		}
		return uint8(v), nil
	}
	v, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(v), nil
}
