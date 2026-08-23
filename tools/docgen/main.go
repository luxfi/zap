// Copyright (C) 2022-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// docgen renders the node's package reference from godoc — every package under
// the module, one MDX page mirroring the import path — for docs.lux.network.
// It PARSES (go/parser + go/doc), never builds, so it is immune to build-graph
// skew. Same model as hanzo/cloud generating its docs from source.
//
//	go run ./tools/docgen <out-dir> [root]     # default root: .
package main

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/printer"
	"go/token"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var mod string

func main() {
	out, root := "node-docs", "."
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if len(os.Args) > 2 {
		root = os.Args[2]
	}
	mod = modulePath(root)
	dirsWithPages := map[string]bool{}
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if path != root && skipDir(d.Name()) {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, path)
		if md, name, ok := genPkg(path); ok {
			dst := filepath.Join(out, rel)
			os.MkdirAll(dst, 0o755)
			os.WriteFile(filepath.Join(dst, "index.mdx"), []byte(md), 0o644)
			dirsWithPages[rel] = true
			_ = name
		}
		return nil
	})
	writeMeta(out, root, dirsWithPages)
	fmt.Printf("node docgen: %d packages → %s\n", len(dirsWithPages), out)
}

func skipDir(n string) bool {
	switch n {
	case "vendor", "testdata", "mocks", "node_modules", "bin", "build", "docs", ".git", "examples", "benchmarks":
		return true
	}
	return strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") || strings.HasSuffix(n, "mock")
}

func genPkg(dir string) (string, string, bool) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil || len(pkgs) == 0 {
		return "", "", false
	}
	var p *ast.Package
	var pname string
	for n, pk := range pkgs {
		if strings.HasSuffix(n, "_test") {
			continue
		}
		p, pname = pk, n
		break
	}
	if p == nil {
		return "", "", false
	}
	imp := mod
	if rel, e := filepath.Rel(rootOf, dir); e == nil && rel != "." {
		imp = mod + "/" + filepath.ToSlash(rel)
	}
	d := doc.New(p, imp, 0)
	if d.Doc == "" && len(d.Funcs) == 0 && len(d.Types) == 0 {
		return "", "", false
	}
	syn := doc.Synopsis(d.Doc)
	if syn == "" {
		syn = "Package " + pname
	}
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: \"%s\"\ndescription: \"%s\"\n---\n\n", pname, inline(syn))
	b.WriteString("{/* Generated from godoc by tools/docgen — edit the Go source, not this file. */}\n\n")
	fmt.Fprintf(&b, "```go\nimport \"%s\"\n```\n\n", imp)
	if d.Doc != "" {
		b.WriteString(prose(d.Doc) + "\n\n")
	}
	if len(d.Funcs) > 0 {
		b.WriteString("## Functions\n\n")
		for _, f := range d.Funcs {
			fmt.Fprintf(&b, "### %s\n\n```go\n%s\n```\n\n", f.Name, sig(fset, f.Decl))
			if f.Doc != "" {
				b.WriteString(prose(f.Doc) + "\n\n")
			}
		}
	}
	if len(d.Types) > 0 {
		b.WriteString("## Types\n\n")
		for _, t := range d.Types {
			fmt.Fprintf(&b, "### %s\n\n", t.Name)
			if t.Doc != "" {
				b.WriteString(prose(t.Doc) + "\n\n")
			}
			for _, f := range t.Funcs {
				fmt.Fprintf(&b, "```go\n%s\n```\n\n", sig(fset, f.Decl))
			}
			for _, m := range t.Methods {
				fmt.Fprintf(&b, "```go\n%s\n```\n\n", sig(fset, m.Decl))
			}
		}
	}
	return b.String(), pname, true
}

var rootOf string

func modulePath(root string) string {
	rootOf = root
	b, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "module "))
		}
	}
	return "github.com/luxfi/node"
}

// writeMeta emits a Fumadocs meta.json in every output dir listing its immediate
// child dirs (sorted), so the package tree becomes the nav tree.
func writeMeta(out, root string, pages map[string]bool) {
	children := map[string][]string{}
	seen := map[string]bool{}
	for rel := range pages {
		for rel != "." && rel != "" {
			parent := filepath.Dir(rel)
			key := parent
			if parent == "." {
				key = ""
			}
			base := filepath.Base(rel)
			if !seen[key+"/"+base] {
				children[key] = append(children[key], base)
				seen[key+"/"+base] = true
			}
			rel = parent
		}
	}
	for dir, kids := range children {
		sort.Strings(kids)
		meta := `{"pages":["` + strings.Join(kids, `","`) + `"]}` + "\n"
		os.WriteFile(filepath.Join(out, dir, "meta.json"), []byte(meta), 0o644)
	}
}

func sig(fset *token.FileSet, d *ast.FuncDecl) string {
	body := d.Body
	d.Body = nil
	var buf strings.Builder
	printer.Fprint(&buf, fset, d)
	d.Body = body
	return strings.TrimSpace(buf.String())
}

func prose(s string) string {
	lines := strings.Split(s, "\n")
	fenced := false
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		ln = strings.ReplaceAll(ln, "<", "&lt;")
		lines[i] = strings.ReplaceAll(ln, "{", "&#123;")
	}
	return strings.Join(lines, "\n")
}

func inline(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), `"`, `'`)
	return strings.ReplaceAll(s, "<", "&lt;")
}
