// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zapv2_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCompileFail is the load-bearing test that proves the v2 generic
// API enforces compile-time field-type safety.
//
// It invokes `go build` against the _compile_fail_test/ subdirectory,
// which contains a file that deliberately misuses the API. The test
// PASSES if the build FAILS with a type-mismatch diagnostic, and
// FAILS if the build succeeds (the safety net has a hole).
//
// The directory begins with an underscore so the normal `go build
// ./...` and `go test ./...` skip it (cf. cmd/go/internal/load:
// directories starting with '_' or '.' are excluded from "..."
// expansion).
//
// This is the most reliable form of negative-compile testing in Go:
// the toolchain itself is the oracle.
func TestCompileFail(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("go", "build", "./_compile_fail_test/")
	cmd.Env = append(cmd.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("compile_fail_demo built successfully — generic "+
			"type-safety is broken. Expected build failure.\nOutput:\n%s",
			string(output))
	}
	out := string(output)
	// Specific diagnostics we expect: the type-mismatch on Read and
	// the type-mismatch on Write. Either alone is sufficient.
	hasReadDiag := strings.Contains(out, "AlphaSchema") &&
		strings.Contains(out, "BetaSchema") &&
		strings.Contains(out, "Field")
	hasWriteDiag := strings.Contains(out, "int64") &&
		strings.Contains(out, "uint64")
	if !hasReadDiag && !hasWriteDiag {
		t.Fatalf("expected type-mismatch diagnostic mentioning "+
			"AlphaSchema/BetaSchema/Field or int64/uint64; got:\n%s", out)
	}
	t.Logf("compile-fail demo correctly rejected:\n%s", out)
}
