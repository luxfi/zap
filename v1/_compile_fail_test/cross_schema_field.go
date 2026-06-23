// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// This file deliberately fails to compile. It demonstrates the
// compile-time type-safety property the v2 generic API guarantees:
// you cannot read a Field declared for schema A through a View for
// schema B, and you cannot pass a value of the wrong wire type.
//
// Run:
//
//	cd ~/work/lux/zap/v2 && go build ./_compile_fail_test/...
//
// Expected output (Go 1.23+):
//
//	./cross_schema_field.go:NN:NN: cannot use AlphaFields.X (variable
//	  of type zapv1.Field[AlphaSchema, uint64]) as
//	  zapv1.Field[BetaSchema, uint64] value in argument to zapv1.Read
//
// The directory name begins with an underscore so `go build ./...`
// at the v2 root skips it; only an explicit build path includes it,
// which is the test harness's job (see [TestCompileFail] in the
// adjacent compile_fail_test.go).
package compile_fail_demo

import (
	"github.com/luxfi/zap/v1"
)

// AlphaSchema is one schema...
type AlphaSchema struct{}

func (AlphaSchema) Kind() zapv1.KindByte { return 0xA1 }
func (AlphaSchema) Size() int            { return 16 }
func (AlphaSchema) Name() string         { return "Alpha" }

// BetaSchema is a different schema...
type BetaSchema struct{}

func (BetaSchema) Kind() zapv1.KindByte { return 0xB1 }
func (BetaSchema) Size() int            { return 16 }
func (BetaSchema) Name() string         { return "Beta" }

var (
	AlphaFields = struct {
		X zapv1.Field[AlphaSchema, uint64]
	}{X: zapv1.At[AlphaSchema, uint64](1)}

	BetaFields = struct {
		Y zapv1.Field[BetaSchema, uint64]
	}{Y: zapv1.At[BetaSchema, uint64](1)}
)

// crossSchemaRead is the load-bearing compile-time-safety
// demonstration. The compiler MUST reject this because
// AlphaFields.X is a Field[AlphaSchema, uint64] but the View is
// View[BetaSchema] — the type parameters do not unify.
func crossSchemaRead(beta zapv1.View[BetaSchema]) uint64 {
	return zapv1.Read(beta, AlphaFields.X) // COMPILE ERROR
}

// crossTypeWrite tries to write an int64 into a Field declared for
// uint64. The compiler MUST reject this because the value type does
// not match the field's T parameter.
func crossTypeWrite(s zapv1.Setter[AlphaSchema]) {
	zapv1.Write(s, AlphaFields.X, int64(42)) // COMPILE ERROR
}
