# zapv2 — Elegant Generic ZAP

`zapv2` (`github.com/luxfi/zap/v2`) is the generic, idiomatic Go reference
implementation of the ZAP wire format. It expresses the same on-wire
encoding as v1 (`github.com/luxfi/zap`), but through Go 1.23+ generics
so that every schema gets:

- One typed `View` over the buffer.
- One typed `Field` per offset, with the field's value type enforced
  at compile time.
- One generic `List` with `iter.Seq` range-over-func iteration.
- One generic `Pool` for reuse.
- One generic `Registry` for kind-byte dispatch (reflection at boot,
  none in the hot path).

The wire format is unchanged. v1 and v2 are byte-compatible — `Build`ing
a message in v2 produces the same bytes as the hand-rolled v1 pattern,
and Wrap/Read in either form reads either set of bytes.

## Why v2

The v1 API is C-port-shaped: one hand-written `WrapXxxTx` and `NewXxxTx`
function per schema, runtime offset constants (`OffsetAdvanceTimeTx_Time
= 1`), a runtime `switch kindByte` for dispatch, no compile-time type
relationship between schemas and accessors. Every new schema adds ~80
lines of boilerplate. Every dispatch is checked at runtime.

v2 lifts schema identity into the type system. The compiler enforces:

- A `Field[A, uint64]` cannot be read from a `View[B]`.
- A `uint32` cannot be written through a `Field[..., uint64]`.
- A `View[A]` cannot be mistaken for a `View[B]`.

No new wire format. No new threat model. Same bytes, stricter types.

## Authoring a schema

There is **one canonical path** for new schemas, and one fallback for
ad-hoc / dynamic dispatch. They share the same wire bytes.

### Canonical path: declarative codegen (recommended)

1. Declare your schema in a `.zap` JSON bundle (one entry per schema):

   ```json
   {
     "lp": "lp-example",
     "schemas": [
       {
         "wire_name": "AdvanceTimeTx",
         "go_name":   "AdvanceTimeSchema",
         "kind":      "0x01",
         "size":      9,
         "package":   "examples",
         "out":       "examples/advance_time_zap.go",
         "fields": [
           { "name": "Time", "type": "uint64", "offset": 1 }
         ]
       }
     ]
   }
   ```

2. Run codegen (one tool invocation per bundle):

   ```bash
   GOWORK=off go run ./v2/codegen/cmd/zapgen-all \
     -schemas ./v2/codegen/schemas \
     -out .
   ```

   Single-schema form (legacy CLI, still supported):

   ```bash
   go run ./v2/codegen/cmd/zapgen \
     -name AdvanceTimeTx -go-name AdvanceTimeSchema \
     -kind 1 -size 9 -package examples \
     -field Time:uint64:1 \
     -out v2/examples/advance_time_zap.go
   ```

3. Consumer imports the emitted file and uses the per-schema fast path:

   ```go
   tx, err := WrapAdvanceTime(buf)
   if err != nil { /* ... */ }
   time := AdvanceTimeFields.Time
   ts := zapv2.Read(tx, time)
   ```

The codegen emits v1-equivalent hand-rolled Go: ~0.5 ns/op read,
1 alloc/op build. Same wire bytes as the generic path.

### Generic consumer API (ad-hoc / dynamic schemas)

For consumers that don't know the schema at compile time, or for cold
paths / CLI tools / test fixtures where the extra function call doesn't
matter:

```go
view, err := zapv2.Wrap[AdvanceTimeSchema](buf)
if err != nil { /* SchemaError on kind-byte mismatch */ }
ts := zapv2.Read(view, AdvanceTimeFields.Time)
```

~10 ns/op read; pays the generic-dispatch tax (one un-inlinable
function call per Wrap). Acceptable for everything that isn't a
per-block hot loop. See the "API at a glance" section below for the
full generic surface.

### Deprecated: v1 hand-rolled

The original `github.com/luxfi/zap` v1 API (no `/v2` import path) is
**deprecated migration-only**. New schemas MUST use codegen (canonical)
or the v2 generic API (ad-hoc). v1 files remain only so in-flight
legacy callers (`luxfi/node/vms/platformvm/txs/zap_native`, parts of
`luxfi/consensus`, etc.) keep compiling while they migrate to one of
the v2 paths above. The v1 package will not accept new schemas.

---

## API at a glance

```go
import "github.com/luxfi/zap/v2"

// 1. Declare a schema (one struct, three methods).
type AdvanceTimeSchema struct{}
func (AdvanceTimeSchema) Kind() zapv2.KindByte { return 0x14 }
func (AdvanceTimeSchema) Size() int            { return 9 }
func (AdvanceTimeSchema) Name() string         { return "AdvanceTimeTx" }

// 2. Declare its fields once. Offsets live HERE; nowhere else.
var AdvanceTimeFields = struct {
    Time zapv2.Field[AdvanceTimeSchema, uint64]
}{
    Time: zapv2.At[AdvanceTimeSchema, uint64](1),
}

// 3. Build a message (imperative form — 1 wrapping struct on the stack,
//    same allocation count as v1's hand-rolled NewAdvanceTimeTx).
bb := zapv2.NewBuilderFor[AdvanceTimeSchema]()
zapv2.WriteB(bb, AdvanceTimeFields.Time, uint64(1735862400))
view, buf := bb.Finish()

// 4. Wrap an existing buffer (zero-copy).
view, err := zapv2.Wrap[AdvanceTimeSchema](buf)
if err != nil { /* SchemaError on kind-byte mismatch */ }

// 5. Read fields — type-safe, zero-allocation.
ts := zapv2.Read(view, AdvanceTimeFields.Time) // uint64
```

## Which constructor to use

| Form | Allocations | Readability | When to use |
|---|---|---|---|
| `zapv2.Build[S](init)` | 4 | best | cold paths, CLI tools, test fixtures |
| `zapv2.NewBuilderFor[S]()` + `WriteB` + `Finish` | 4 | imperative | hot paths (per-tx assembly), matches v1 baseline closely |
| `zapv2.Wrap[S](b)` | 1 | n/a (read-only) | parsing untrusted bytes from the wire |
| `zapv2.WrapUnchecked[S](b)` | 1 | n/a (read-only) | parsing inside Registry.Wrap after kind dispatch |

The closure-style `Build` is the most natural to read; the imperative
form is what you reach for when allocation pressure matters.

## Lists

Variable-length homogeneous lists use a generic `List[E]` with
`iter.Seq` and `iter.Seq2` accessors:

```go
type BatchSchema struct{}
func (BatchSchema) Kind() zapv2.KindByte { return 0x21 }
func (BatchSchema) Size() int            { return 17 }
func (BatchSchema) Name() string         { return "BatchTx" }

type ItemSchema struct{}
func (ItemSchema) Kind() zapv2.KindByte { return 0x22 }
func (ItemSchema) Size() int            { return 16 }
func (ItemSchema) Name() string         { return "BatchItem" }

const OffsetBatchItems uint32 = 9

// Build a batch.
bb := zapv2.NewBuilderFor[BatchSchema]()
zapv2.WriteList[BatchSchema, ItemSchema](bb.AsSetter(), OffsetBatchItems,
    func(es *zapv2.ElemSetter[ItemSchema]) {
        for _, it := range source {
            es.Append(func(e zapv2.Setter[ItemSchema]) {
                zapv2.Write(e, ItemFields.ID, it.ID)
                zapv2.Write(e, ItemFields.Value, it.Value)
            })
        }
    })
view, buf := bb.Finish()

// Read with range-over-func.
list := zapv2.ListAt[BatchSchema, ItemSchema](view, OffsetBatchItems)
for itemView := range list.All() {
    id := zapv2.Read(itemView, ItemFields.ID)
    // ...
}

// Or with index.
for i, itemView := range list.Indexed() {
    // ...
}
```

`iter.Seq` combinators are available: `zapv2.Take`, `Filter`, `Map`,
`Count`, `Collect`. Constant memory; one allocation per call (the
closure), zero per element. See `iter.go`.

## Compile-time field safety

The phantom type parameters of `Field[S, T]` are load-bearing for
nominal type identity. The compiler rejects:

```go
// ./v2/_compile_fail_test/cross_schema_field.go (intentional fail)
zapv2.Read(betaView, AlphaFields.X)  // error
zapv2.Write(setter, AlphaFields.X, int64(42))  // error
```

with diagnostics like:

```
./cross_schema_field.go:58:26: in call to zapv2.Read,
  type zapv2.Field[AlphaSchema, uint64] of AlphaFields.X
  does not match inferred type zapv2.Field[BetaSchema, T]
  for zapv2.Field[S, T]
```

The `TestCompileFail` test (in the same package) runs `go build`
against the demo dir and asserts the build fails with this diagnostic.
If the build ever succeeds, the safety net has a hole.

## Performance

Measured on Apple M1 Max with `go test -bench`. Full results in
[BENCH_RESULTS.md](BENCH_RESULTS.md). Summary:

| Bench | v1 hand-rolled (inline) | v2 (this) | Verdict |
|---|---|---|---|
| Read field (no parse) | 0.55 ns / 0 alloc | **0.33 ns** / 0 alloc | **v2 WIN -40%** |
| Read field (with parse) | 2.00 ns / 0 alloc | 10.07 ns / 0 alloc | LOSS 5x [†](#fn-fn1) |
| Build (per-schema fast path) | 30 ns / 1 alloc / 48 B | 32 ns / 1 alloc / 32 B | **v2 PARITY** |
| Build (closure-style) | n/a | 80 ns / 3 allocs | (cold path only) |
| List range 1000 elems (`Payloads`) | 920 ns / 0 alloc | **666 ns** / 0 alloc | **v2 WIN -27%** |
| List range 1000 elems (`All`) | 920 ns / 0 alloc | 2740 ns / 0 alloc | LOSS 3x [‡](#fn-fn2) |
| Pool Get/Put | n/a | 8.65 ns / 0 alloc | — |

<a id="fn-fn1"></a>**[†]** The "v1 hand-rolled" Read+parse baseline
is the inline-everything case: `zap.Parse(buf)` + `msg.Root()` +
`root.Uint8(0)` + `root.Uint64(1)` directly in the bench loop body.
The 5x gap is the cost of the function call to `WrapAdvanceTime` —
unavoidable as long as `Wrap*` is a function rather than a textual
expansion. Compared against v1's actual typed Wrap functions
(`luxfi/node/.../zap_native.WrapAdvanceTimeTx`, measured 21-37 ns /
1 alloc / 24 B), v2 **wins by 2-3x and uses zero allocations**. See
[IMPOSSIBILITY.md](IMPOSSIBILITY.md) for the full cost-budget analysis.

<a id="fn-fn2"></a>**[‡]** The `List.All()` iterator yields the
56-byte `View[E]` per element, which spills to stack each iteration.
Use `List.Payloads()` for hot-path large-list iteration — it yields
a 24-byte slice that fits in registers and **beats v1 by 27%**. The
`All()` form is the ergonomic path; `Payloads()` is the speed path.

## Migration path

v2 ships side-by-side with v1. v1 callers keep working. New schemas
land in v2; existing schemas migrate one at a time.

The canary in `examples/advance_time_tx.go` is the worked example
for migration. Compare it to the v1 hand-rolled
`luxfi/node/vms/platformvm/txs/zap_native/advance_time_tx.go` line by
line — same wire bytes, ~30% fewer lines, full type safety.

The byte-equality test `TestByteEqual_V1Canonical` pins this: the v2
generic builder produces the exact same bytes as the v1 hand-rolled
NewAdvanceTimeTx with the same TxKind and same offset.

## Threat model inheritance

All wire-level safety properties of v1 are inherited verbatim by v2:

- Magic + version + size bounds check at Parse.
- Signed-but-non-header-aliasing Object/List pointers (RED-HIGH-2:
  reject `absOffset < HeaderSize`).
- RED-HIGH-1 length clamp on lists.
- RED-MEDIUM-1 schema-version gate (Wrap rejects v1-shaped buffers
  when the schema is v2).
- Graceful degradation on out-of-range field offsets (return zero
  instead of panic).

v2 adds compile-time type safety on top. It does NOT loosen any
runtime check.

## Hot-path fast forms

For absolute-minimum-overhead consumers (per-block validator loops,
mempool ingest), three non-generic primitives let you bypass the
generic dispatch and write the same pattern v1 used:

- **`zapv2.WrapRaw(b, kind, size, name)`** → `Raw, error`: the
  non-generic parse + kind check. Used inside per-schema `WrapX`
  shims (hand-written or codegen-emitted).
- **`zapv2.AsView[S](r Raw)`** → `View[S]`: zero-instruction cast
  (unsafe-pointer reinterpret) — the type-safety hop without runtime
  cost.
- **`zapv2.RawFromSlices(data, rootOff, end)`** → `Raw`: compose a
  Raw from already-validated slices. For the most aggressive inline
  paths, use this with manual Parse + check in the consumer.
- **`zapv2.ReadPayload[S, T](payload, field)`**: read a field from a
  bare payload slice (as yielded by `List.Payloads()`). Register-
  friendly equivalent of `Read(view, field)`.

The `examples/advance_time_tx.go` file demonstrates the canonical
hand-rolled pattern; the `codegen/` package emits the same pattern
from a declarative `Schema` value (one tool invocation per schema).

## Codegen

For schemas where you have a declarative description (a YAML schema
file, struct tags, or a list of fields), the `codegen/` package emits
a `*_zap.go` file per schema with hand-rolled `WrapX` / `NewX`
functions that use v1 primitives directly:

```
go run ./v2/codegen/cmd/zapgen \
    -name AdvanceTimeTx \
    -go-name AdvanceTimeSchema \
    -kind 1 -size 9 \
    -package examples \
    -field Time:uint64:1 \
    -out v2/examples/advance_time_zap.go
```

The emitted code is byte-identical in wire semantics to the generic
`Wrap[S]` / `Build[S]` paths but matches v1 hand-rolled performance
to within compiler noise. See `codegen/doc.go` for the API.

## Files

```
v2/
  doc.go              Package overview.
  schema.go           Schema interface, KindByte, FieldKind, SchemaError.
  view.go             View[S], Wrap, Build, Setter[S], Raw, WrapRaw, AsView, RawFromSlices.
  builder.go          Builder[S] (imperative form), NewBuilderFor, Finish.
  field.go            Field[S, T], At, Read, Write, WriteB, ReadPayload.
  list.go             List[E], ListAt, WriteList, ElemSetter[E], All, Indexed, Payloads.
  iter.go             iter.Seq combinators (Take, Filter, Map, Count, Collect).
  pool.go             Pool[T] — generic sync.Pool wrapper.
  registry.go         Registry, Entry, Register, PeekKind, WrapAs, DefaultRegistry.

  v2_test.go          Round-trip, byte-equality, dispatch, pool, list, iter tests.
  bench_test.go       Side-by-side benchmarks vs v1 hand-rolled baseline.
  compile_fail_test.go  Negative-compile test harness.
  _compile_fail_test/   Demo file that deliberately fails to compile.

  examples/
    advance_time_tx.go    Canary schema (AdvanceTimeTx, 1-field tx) — hand-rolled fast path.
    batch_tx.go           Multi-element list schema (Items: []ItemSchema).

  codegen/
    doc.go            Package overview.
    schema.go         Schema, Field declarations.
    emit.go           Code generation (Emit -> io.Writer).
    cmd/zapgen/       CLI tool.

  BENCH_RESULTS.md    Full benchmark table + reproducible commands.
  IMPOSSIBILITY.md    Cost-budget analysis: why Read+parse can't beat inline-everything.
```
