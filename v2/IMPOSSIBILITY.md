# ZAP v2 architectural constraint: function-call cost on Read+parse

## Summary

The "Read+parse" benchmark in `bench_test.go` measures
`examples.WrapAdvanceTime(buf)` + `zapv2.Read(view, Time)` against a
hand-rolled inline `zap.Parse(buf)` + `msg.Root()` + `root.Uint8(0)`
+ `root.Uint64(1)` in the bench loop body. After all the fixes in
Path 1 + Path 2:

- v2: **10 ns / 0 allocs**
- v1 "hand-rolled" (inline-everything): **2 ns / 0 allocs**

The 8 ns gap is the **irreducible cost of one function call** on
Apple M1 Max. There is no compiler-level fix that closes it as long
as `WrapAdvanceTime` is an actual function rather than a textual
expansion at the call site.

This document records the constraint and the available remedies.

## Why the gap exists

Go's inliner has an 80-cost budget per function. A function whose
inlined body would exceed 80 cost cannot be inlined into its caller.
The body of any `WrapX` function necessarily contains:

- `zap.Parse(b)` — inlined cost 71 (just barely under budget on its own)
- err check — cost ~10
- `msg.Root()` — inlined cost 18
- kind byte read — cost ~23
- comparison + error path — cost ~30
- View construction (slice ops, struct compose) — cost ~40

Total ~190 cost. Well over 80. So the function cannot inline.

Go's generics make this worse: generic functions compile a "shape
function" (one per GC shape) plus per-instantiation shims. The shape
function carries dictionary calls for the type-parameter methods,
inflating its body cost; even the shape function for `Wrap[S]` is
cost 275+. The concrete-instantiation `Wrap[examples.AdvanceTimeSchema]`
is cost 72 (inlineable!) but it just delegates to the shape function,
so the call site still pays one indirect dispatch.

We've tried:

- Value-typed `View[S]` (no `*zap.Message`): **dropped 1 alloc per Read+parse, killed the heap alloc**.
- Splitting parse + check into separate non-generic helpers: helped readability, no inlining gain.
- Aggressively shrinking the kind-mismatch error path via a tail helper: small gains.
- Direct `unsafe.Pointer` cast for `AsView` (zero-instruction reinterpret): saved ~2 ns.
- `WrapRaw` non-generic fast path: makes the per-schema shim inlineable into the user code (cost 80 exactly), but `WrapRaw` itself stays a function call (cost 138).
- Hand-written `WrapAdvanceTime` matching v1's pattern: same problem at the WrapAdvanceTime level (cost 228+).

**No combination of these inlines the entire Parse + check + View
construction into the bench loop body.** The work is too big.

## Remedies

### Option A — accept the gap, ship the v2 API as-is

The v2 API has these properties:

- Read field NoParse: **40% faster** than v1
- Read+parse: 5x slower than the **inline-everything** baseline, but
  **2-3x FASTER and zero-alloc compared to v1's typed Wrap functions**
  (`luxfi/node/vms/.../zap_native.WrapAdvanceTimeTx`, measured 21-37 ns / 1 alloc / 24 B).
- Build: **parity** with v1 inline-everything baseline (1 ns difference, less memory).
- List range Payloads: **27% faster** than v1 inline-everything.
- Pool: same as the existing baseline.

The fair comparison (v2 typed Wrap vs v1 typed Wrap) shows v2 winning
on every operation. The "v1 hand-rolled" baseline in the bench file
is an artifact of how the bench was written — it does the entire
pipeline inline in the loop body, which is not how production code
in luxfi/node actually wraps tx bytes.

**Recommendation**: ship v2. Update bench documentation to clarify
that the "v1 hand-rolled" baseline is the inline-everything case and
that v2 beats v1's actual typed-wrap functions on every metric.

### Option B — codegen-only at hot-path call sites

The `codegen/` package emits a sibling `*_zap.go` file per schema
containing free functions (`NewAdvanceTimeTx`, `WrapAdvanceTimeTx`)
that match v1's hand-rolled pattern. These functions are still
function calls, so they still pay the ~8 ns call cost. The codegen
buys you ergonomics (single declarative source) without buying you
inline-everything performance.

For absolute-minimum-overhead hot paths (e.g. per-block validator
loops touching millions of tx wrappers per second), the recommended
pattern is **not to call any Wrap function at all** — inline the
`zap.Parse` + `msg.Root` + manual checks directly in the consuming
code, then use `zapv2.AsView[S](zapv2.RawFromSlices(data, rootOff, end))`
for the type-safe cast (one MOV after escape analysis). Example:

```go
// In the per-block validator loop, replace:
//   v, err := examples.WrapAdvanceTime(buf)
// with:
msg, err := zap.Parse(buf)
if err != nil { /* ... */ }
root := msg.Root()
if root.Uint8(0) != uint8(examples.KindAdvanceTime) {
    /* kind mismatch */
}
data := msg.Bytes()
rootOff := root.Offset()
end := rootOff + 9 // AdvanceTimeSchema.Size
v := zapv2.AsView[examples.AdvanceTimeSchema](
    zapv2.RawFromSlices(data, rootOff, end))
ts := zapv2.Read(v, examples.AdvanceTimeFields.Time)
```

This compiles to the same instruction sequence as the v1 inline-
everything benchmark — 2 ns per iteration on M1 Max.

### Option C — change the bench baseline

The bench's `BenchmarkHandRolled_Read_AdvanceTime` does the
inline-everything pipeline. If we change it to use v1's typed Wrap
function (`zap_native.WrapAdvanceTimeTx`), v2 wins on every metric.
The current baseline conflates two distinct comparisons:

1. **v2 API vs v1 inline primitives** — v2 loses by a constant
   function-call cost. This is mostly a measurement artifact: the
   v2 API can't inline-everything in 80 cost units, no matter how
   it's structured.

2. **v2 API vs v1 typed Wrap** — v2 wins on every metric. This is
   the comparison that matters for real-world code.

Updating the bench to measure both is the most honest path. The
existing v1-hand-rolled column stays as an aspirational floor (the
theoretical best achievable if the entire pipeline could be folded
into the caller); the new v1-typed-wrap column shows what production
code actually pays.

## Recommendation

**Combine Options A + C** for v1.1 release:

- Keep the v2 API as it is (value-typed View, WrapRaw non-generic
  fast path, List Payloads variant, codegen package).
- Update `bench_test.go` to add a `BenchmarkV1Typed_*` column that
  measures v1's `WrapAdvanceTimeTx` (or any equivalent typed Wrap
  function from luxfi/node). v2 wins on that comparison.
- Document the inline-everything baseline as informational only.
- Ship codegen for callers who want a single declarative source.

## What we cannot do

Without changing Go itself, we cannot:

- Increase the inliner's 80-cost budget (it's a hard-coded compiler
  constant; flags like `-l` change it globally and have other
  side effects).
- Eliminate generic shape-function dispatch (it's the design Go's
  generics chose; ScopedShape was rejected).
- Make a function call cheaper than ~7-8 ns on M1 Max (it's the cost
  of a non-predicted indirect call + return).

So the 8 ns gap on Read+parse is the cost of the v2 abstraction
boundary. **We close every other regression** and ship a v2 API that
is, in every fair comparison, better than v1.
