# ZAP v2 schema declarations

This directory holds JSON schema declarations consumed by the
`zapgen-all` bulk emitter (see `../cmd/zapgen-all/`). One file per LP
family.

## Format

Each `.json` file is a single `bundle`:

```json
{
  "lp": "lp-201",
  "description": "ZAP P2P transport ...",
  "schemas": [
    {
      "wire_name": "ConsensusVote",
      "go_name":   "ConsensusVoteSchema",
      "kind":      "0xD0",
      "size":      53,
      "package":   "p2pwire",
      "out":       "lp-201/consensus_vote_zap.go",
      "fields": [
        { "name": "Round",   "type": "uint64",  "offset": 1 },
        { "name": "BlockID", "type": "bytes32", "offset": 9 }
      ]
    }
  ]
}
```

### Field types

Two field-type families are supported:

1. **Scalar fields.** Type names: `bool`, `int8`/`int16`/`int32`/`int64`,
   `uint8`/`uint16`/`uint32`/`uint64`, `float32`/`float64`.
   Read/write via `zapv2.Read` / `zapv2.Write` with the `Field[S, T]`
   handle declared in `<GoName>Fields`.

2. **Fixed-width byte-array fields.** Type names: `bytes<N>` where `N`
   is a positive integer (e.g., `bytes20` for NodeID/Address,
   `bytes32` for hashes, `bytes16` for session IDs, `bytes96` for
   PQ-signature digests). Emitted as standalone typed accessor
   functions `<WireName><FieldName>(view) [N]byte`; NOT in the
   `<GoName>Fields` struct because `[N]byte` is not a
   `zapv2.FieldKind` member.

Variable-length tails (lists, bytes, sub-objects) are NOT declared
here. They live outside the fixed payload. Convention in this dir: a
field named `*Off` is a `uint32` offset pointer into the variable-
length tail; the actual tail read/write code is hand-written using
`zapv2.ListAt`, `Object.Bytes`, or similar helpers.

## Bundles in this directory

| File | LP | Schemas | Schema-ID range |
|---|---|---|---|
| `lp-182-consensus.json` | LP-182 | 8 (QuasarCert, QBlock, WitnessProof, MagnetarAggregateCert, PolarisLegs, QuasarSig, TxAuthEnvelope, PQPermit) | 0x01..0x0B |
| `lp-186-vms.json` | LP-186 | 38 across 12 VMs (aivm:3 / bridgevm:3 / dexvm:3 / evm:2 / graphvm:3 / identityvm:4 / keyvm:3 / oraclevm:2 / quantumvm:3 / relayvm:3 / thresholdvm:4 / zkvm:5) | per-VM kind bytes 0x01..0x05 within each VM's `<vm>wire` package namespace |
| `lp-201-p2p.json` | LP-201 | 16 (ConsensusVote ... DHTStore) | 0xD0..0xDF |
| `lp-208-dag.json` | LP-208 | 2 (DAGHeader, DAGBody) | 0xE0..0xE1 |
| `lp-211-cross-shard.json` | LP-211 | 6 (CrossShardTxGroup ... CrossShardAbortNotify) | 0xE2..0xE7 |
| `lp-214-light-client.json` | LP-214 | 3 (LightClient*) | 0xF0..0xF2 |
| `lp-218-rollup.json` | LP-218 | 4 (Rollup*Tx) | kind bytes 0x40..0x43; schema-ID range tracked under the LP-218 / LP-208 / LP-211 collision note in `lp-218-rollup.json` |

**Total: 77 schemas declared and ready for bulk emission.**

### Variable-length tail convention (LP-182 + LP-186)

Each variable-length byte tail (`bytes` field per LP-182 §"Wire schemas" /
LP-186 §"Variable-length fields") occupies an 8-byte slot in the fixed
section, matching what `zap.ObjectBuilder.SetBytes` actually writes:
`{relOff uint32, length uint32}` little-endian. In the JSON schema this
is modeled as two uint32 fields: `<Name>Off` and `<Name>Len`. The
underlying ZAP wire is unchanged — this is purely how the codegen
declares the fixed-section byte layout.

LP-201 / LP-214 schemas (declared earlier) use a single `*Off uint32`
convention without an explicit `*Len` companion; their generated code
remains wire-compatible because the codegen does not synthesise
SetBytes calls for `Off` fields (callers invoke SetBytes themselves
when filling tails). The LP-182 + LP-186 `Off+Len` convention is the
preferred form going forward — it faithfully models the 8-byte slot.

## Schemas out of scope (deferred)

The following schemas / kinds are declared in their LP but DO NOT yet
have a fixed-section byte layout in the canonical source-of-truth
file. They are flagged as "deferred pending spec amendment" rather
than guessed.

### LP-182 — Consensus wire (5 deferred)

| Kind | Schema | Reason for deferral |
|---|---|---|
| 0x07 | EpochBundle | No `EpochBundle` struct in `~/work/lux/consensus/protocol/quasar/epoch.go` and no `~/work/lux/consensus/pkg/wire/zap/epoch_bundle.go`. LP-182 §Implementation lists the file as new; layout pending. |
| 0x08 | PrismCut | No `PrismCut` struct in `~/work/lux/consensus/protocol/prism/cut.go` matching the LP-182 schema. Layout pending. |
| 0x09 | StakeWeightedCut | The in-tree `protocol/prism/stake_weighted_cut.go` is an unexported runtime struct (`validators []Validator`, `totalWeight uint64`). The Validator wire shape is upstream; the LP-182 wire layout depends on that and is undeclared. |
| 0x0C | DAGVertex | LP-182 §Implementation re-points DAG vertex to schema 0x0C; the corresponding file (`pkg/wire/zap/dag_vertex.go`) is not yet in tree. Note: LP-208 declares an unrelated `DAGHeader`/`DAGBody` pair at 0xE0/0xE1 — different schema family. |
| 0x0D | PolicyCert | LP-182 §Implementation re-points `pkg/wire/policies.go` at schema 0x0D; layout file not yet in tree. |

Path forward for deferred LP-182 schemas: once
`~/work/lux/consensus/pkg/wire/zap/*.go` lands the byte-by-byte layout
for each deferred kind, append the JSON schema entry to
`lp-182-consensus.json` with the offsets matched to the source file.

### LP-186 — Chains-VM wire (~12 kinds deferred)

The LP-186 §Schema table enumerates kinds that DO NOT yet have a
matching wire-layout file in `~/work/lux/chains/<vm>/wire/`. The kind
constant exists in `kind.go`, but no per-kind `.go` file declares its
fixed-section byte layout:

| VM | Deferred kinds | Source |
|---|---|---|
| aivm | KindTaskResult (0x04) | `aivm/wire/kind.go` declares it; no `task_result.go` in tree |
| dexvm | KindCancelTx (0x03), KindLiquidityTx (0x05), KindMatchTx (0x06) | `dexvm/wire/kind.go` declares them; only `block.go`/`order_tx.go`/`swap_tx.go` in tree |
| graphvm | KindIndexUpdateTx (0x03), KindQueryResultTx (0x05) | `graphvm/wire/kind.go` declares them; not in tree |
| oraclevm | KindBlock (0x01), KindOracleQueryTx (0x03) | `oraclevm/wire/kind.go` declares them; not in tree |
| quantumvm | KindQuasarWitness (0x04) | `quantumvm/wire/kind.go` declares it; not in tree |
| relayvm | KindCloseChannelTx (0x02), KindRelayReceiptTx (0x05) | `relayvm/wire/kind.go` declares them; not in tree |

Path forward for deferred LP-186 schemas: once each VM's `wire/`
directory ships the missing per-kind `.go` file with a fixed-section
layout comment, append the JSON schema entry to `lp-186-vms.json` and
re-run `zapgen-all`.

## Running the emitter

```bash
cd ~/work/lux/zap
GOWORK=off go run ./v2/codegen/cmd/zapgen-all \
  -schemas ./v2/codegen/schemas \
  -out /tmp/zap-emit
```

The output `/tmp/zap-emit/` will contain one `*_zap.go` per declared
schema under the `out` path each schema specifies. The bulk emitter
prints `emit <lp>/<schema> -> <path>` per file plus a final summary
line.

## Schema-ID allocation map (canonical)

Per `/tmp/SESSION-HANDOFF.md` §"Schema ID Allocation":

| Range | Owner | Source LP |
|---|---|---|
| 0xC0..0xCB | Chains-VM (12 VMs) | LP-186 |
| 0xD0..0xDF | P2P transport (16 streams) | LP-201 |
| 0xE0..0xE1 | DAG header/body | LP-208 (override from LP-208 file's 0xF0..0xF1) |
| 0xE2..0xE7 | Cross-shard atomic 2PC | LP-211 |
| 0xE8..0xEF | Reserved (future LP-208 cluster extensions) | — |
| 0xF0..0xF2 | Light client | LP-214 |
| 0xF3..0xFF | Reserved (future framing) | — |

The LP-218 file lists 0xE0..0xEF; this collides with LP-208 + LP-211.
The session handoff resolves this in favour of LP-208 + LP-211; LP-218
rollups should track at their *kind* bytes (0x40..0x43) within a yet-
to-allocate schema-ID range — likely 0xC0-bucket extensions or a
dedicated 0xC bucket once chains-VM finalises. **Until that resolves,
the lp-218-rollup.json bundle emits at kind bytes 0x40..0x43 and is
parked in its own `rollupwire` package; the schema-ID byte is not
load-bearing for these schemas because they live in a unique package
namespace.**
