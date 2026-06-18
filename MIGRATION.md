# ZAP-native storage migration

The canonical KV + transport for Lux is `luxfi/zap` (this repo) backed by
`luxfi/zapdb` for the on-disk KV. New deployments use ZAP for hot KV
**and** cold ancient stores. PebbleDB / leveldb remain only as legacy
in-place upgrade paths.

## ZAP runtime consolidation (serialization core)

`github.com/zap-proto/go` is the canonical pure-stdlib runtime for the ZAP
wire format (`Parse`/`Message`/`Object`/`List` + `Builder`/`ObjectBuilder`/
`ListBuilder` + `Schema`). This repo (`luxfi/zap`) historically duplicated
that core in its own `zap.go`/`builder.go`/`schema.go` while adding the
network layer (Node mesh, QUIC/TCP, mDNS, PQ-TLS handshake, EVM types, the
`forward` HTTP-over-ZAP contract). The duplication is being collapsed so
there is ONE serialization runtime; `zap-proto/go` is the source of truth and
this repo will ride it.

**Status (first safe step landed):** the two cores are now proven to emit a
byte-identical data segment, and `zap-proto/go` has absorbed the two deltas
that previously diverged it from this repo's hardened core, so the readers now
agree on accept/reject for every input.

- **Wire proof.** `zap_crosswire_test.go` (here) and the file of the same
  name in `zap-proto/go` pin the SAME `goldenV1Hex` constant. This repo's
  `NewBuilderV1` emits it byte-for-byte; `zap-proto/go`'s default `NewBuilder`
  emits it too. The ONLY header difference between this repo's default
  (Version2) output and the v1 golden vector is byte 4 (the version). A live
  cross-encode in a throwaway `go.work` joining both modules confirmed every
  field round-trips both directions.
- **Deltas reconciled in `zap-proto/go`** (additive — no honest wire changed):
  (1) it now accepts `Version1` AND `Version2` on read (was v1-only → it would
  reject this repo's default v2 buffers); (2) its reader now applies the same
  hardening this repo already had — unsigned-forward `Bytes` with
  `absPos < HeaderSize` rejection, `Object`/`List` `absOffset < HeaderSize`
  rejection, and `List` `length ≤ msgsize` clamp.

**Remaining steps** (see `zap-proto/go`'s LLM.md for the canonical list):
`schema.go` is already byte-identical and is the first alias target; the
reader/builder alias follows once `cmd/zapgen` lands (the read-buffer pool —
`Message.refs`/`Release`/`Retain` — is network-local and stays here); the
`StartObject` pre-reserve discipline is a documented, test-covered delta to
unify when the builder is aliased (adopt `zap-proto/go`'s pre-reserve — it is
strictly more reserving and byte-identical for every honest layout).

This doc enumerates every storage surface in luxd and the migration path
per backend.

## Backends in luxd today

| Surface                               | Today              | Canonical                | Migration                                |
| ------------------------------------- | ------------------ | ------------------------ | ---------------------------------------- |
| P-Chain DB                            | leveldb            | ZAP KV                   | One-shot migrator (planned, #186)        |
| X-Chain DB                            | leveldb            | ZAP KV                   | Same as P-Chain                          |
| EVM chainData (per chain)             | PebbleDB           | ZAP KV                   | `migrate-pebble-to-zap` (planned, #187)  |
| EVM ancient store                     | upstream freezer   | **ZAP ancient (`rawdb.ZapAncientStore`)** | `luxfi/geth/cmd/migrate-ancient` (shipped)|
| Plugin DBs (aivm, etc.)               | mixed              | ZAP KV                   | Per-plugin opt-in                        |
| ZAP wire protocol (peer + RPC)        | ZAP                | ZAP                      | No change                                |

## EVM ancient store — shipped

See `~/work/lux/geth/core/rawdb/zap_ancient.go`. Key layout:

```
['a'][kind byte][big-endian uint64 number] -> snappy-compressed value
['m']['h'][kind byte]                      -> big-endian uint64 head
['m']['t'][kind byte]                      -> big-endian uint64 tail
```

Single ZAP database per chain. Snappy on by default (~10× compression on
cold data); tables can opt out via `freezerTableConfig{noSnappy: true}`.
Headers + canonical hashes are non-prunable; bodies + receipts are
prunable so `TruncateTail` is real work, not a no-op.

### Migrating an existing chain

```sh
# Stop luxd on the box.
kubectl scale -n lux-system sts/<network>-archive --replicas=0

# Run the migrator. Source = upstream freezer dir; dest = new ZAP dir.
migrate-ancient \
    --src /data/db/<network>/chainData/<chainID>/ancient \
    --dst /data/ancient/<chainID>

# Flip the NodeFleet CR to point at the new ZAP store. (The default is
# already zap; existing legacy fleets need an explicit edit.)
kubectl -n lux-system edit nodefleet <network>-fleet
#   spec.archive.ancientStore.backend: zap
#   spec.archive.ancientStore.path: /data/ancient

# Bring the archive back up.
kubectl scale -n lux-system sts/<network>-archive --replicas=1
```

### Verification

The migrator copies head + tail pointers. After re-opening, the new
store reports the same `Ancients()` and `Tail()` values. The chain head
on disk does not change — block import resumes at the same number.

## ZAP wire (unchanged)

The peer-to-peer transport and the JSON-RPC server already use ZAP. No
migration required.

## Hot KV (P/X/chainData/plugin DBs)

Planned as separate one-shot migrators per backend (issues #186, #187).
ZAP KV under the hood is `luxfi/zapdb` (the BadgerDB fork) — the same
backend the EVM ancient store uses, so a unified migration story is
reachable.

## Why ZAP

- Append-friendly LSM tree fits the cold block history pattern (~10×
  snappy compression on bodies + receipts).
- One backend everywhere → one toolchain, one set of operational
  primitives (snapshots, backups, profiling).
- Transport layer (`luxfi/zap`) already uses the same codecs — the wire
  format and the storage format can share `node_codec.go`.

## Constraints

- ZAP records max 2 GB per key/value (BadgerDB limit). Our largest cold
  record (a body at the network's gas cap) is ~2 MB; comfortably
  within budget.
- ZAP files are not directly addressable by other tools (Pebble's
  sst-dump style debug tools). Use the migrator + JSON-RPC.
