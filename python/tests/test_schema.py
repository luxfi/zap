"""Schema DSL tests for zap_py.

The Go-vs-Python parity test compares offsets/sizes against a JSON dump
emitted by gen_schema_fixture.go — set ZAP_GO_SCHEMA_FIXTURE to enable.
"""

import json
import os

import pytest

from zap_py import (
    BLOCK_HEADER_SCHEMA,
    Builder,
    Field,
    LOG_SCHEMA,
    Schema,
    Struct,
    StructBuilder,
    TRANSACTION_SCHEMA,
    Type,
    new_schema,
    new_struct_builder,
    parse,
    type_size,
)


def test_type_sizes():
    assert type_size(Type.BOOL) == 1
    assert type_size(Type.UINT8) == 1
    assert type_size(Type.UINT16) == 2
    assert type_size(Type.UINT32) == 4
    assert type_size(Type.FLOAT32) == 4
    assert type_size(Type.UINT64) == 8
    assert type_size(Type.FLOAT64) == 8
    assert type_size(Type.TEXT) == 8
    assert type_size(Type.BYTES) == 8
    assert type_size(Type.LIST) == 8
    assert type_size(Type.STRUCT) == 4
    assert type_size(Type.VOID) == 0


def test_struct_builder_alignment():
    """Same alignment rules as schema.go: each field rounds up to its size."""
    s = (
        StructBuilder("Mixed")
        .bool("active")    # offset 0, size 1
        .uint32("id")      # padded to offset 4, size 4
        .uint64("amount")  # offset 8, size 8
        .text("label")     # offset 16, size 8
        .build()
    )
    offsets = {f.name: f.offset for f in s.fields}
    assert offsets == {"active": 0, "id": 4, "amount": 8, "label": 16}
    # Final align to 8.
    assert s.size == 24


def test_struct_builder_no_realignment_for_same_width():
    s = (
        StructBuilder("Tight")
        .uint8("a")
        .uint8("b")
        .uint8("c")
        .uint8("d")
        .build()
    )
    offsets = [f.offset for f in s.fields]
    assert offsets == [0, 1, 2, 3]
    # Final 8-byte alignment.
    assert s.size == 8


def test_field_lookup():
    s = (
        StructBuilder("X")
        .uint32("first")
        .text("second")
        .build()
    )
    assert s.field_by_name("first").type == Type.UINT32
    # Text aligns to 4, so it sits flush after the uint32.
    assert s.field_by_name("second").offset == 4
    assert s.field_by_name("missing") is None


def test_list_field_carries_elem_type():
    s = StructBuilder("L").list("tags", Type.TEXT).build()
    f = s.field_by_name("tags")
    assert f.type == Type.LIST
    assert f.list_elem == Type.TEXT


def test_struct_field_carries_struct_name():
    s = StructBuilder("Outer").struct("inner", "Inner").build()
    f = s.field_by_name("inner")
    assert f.type == Type.STRUCT
    assert f.struct_name == "Inner"


def test_schema_registry():
    sch = new_schema("myapp")
    person = StructBuilder("Person").uint32("id").text("name").build()
    sch.add_struct(person)
    assert "Person" in sch.structs
    assert sch.structs["Person"].field_by_name("name").offset == 4


def test_address_hash_signature_offsets():
    """EVM extension methods stack at their full sizes with no alignment."""
    s = (
        StructBuilder("Receipt")
        .address("recipient")           # 0..20
        .hash("txHash")                 # 20..52
        .signature("sig")               # 52..117
        .build()
    )
    offsets = {f.name: f.offset for f in s.fields}
    assert offsets == {"recipient": 0, "txHash": 20, "sig": 52}
    # 117 → final align(8) = 120
    assert s.size == 120


def test_transaction_schema_offsets():
    """Hand-computed offsets for the canonical Transaction schema."""
    offsets = {f.name: f.offset for f in TRANSACTION_SCHEMA.fields}
    # hash[32] | nonce(u64,align8=32) | from[20] | to[20] | value(bytes,align4) ...
    assert offsets["hash"] == 0
    assert offsets["nonce"] == 32
    assert offsets["from"] == 40
    assert offsets["to"] == 60
    # 80 → align4 = 80
    assert offsets["value"] == 80
    assert offsets["data"] == 88
    # 96 → align8 = 96
    assert offsets["gas"] == 96
    assert offsets["gasPrice"] == 104
    # 112 → align8 = 112
    assert offsets["chainId"] == 112
    assert offsets["signature"] == 120
    # 120 + 65 = 185 → final align8 = 192
    assert TRANSACTION_SCHEMA.size == 192


def test_schema_drives_builder():
    """The classic loop: declare schema → use offsets → roundtrip."""
    s = (
        StructBuilder("Person")
        .uint32("id")
        .text("name")
        .int32("age")
        .bool("active")
        .build()
    )
    f = {fld.name: fld.offset for fld in s.fields}

    b = Builder()
    ob = b.start_object(s.size)
    ob.set_uint32(f["id"], 42)
    ob.set_text(f["name"], "Vitalik")
    ob.set_int32(f["age"], 30)
    ob.set_bool(f["active"], True)
    ob.finish_as_root()

    root = parse(b.finish()).root()
    assert root.uint32(f["id"]) == 42
    assert root.text(f["name"]) == "Vitalik"
    assert root.int32(f["age"]) == 30
    assert root.bool(f["active"]) is True


def test_block_header_and_log_schemas_build_clean():
    # No assertions on absolute offsets here — they're checked field-by-field
    # in the Go fixture interop test below. This guards against trivial
    # builder failures.
    assert BLOCK_HEADER_SCHEMA.size > 0
    assert LOG_SCHEMA.size > 0
    assert all(f.offset >= 0 for f in BLOCK_HEADER_SCHEMA.fields)
    assert all(f.offset >= 0 for f in LOG_SCHEMA.fields)


@pytest.mark.skipif(
    not os.environ.get("ZAP_GO_SCHEMA_FIXTURE"),
    reason="set ZAP_GO_SCHEMA_FIXTURE=path/to/schemas.json (built with gen_schema_fixture.go)",
)
def test_go_schema_fixture_parity():
    """Go and Python compute identical offsets and total sizes for every
    predefined schema. Drives the JSON fixture comparison."""
    with open(os.environ["ZAP_GO_SCHEMA_FIXTURE"]) as f:
        go = json.load(f)

    py_schemas = {
        "Transaction": TRANSACTION_SCHEMA,
        "BlockHeader": BLOCK_HEADER_SCHEMA,
        "Log": LOG_SCHEMA,
    }
    for name, expected in go.items():
        actual = py_schemas[name]
        assert actual.size == expected["size"], (
            f"{name}: py size {actual.size} != go size {expected['size']}"
        )
        py_fields = {f.name: f.offset for f in actual.fields}
        go_fields = {f["name"]: f["offset"] for f in expected["fields"]}
        assert py_fields == go_fields, f"{name} field offsets diverged"
