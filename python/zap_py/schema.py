"""Schema DSL for ZAP messages — mirror of schema.go and the EVM schema
helpers in evm.go.

Lets Python code declare a struct shape, get back computed field offsets,
and pass that schema to a Builder/Object pair without hand-rolling
constants. Same alignment rules and same offsets as Go, so a struct
declared in both languages stays interchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List as _PyList, Optional


class Type(IntEnum):
    """Wire type tags. Values match Go's iota ordering in schema.go."""

    VOID = 0
    BOOL = 1
    INT8 = 2
    INT16 = 3
    INT32 = 4
    INT64 = 5
    UINT8 = 6
    UINT16 = 7
    UINT32 = 8
    UINT64 = 9
    FLOAT32 = 10
    FLOAT64 = 11
    TEXT = 12
    BYTES = 13
    LIST = 14
    STRUCT = 15
    ENUM = 16
    UNION = 17


def type_size(t: Type) -> int:
    """Bytes occupied by a field of this type in the parent struct."""
    if t in (Type.BOOL, Type.INT8, Type.UINT8):
        return 1
    if t in (Type.INT16, Type.UINT16):
        return 2
    if t in (Type.INT32, Type.UINT32, Type.FLOAT32):
        return 4
    if t in (Type.INT64, Type.UINT64, Type.FLOAT64):
        return 8
    if t in (Type.TEXT, Type.BYTES, Type.LIST):
        return 8  # offset (4) + length (4)
    if t == Type.STRUCT:
        return 4  # offset only
    return 0


@dataclass
class Field:
    name: str
    type: Type
    offset: int
    list_elem: Optional[Type] = None
    struct_name: str = ""
    default: Any = None


@dataclass
class Struct:
    name: str
    size: int = 0
    fields: _PyList[Field] = field(default_factory=list)

    def field_by_name(self, name: str) -> Optional[Field]:
        for f in self.fields:
            if f.name == name:
                return f
        return None


@dataclass
class Enum:
    name: str
    type: Type
    values: Dict[str, int] = field(default_factory=dict)


@dataclass
class Schema:
    name: str
    structs: Dict[str, Struct] = field(default_factory=dict)
    enums: Dict[str, Enum] = field(default_factory=dict)

    def add_struct(self, st: Struct) -> None:
        self.structs[st.name] = st

    def add_enum(self, e: Enum) -> None:
        self.enums[e.name] = e


def new_schema(name: str) -> Schema:
    return Schema(name=name)


# Sizes for the EVM extension types — mirror evm.go's StructBuilder hooks.
_ADDRESS_SIZE = 20
_HASH_SIZE = 32
_SIGNATURE_SIZE = 65


class StructBuilder:
    """Fluent struct definition. Same alignment rules as schema.go."""

    def __init__(self, name: str):
        self._s = Struct(name=name)
        self._offset = 0

    def _align(self, n: int) -> None:
        # Round up to the nearest multiple of n. Equivalent to Go's
        # (offset + n - 1) &^ (n - 1).
        self._offset = (self._offset + n - 1) & ~(n - 1)

    def _push(self, name: str, type_: Type, size: int, **extra) -> "StructBuilder":
        self._s.fields.append(
            Field(name=name, type=type_, offset=self._offset, **extra)
        )
        self._offset += size
        return self

    def bool(self, name: str) -> "StructBuilder":
        return self._push(name, Type.BOOL, 1)

    def int8(self, name: str) -> "StructBuilder":
        return self._push(name, Type.INT8, 1)

    def uint8(self, name: str) -> "StructBuilder":
        return self._push(name, Type.UINT8, 1)

    def int16(self, name: str) -> "StructBuilder":
        self._align(2)
        return self._push(name, Type.INT16, 2)

    def uint16(self, name: str) -> "StructBuilder":
        self._align(2)
        return self._push(name, Type.UINT16, 2)

    def int32(self, name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.INT32, 4)

    def uint32(self, name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.UINT32, 4)

    def float32(self, name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.FLOAT32, 4)

    def int64(self, name: str) -> "StructBuilder":
        self._align(8)
        return self._push(name, Type.INT64, 8)

    def uint64(self, name: str) -> "StructBuilder":
        self._align(8)
        return self._push(name, Type.UINT64, 8)

    def float64(self, name: str) -> "StructBuilder":
        self._align(8)
        return self._push(name, Type.FLOAT64, 8)

    def text(self, name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.TEXT, 8)

    def bytes(self, name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.BYTES, 8)

    def list(self, name: str, elem_type: Type) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.LIST, 8, list_elem=elem_type)

    def struct(self, name: str, struct_name: str) -> "StructBuilder":
        self._align(4)
        return self._push(name, Type.STRUCT, 4, struct_name=struct_name)

    # EVM extension hooks — matching the StructBuilder methods Go's evm.go
    # adds to the same builder. No alignment, mirroring evm.go's `align(1)`.
    def address(self, name: str) -> "StructBuilder":
        return self._push(name, Type.BYTES, _ADDRESS_SIZE)

    def hash(self, name: str) -> "StructBuilder":
        return self._push(name, Type.BYTES, _HASH_SIZE)

    def signature(self, name: str) -> "StructBuilder":
        return self._push(name, Type.BYTES, _SIGNATURE_SIZE)

    def build(self) -> Struct:
        # Final alignment to 8 bytes — matches schema.go.
        self._align(8)
        self._s.size = self._offset
        return self._s


def new_struct_builder(name: str) -> StructBuilder:
    return StructBuilder(name)


# Predefined schemas (1:1 with evm.go). Useful as a smoke test for the
# whole DSL: if these match Go's offsets, downstream apps can declare
# either side and read/write the other's bytes.

TRANSACTION_SCHEMA = (
    StructBuilder("Transaction")
    .hash("hash")
    .uint64("nonce")
    .address("from")
    .address("to")
    .bytes("value")
    .bytes("data")
    .uint64("gas")
    .bytes("gasPrice")
    .uint64("chainId")
    .signature("signature")
    .build()
)

BLOCK_HEADER_SCHEMA = (
    StructBuilder("BlockHeader")
    .hash("parentHash")
    .hash("uncleHash")
    .address("coinbase")
    .hash("stateRoot")
    .hash("transactionsRoot")
    .hash("receiptsRoot")
    .bytes("logsBloom")
    .uint64("difficulty")
    .uint64("number")
    .uint64("gasLimit")
    .uint64("gasUsed")
    .uint64("timestamp")
    .bytes("extraData")
    .hash("mixHash")
    .uint64("nonce")
    .build()
)

LOG_SCHEMA = (
    StructBuilder("Log")
    .address("address")
    .list("topics", Type.BYTES)
    .bytes("data")
    .uint64("blockNumber")
    .hash("txHash")
    .uint32("txIndex")
    .hash("blockHash")
    .uint32("logIndex")
    .bool("removed")
    .build()
)
