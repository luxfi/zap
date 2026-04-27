"""Builder for ZAP messages — wire-compatible with the Go implementation."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List as _PyList, Optional

from .wire import ALIGNMENT, HEADER_SIZE, MAGIC, VERSION

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")
_I16 = struct.Struct("<h")
_I32 = struct.Struct("<i")
_I64 = struct.Struct("<q")
_F32 = struct.Struct("<f")
_F64 = struct.Struct("<d")


class Builder:
    """Constructs ZAP messages.

    Layout matches builder.go: 16-byte header, then aligned data segment.
    """

    __slots__ = ("_buf", "_pos", "_root_offset")

    def __init__(self, capacity: int = 256):
        if capacity < HEADER_SIZE:
            capacity = 256
        self._buf = bytearray(capacity)
        self._pos = HEADER_SIZE
        self._root_offset = 0
        self._buf[0:4] = MAGIC
        _U16.pack_into(self._buf, 4, VERSION)

    def reset(self) -> None:
        self._pos = HEADER_SIZE
        self._root_offset = 0

    @property
    def pos(self) -> int:
        return self._pos

    def _grow(self, n: int) -> None:
        needed = self._pos + n
        if needed <= len(self._buf):
            return
        new_cap = len(self._buf) * 2
        if new_cap < needed:
            new_cap = needed
        self._buf.extend(bytes(new_cap - len(self._buf)))

    def _align(self, alignment: int) -> None:
        padding = (alignment - (self._pos % alignment)) % alignment
        if padding == 0:
            return
        self._grow(padding)
        for i in range(padding):
            self._buf[self._pos + i] = 0
        self._pos += padding

    def finish(self) -> bytes:
        _U32.pack_into(self._buf, 8, self._root_offset)
        _U32.pack_into(self._buf, 12, self._pos)
        return bytes(self._buf[:self._pos])

    def finish_with_flags(self, flags: int) -> bytes:
        _U16.pack_into(self._buf, 6, flags)
        return self.finish()

    def start_object(self, data_size: int) -> "ObjectBuilder":
        self._align(ALIGNMENT)
        return ObjectBuilder(self, self._pos, data_size)

    def start_list(self, elem_size: int) -> "ListBuilder":
        self._align(ALIGNMENT)
        return ListBuilder(self, self._pos, elem_size)

    def write_bytes(self, data: bytes) -> int:
        if not data:
            return 0
        self._align(ALIGNMENT)
        offset = self._pos
        self._grow(len(data))
        self._buf[self._pos:self._pos + len(data)] = data
        self._pos += len(data)
        return offset

    def write_text(self, s: str) -> int:
        return self.write_bytes(s.encode("utf-8"))


@dataclass
class _OffsetEntry:
    field_offset: int
    data: bytes


class ObjectBuilder:
    """Builds a single ZAP object inside a Builder."""

    __slots__ = ("_b", "_start_pos", "_data_size", "_offsets")

    def __init__(self, b: Builder, start_pos: int, data_size: int):
        self._b = b
        self._start_pos = start_pos
        self._data_size = data_size
        self._offsets: _PyList[_OffsetEntry] = []

    def _ensure_field(self, end_offset: int) -> None:
        needed = self._start_pos + end_offset
        b = self._b
        if needed > b._pos:
            b._grow(needed - b._pos)
            for i in range(b._pos, needed):
                b._buf[i] = 0
            b._pos = needed

    def set_bool(self, field_offset: int, v: bool) -> None:
        self.set_uint8(field_offset, 1 if v else 0)

    def set_uint8(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 1)
        self._b._buf[self._start_pos + field_offset] = v & 0xFF

    def set_uint16(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 2)
        _U16.pack_into(self._b._buf, self._start_pos + field_offset, v & 0xFFFF)

    def set_uint32(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 4)
        _U32.pack_into(self._b._buf, self._start_pos + field_offset, v & 0xFFFFFFFF)

    def set_uint64(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 8)
        _U64.pack_into(self._b._buf, self._start_pos + field_offset, v & 0xFFFFFFFFFFFFFFFF)

    def set_int8(self, field_offset: int, v: int) -> None:
        self.set_uint8(field_offset, v & 0xFF)

    def set_int16(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 2)
        _I16.pack_into(self._b._buf, self._start_pos + field_offset, v)

    def set_int32(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 4)
        _I32.pack_into(self._b._buf, self._start_pos + field_offset, v)

    def set_int64(self, field_offset: int, v: int) -> None:
        self._ensure_field(field_offset + 8)
        _I64.pack_into(self._b._buf, self._start_pos + field_offset, v)

    def set_float32(self, field_offset: int, v: float) -> None:
        self._ensure_field(field_offset + 4)
        _F32.pack_into(self._b._buf, self._start_pos + field_offset, v)

    def set_float64(self, field_offset: int, v: float) -> None:
        self._ensure_field(field_offset + 8)
        _F64.pack_into(self._b._buf, self._start_pos + field_offset, v)

    def set_text(self, field_offset: int, v: str) -> None:
        self.set_bytes(field_offset, v.encode("utf-8"))

    def set_bytes(self, field_offset: int, v: bytes) -> None:
        self._ensure_field(field_offset + 8)
        if len(v) == 0:
            _U32.pack_into(self._b._buf, self._start_pos + field_offset, 0)
            _U32.pack_into(self._b._buf, self._start_pos + field_offset + 4, 0)
            return
        self._offsets.append(_OffsetEntry(field_offset=field_offset, data=bytes(v)))
        _U32.pack_into(self._b._buf, self._start_pos + field_offset + 4, len(v))

    def set_object(self, field_offset: int, obj_offset: int) -> None:
        self._ensure_field(field_offset + 4)
        if obj_offset == 0:
            _U32.pack_into(self._b._buf, self._start_pos + field_offset, 0)
            return
        rel_offset = obj_offset - (self._start_pos + field_offset)
        _I32.pack_into(self._b._buf, self._start_pos + field_offset, rel_offset)

    def set_list(self, field_offset: int, list_offset: int, length: int) -> None:
        self._ensure_field(field_offset + 8)
        if list_offset == 0 or length == 0:
            _U32.pack_into(self._b._buf, self._start_pos + field_offset, 0)
            _U32.pack_into(self._b._buf, self._start_pos + field_offset + 4, 0)
            return
        rel_offset = list_offset - (self._start_pos + field_offset)
        _I32.pack_into(self._b._buf, self._start_pos + field_offset, rel_offset)
        _U32.pack_into(self._b._buf, self._start_pos + field_offset + 4, length)

    def finish(self) -> int:
        self._ensure_field(self._data_size)
        b = self._b
        for entry in self._offsets:
            data_pos = b._pos
            b._grow(len(entry.data))
            b._buf[b._pos:b._pos + len(entry.data)] = entry.data
            b._pos += len(entry.data)
            field_abs_pos = self._start_pos + entry.field_offset
            rel_offset = data_pos - field_abs_pos
            _I32.pack_into(b._buf, field_abs_pos, rel_offset)
        return self._start_pos

    def finish_as_root(self) -> int:
        offset = self.finish()
        self._b._root_offset = offset
        return offset


class ListBuilder:
    """Builds a contiguous list of fixed-width elements."""

    __slots__ = ("_b", "_start_pos", "_elem_size", "_count")

    def __init__(self, b: Builder, start_pos: int, elem_size: int):
        self._b = b
        self._start_pos = start_pos
        self._elem_size = elem_size
        self._count = 0

    def add_uint8(self, v: int) -> None:
        self._b._grow(1)
        self._b._buf[self._b._pos] = v & 0xFF
        self._b._pos += 1
        self._count += 1

    def add_uint32(self, v: int) -> None:
        self._b._grow(4)
        _U32.pack_into(self._b._buf, self._b._pos, v & 0xFFFFFFFF)
        self._b._pos += 4
        self._count += 1

    def add_uint64(self, v: int) -> None:
        self._b._grow(8)
        _U64.pack_into(self._b._buf, self._b._pos, v & 0xFFFFFFFFFFFFFFFF)
        self._b._pos += 8
        self._count += 1

    def add_bytes(self, data: bytes) -> None:
        self._b._grow(len(data))
        self._b._buf[self._b._pos:self._b._pos + len(data)] = data
        self._b._pos += len(data)
        self._count += len(data)

    def finish(self) -> tuple[int, int]:
        return self._start_pos, self._count
