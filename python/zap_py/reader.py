"""Zero-copy reader for ZAP messages.

Mirrors zap.go. Backing storage is a memoryview so slicing does not
copy — the same read-side guarantees as the Go side.
"""

from __future__ import annotations

import struct
from typing import Optional, Union

from .wire import (
    HEADER_SIZE,
    MAGIC,
    VERSION,
    BufferTooSmall,
    InvalidMagic,
    InvalidVersion,
)

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")
_I8 = struct.Struct("<b")
_I16 = struct.Struct("<h")
_I32 = struct.Struct("<i")
_I64 = struct.Struct("<q")
_F32 = struct.Struct("<f")
_F64 = struct.Struct("<d")


def parse(data: Union[bytes, bytearray, memoryview]) -> "Message":
    """Parse a ZAP message without copying the backing bytes."""
    if len(data) < HEADER_SIZE:
        raise BufferTooSmall(f"need {HEADER_SIZE} bytes, got {len(data)}")
    view = memoryview(data) if not isinstance(data, memoryview) else data
    if bytes(view[0:4]) != MAGIC:
        raise InvalidMagic(f"got {bytes(view[0:4])!r}, expected {MAGIC!r}")
    version, = _U16.unpack_from(view, 4)
    if version != VERSION:
        raise InvalidVersion(f"version {version} not supported")
    size, = _U32.unpack_from(view, 12)
    if size > len(view):
        raise BufferTooSmall(f"declared size {size} > buffer {len(view)}")
    return Message(view[:size])


class Message:
    """A parsed ZAP message. Backed by a memoryview — no copy."""

    __slots__ = ("_data",)

    def __init__(self, data: memoryview):
        self._data = data

    @property
    def data(self) -> memoryview:
        return self._data

    def size(self) -> int:
        return len(self._data)

    def flags(self) -> int:
        return _U16.unpack_from(self._data, 6)[0]

    def root(self) -> "Object":
        offset, = _U32.unpack_from(self._data, 8)
        return Object(self, int(offset))

    def __len__(self) -> int:
        return len(self._data)


class Object:
    """Zero-copy view of a ZAP struct."""

    __slots__ = ("_msg", "_offset")

    def __init__(self, msg: Optional[Message], offset: int):
        self._msg = msg
        self._offset = offset

    @property
    def offset(self) -> int:
        return self._offset

    def is_null(self) -> bool:
        return self._msg is None or self._offset == 0

    def _abs(self, field_offset: int) -> int:
        return self._offset + field_offset

    def bool(self, field_offset: int) -> bool:
        return self.uint8(field_offset) != 0

    def uint8(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos >= len(self._msg._data):
            return 0
        return self._msg._data[pos]

    def uint16(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 2 > len(self._msg._data):
            return 0
        return _U16.unpack_from(self._msg._data, pos)[0]

    def uint32(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 4 > len(self._msg._data):
            return 0
        return _U32.unpack_from(self._msg._data, pos)[0]

    def uint64(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 8 > len(self._msg._data):
            return 0
        return _U64.unpack_from(self._msg._data, pos)[0]

    def int8(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos >= len(self._msg._data):
            return 0
        return _I8.unpack_from(self._msg._data, pos)[0]

    def int16(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 2 > len(self._msg._data):
            return 0
        return _I16.unpack_from(self._msg._data, pos)[0]

    def int32(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 4 > len(self._msg._data):
            return 0
        return _I32.unpack_from(self._msg._data, pos)[0]

    def int64(self, field_offset: int) -> int:
        pos = self._abs(field_offset)
        if pos + 8 > len(self._msg._data):
            return 0
        return _I64.unpack_from(self._msg._data, pos)[0]

    def float32(self, field_offset: int) -> float:
        pos = self._abs(field_offset)
        if pos + 4 > len(self._msg._data):
            return 0.0
        return _F32.unpack_from(self._msg._data, pos)[0]

    def float64(self, field_offset: int) -> float:
        pos = self._abs(field_offset)
        if pos + 8 > len(self._msg._data):
            return 0.0
        return _F64.unpack_from(self._msg._data, pos)[0]

    def bytes(self, field_offset: int) -> bytes:
        view = self.bytes_view(field_offset)
        return bytes(view) if view is not None else b""

    def bytes_view(self, field_offset: int) -> Optional[memoryview]:
        """Like .bytes() but returns a zero-copy memoryview slice."""
        pos = self._abs(field_offset)
        data = self._msg._data
        if pos + 4 > len(data):
            return None
        rel_offset = _I32.unpack_from(data, pos)[0]
        if rel_offset == 0:
            return None
        if pos + 8 > len(data):
            return None
        length = _U32.unpack_from(data, pos + 4)[0]
        abs_pos = pos + rel_offset
        if abs_pos < 0 or abs_pos + length > len(data):
            return None
        return data[abs_pos:abs_pos + length]

    def text(self, field_offset: int) -> str:
        view = self.bytes_view(field_offset)
        if view is None:
            return ""
        return bytes(view).decode("utf-8")

    def object(self, field_offset: int) -> "Object":
        pos = self._abs(field_offset)
        data = self._msg._data
        if pos + 4 > len(data):
            return Object(None, 0)
        rel_offset = _I32.unpack_from(data, pos)[0]
        if rel_offset == 0:
            return Object(None, 0)
        abs_offset = pos + rel_offset
        if abs_offset < 0 or abs_offset >= len(data):
            return Object(None, 0)
        return Object(self._msg, abs_offset)

    def list(self, field_offset: int) -> "List":
        pos = self._abs(field_offset)
        data = self._msg._data
        if pos + 8 > len(data):
            return List(None, 0, 0)
        rel_offset = _I32.unpack_from(data, pos)[0]
        if rel_offset == 0:
            return List(None, 0, 0)
        length = _U32.unpack_from(data, pos + 4)[0]
        abs_offset = pos + rel_offset
        if abs_offset < 0 or abs_offset >= len(data):
            return List(None, 0, 0)
        return List(self._msg, abs_offset, int(length))


class List:
    """Zero-copy view of a ZAP list."""

    __slots__ = ("_msg", "_offset", "_length")

    def __init__(self, msg: Optional[Message], offset: int, length: int):
        self._msg = msg
        self._offset = offset
        self._length = length

    def is_null(self) -> bool:
        return self._msg is None

    def __len__(self) -> int:
        return self._length

    def len(self) -> int:
        return self._length

    def uint8(self, i: int) -> int:
        if i < 0 or i >= self._length:
            return 0
        pos = self._offset + i
        if pos >= len(self._msg._data):
            return 0
        return self._msg._data[pos]

    def uint32(self, i: int) -> int:
        if i < 0 or i >= self._length:
            return 0
        pos = self._offset + i * 4
        if pos + 4 > len(self._msg._data):
            return 0
        return _U32.unpack_from(self._msg._data, pos)[0]

    def uint64(self, i: int) -> int:
        if i < 0 or i >= self._length:
            return 0
        pos = self._offset + i * 8
        if pos + 8 > len(self._msg._data):
            return 0
        return _U64.unpack_from(self._msg._data, pos)[0]

    def object(self, i: int, elem_size: int) -> Object:
        if i < 0 or i >= self._length:
            return Object(None, 0)
        return Object(self._msg, self._offset + i * elem_size)

    def bytes(self) -> bytes:
        if self._msg is None:
            return b""
        end = self._offset + self._length
        if end > len(self._msg._data):
            return b""
        return bytes(self._msg._data[self._offset:end])
