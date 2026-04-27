"""Python-only roundtrip tests for zap_py.

The Go-vs-Python interop test lives in test_go_fixture.py and consumes
a binary fixture emitted by `python/testdata/gen_fixture.go`.
"""

import math
import os

import pytest

from zap_py import (
    Builder,
    FLAG_COMPRESSED,
    FLAG_SIGNED,
    HEADER_SIZE,
    InvalidMagic,
    InvalidVersion,
    MAGIC,
    parse,
)


def test_header_basics():
    b = Builder()
    ob = b.start_object(8)
    ob.set_uint32(0, 42)
    ob.set_uint32(4, 0xDEADBEEF)
    ob.finish_as_root()
    data = b.finish()

    assert data[:4] == MAGIC
    assert len(data) >= HEADER_SIZE
    msg = parse(data)
    assert msg.size() == len(data)
    assert msg.flags() == 0


def test_scalar_roundtrip():
    b = Builder()
    ob = b.start_object(64)
    ob.set_bool(0, True)
    ob.set_uint8(1, 0xAB)
    ob.set_uint16(2, 0xBEEF)
    ob.set_uint32(4, 0xDEADBEEF)
    ob.set_uint64(8, 0x0123456789ABCDEF)
    ob.set_int32(16, -12345)
    ob.set_int64(20, -987654321)
    ob.set_float32(28, 1.5)
    ob.set_float64(32, math.pi)
    ob.finish_as_root()

    msg = parse(b.finish())
    root = msg.root()
    assert root.bool(0) is True
    assert root.uint8(1) == 0xAB
    assert root.uint16(2) == 0xBEEF
    assert root.uint32(4) == 0xDEADBEEF
    assert root.uint64(8) == 0x0123456789ABCDEF
    assert root.int32(16) == -12345
    assert root.int64(20) == -987654321
    assert root.float32(28) == 1.5
    assert math.isclose(root.float64(32), math.pi)


def test_text_and_bytes():
    b = Builder()
    ob = b.start_object(24)
    ob.set_uint32(0, 7)
    ob.set_text(8, "héllo, ZAP")
    ob.set_bytes(16, b"\x00\x01\x02\xff")
    ob.finish_as_root()

    msg = parse(b.finish())
    root = msg.root()
    assert root.uint32(0) == 7
    assert root.text(8) == "héllo, ZAP"
    assert root.bytes(16) == b"\x00\x01\x02\xff"


def test_empty_text_returns_null():
    b = Builder()
    ob = b.start_object(16)
    ob.set_text(0, "")
    ob.set_text(8, "non-empty")
    ob.finish_as_root()
    root = parse(b.finish()).root()
    assert root.text(0) == ""
    assert root.text(8) == "non-empty"


def test_uint32_list():
    b = Builder()
    lb = b.start_list(4)
    for v in (10, 20, 30, 40, 50):
        lb.add_uint32(v)
    list_offset, length = lb.finish()
    assert length == 5

    ob = b.start_object(8)
    ob.set_list(0, list_offset, length)
    ob.finish_as_root()

    root = parse(b.finish()).root()
    lst = root.list(0)
    assert lst.len() == 5
    assert [lst.uint32(i) for i in range(lst.len())] == [10, 20, 30, 40, 50]


def test_uint64_list():
    b = Builder()
    lb = b.start_list(8)
    for v in (1, 1 << 32, (1 << 63) | 1):
        lb.add_uint64(v)
    list_offset, length = lb.finish()
    ob = b.start_object(8)
    ob.set_list(0, list_offset, length)
    ob.finish_as_root()
    root = parse(b.finish()).root()
    lst = root.list(0)
    assert lst.len() == 3
    assert lst.uint64(0) == 1
    assert lst.uint64(1) == 1 << 32
    assert lst.uint64(2) == (1 << 63) | 1


def test_nested_object():
    b = Builder()
    inner = b.start_object(8)
    inner.set_uint32(0, 111)
    inner.set_uint32(4, 222)
    inner_offset = inner.finish()

    outer = b.start_object(16)
    outer.set_uint32(0, 999)
    outer.set_object(8, inner_offset)
    outer.finish_as_root()

    root = parse(b.finish()).root()
    assert root.uint32(0) == 999
    inner_view = root.object(8)
    assert not inner_view.is_null()
    assert inner_view.uint32(0) == 111
    assert inner_view.uint32(4) == 222


def test_null_object_and_list():
    b = Builder()
    ob = b.start_object(24)
    ob.set_uint32(0, 1)
    ob.set_object(8, 0)
    ob.set_list(12, 0, 0)
    ob.finish_as_root()
    root = parse(b.finish()).root()
    assert root.object(8).is_null()
    assert root.list(12).is_null()


def test_flags():
    b = Builder()
    ob = b.start_object(8)
    ob.set_uint32(0, 1)
    ob.finish_as_root()
    data = b.finish_with_flags(FLAG_COMPRESSED | FLAG_SIGNED)
    msg = parse(data)
    assert msg.flags() == FLAG_COMPRESSED | FLAG_SIGNED


def test_invalid_magic():
    bad = b"BAD\x00" + bytes(HEADER_SIZE - 4)
    with pytest.raises(InvalidMagic):
        parse(bad)


def test_invalid_version():
    buf = bytearray(HEADER_SIZE)
    buf[0:4] = MAGIC
    # version = 99
    buf[4] = 99
    buf[5] = 0
    # size = 16
    buf[12] = 16
    with pytest.raises(InvalidVersion):
        parse(bytes(buf))


def test_memoryview_zero_copy():
    b = Builder()
    ob = b.start_object(16)
    ob.set_text(0, "zero-copy view")
    ob.finish_as_root()
    data = b.finish()
    msg = parse(memoryview(data))
    view = msg.root().bytes_view(0)
    assert isinstance(view, memoryview)
    assert bytes(view) == b"zero-copy view"


@pytest.mark.skipif(
    not os.environ.get("ZAP_GO_FIXTURE"),
    reason="set ZAP_GO_FIXTURE=path/to/fixture.bin (built with gen_fixture.go)",
)
def test_go_fixture_interop():
    """End-to-end: parse a binary built by the Go reference implementation."""
    path = os.environ["ZAP_GO_FIXTURE"]
    with open(path, "rb") as f:
        data = f.read()
    msg = parse(data)
    root = msg.root()
    # Layout matches gen_fixture.go.
    assert root.uint32(0) == 42
    assert root.uint64(8) == 0xDEADBEEFCAFEBABE
    assert root.text(16) == "from go"
    assert root.bytes(24) == b"\x01\x02\x03\x04"
    inner = root.object(32)
    assert not inner.is_null()
    assert inner.uint32(0) == 7
    assert inner.text(8) == "nested"
    lst = root.list(40)
    assert lst.len() == 4
    assert [lst.uint32(i) for i in range(lst.len())] == [10, 20, 30, 40]
