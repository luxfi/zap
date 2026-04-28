"""EVM-type roundtrip tests for zap_py.

The Go-built fixture is consumed by test_evm_go_fixture; build it with
`go run ./python/testdata/gen_evm_fixture.go > /tmp/zap_evm_fixture.bin`.
"""

import os

import pytest

from zap_py import (
    ADDRESS_SIZE,
    Address,
    Builder,
    HASH_SIZE,
    Hash,
    SIGNATURE_SIZE,
    Signature,
    ZERO_ADDRESS,
    ZERO_HASH,
    address_from_hex,
    hash_from_hex,
    parse,
)


VITALIK = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
SAMPLE_HASH = "0x" + "ab" * 32
SAMPLE_SIG = bytes(range(SIGNATURE_SIZE))


def test_address_roundtrip():
    addr = address_from_hex(VITALIK)
    assert len(addr) == ADDRESS_SIZE
    assert not addr.is_zero()
    assert addr.hex() == VITALIK
    assert str(addr) == VITALIK
    assert bytes(addr) == bytes.fromhex(VITALIK[2:])


def test_address_hex_with_uppercase_prefix():
    addr = address_from_hex("0X" + VITALIK[2:])
    assert addr == address_from_hex(VITALIK)


def test_address_invalid_length():
    with pytest.raises(ValueError):
        address_from_hex("0xdead")
    with pytest.raises(ValueError):
        Address(b"\x00" * 19)


def test_hash_roundtrip():
    h = hash_from_hex(SAMPLE_HASH)
    assert len(h) == HASH_SIZE
    assert not h.is_zero()
    assert h.hex() == SAMPLE_HASH


def test_zero_values():
    assert ZERO_ADDRESS.is_zero()
    assert ZERO_HASH.is_zero()
    assert ZERO_ADDRESS == Address(b"\x00" * ADDRESS_SIZE)


def test_object_address_hash_signature():
    addr = address_from_hex(VITALIK)
    h = hash_from_hex(SAMPLE_HASH)
    sig = Signature(SAMPLE_SIG)

    b = Builder()
    ob = b.start_object(ADDRESS_SIZE + HASH_SIZE + SIGNATURE_SIZE)
    ob.set_address(0, addr)
    ob.set_hash(ADDRESS_SIZE, h)
    ob.set_signature(ADDRESS_SIZE + HASH_SIZE, sig)
    ob.finish_as_root()

    root = parse(b.finish()).root()
    assert root.address(0) == addr
    assert root.hash(ADDRESS_SIZE) == h
    assert root.signature(ADDRESS_SIZE + HASH_SIZE) == sig


def test_address_slice_is_zero_copy():
    addr = address_from_hex(VITALIK)
    b = Builder()
    ob = b.start_object(ADDRESS_SIZE)
    ob.set_address(0, addr)
    ob.finish_as_root()
    msg = parse(b.finish())
    view = msg.root().address_slice(0)
    assert isinstance(view, memoryview)
    assert bytes(view) == addr.bytes


def test_set_address_accepts_raw_bytes():
    raw = bytes.fromhex(VITALIK[2:])
    b = Builder()
    ob = b.start_object(ADDRESS_SIZE)
    ob.set_address(0, raw)
    ob.finish_as_root()
    assert parse(b.finish()).root().address(0).hex() == VITALIK


def test_set_address_rejects_wrong_length():
    b = Builder()
    ob = b.start_object(ADDRESS_SIZE)
    with pytest.raises(ValueError):
        ob.set_address(0, b"\x00" * 19)


def test_address_list():
    addrs = [
        address_from_hex(VITALIK),
        address_from_hex(USDC),
        Address(b"\xff" * ADDRESS_SIZE),
    ]
    b = Builder()
    lb = b.start_list(ADDRESS_SIZE)
    for a in addrs:
        lb.add_bytes(a.bytes)
    list_offset, list_len = lb.finish()
    # add_bytes counts bytes; convert to element count
    elem_count = list_len // ADDRESS_SIZE

    ob = b.start_object(8)
    ob.set_list(0, list_offset, elem_count)
    ob.finish_as_root()

    root = parse(b.finish()).root()
    lst = root.list(0)
    assert len(lst) == len(addrs)
    for i, a in enumerate(addrs):
        assert lst.address(i) == a


def test_hash_list():
    hashes = [hash_from_hex(SAMPLE_HASH), Hash(b"\x00" * HASH_SIZE), Hash(b"\xab" * HASH_SIZE)]
    b = Builder()
    lb = b.start_list(HASH_SIZE)
    for h in hashes:
        lb.add_bytes(h.bytes)
    list_offset, list_len = lb.finish()
    elem_count = list_len // HASH_SIZE

    ob = b.start_object(8)
    ob.set_list(0, list_offset, elem_count)
    ob.finish_as_root()

    root = parse(b.finish()).root()
    lst = root.list(0)
    assert len(lst) == len(hashes)
    for i, h in enumerate(hashes):
        assert lst.hash(i) == h


def test_address_equality_with_bytes():
    addr = address_from_hex(VITALIK)
    assert addr == bytes.fromhex(VITALIK[2:])
    assert addr != bytes.fromhex(USDC[2:])


@pytest.mark.skipif(
    not os.environ.get("ZAP_GO_EVM_FIXTURE"),
    reason="set ZAP_GO_EVM_FIXTURE=path/to/fixture.bin (built with gen_evm_fixture.go)",
)
def test_evm_go_fixture_interop():
    """End-to-end: a Go-built EVM-typed message parses correctly in Python."""
    with open(os.environ["ZAP_GO_EVM_FIXTURE"], "rb") as f:
        data = f.read()
    msg = parse(data)
    root = msg.root()
    # Layout matches gen_evm_fixture.go.
    assert root.address(0).hex() == VITALIK.lower()
    assert root.hash(ADDRESS_SIZE).hex() == SAMPLE_HASH
    assert root.signature(ADDRESS_SIZE + HASH_SIZE) == Signature(SAMPLE_SIG)

    # List of addresses at the end.
    lst = root.list(ADDRESS_SIZE + HASH_SIZE + SIGNATURE_SIZE)
    assert len(lst) == 2
    assert lst.address(0).hex() == VITALIK.lower()
    assert lst.address(1).hex() == USDC.lower()
