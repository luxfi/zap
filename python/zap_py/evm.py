"""EVM-compatible value types for ZAP messages.

Mirrors the Go evm.go: Address (20), Hash (32), Signature (65), Bloom (256).
The reader/builder methods that consume and emit these live on
Object/ObjectBuilder/List in reader.py and builder.py — kept there so
they have access to the underlying buffer state.
"""

from __future__ import annotations


ADDRESS_SIZE = 20
HASH_SIZE = 32
SIGNATURE_SIZE = 65
BLOOM_SIZE = 256


class _FixedBytes:
    """Common base for fixed-width byte values (Address/Hash/Signature/Bloom)."""

    SIZE = 0

    __slots__ = ("_b",)

    def __init__(self, data: bytes = b""):
        if not data:
            self._b = bytes(self.SIZE)
        else:
            if len(data) != self.SIZE:
                raise ValueError(
                    f"{type(self).__name__} expects {self.SIZE} bytes, got {len(data)}"
                )
            self._b = bytes(data)

    @classmethod
    def from_hex(cls, s: str):
        if len(s) >= 2 and s[0] == "0" and s[1] in ("x", "X"):
            s = s[2:]
        if len(s) != cls.SIZE * 2:
            raise ValueError(f"invalid {cls.__name__.lower()} length: {len(s)}")
        return cls(bytes.fromhex(s))

    def hex(self) -> str:
        return "0x" + self._b.hex()

    def is_zero(self) -> bool:
        return self._b == bytes(self.SIZE)

    @property
    def bytes(self) -> bytes:
        return self._b

    def __bytes__(self) -> bytes:
        return self._b

    def __len__(self) -> int:
        return self.SIZE

    def __eq__(self, other) -> bool:
        if isinstance(other, _FixedBytes):
            return self.SIZE == other.SIZE and self._b == other._b
        if isinstance(other, (bytes, bytearray)):
            return self._b == bytes(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._b))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.hex()})"

    def __str__(self) -> str:
        return self.hex()


class Address(_FixedBytes):
    """20-byte EVM address."""

    SIZE = ADDRESS_SIZE


class Hash(_FixedBytes):
    """32-byte hash (keccak256, blockhash, etc.)."""

    SIZE = HASH_SIZE


class Signature(_FixedBytes):
    """65-byte ECDSA signature: r[32] || s[32] || v[1]."""

    SIZE = SIGNATURE_SIZE


class Bloom(_FixedBytes):
    """256-byte log-bloom filter."""

    SIZE = BLOOM_SIZE


ZERO_ADDRESS = Address()
ZERO_HASH = Hash()


def address_from_hex(s: str) -> Address:
    return Address.from_hex(s)


def hash_from_hex(s: str) -> Hash:
    return Hash.from_hex(s)
