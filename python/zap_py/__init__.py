"""Python client for the ZAP zero-copy application protocol.

Mirrors the Go implementation at github.com/luxfi/zap. Lets non-Go peers
(AI agents, ops scripts, FHE clients) read and build ZAP messages
without leaving Python.
"""

from .wire import (
    HEADER_SIZE,
    MAGIC,
    VERSION,
    DEFAULT_PORT,
    ALIGNMENT,
    FLAG_NONE,
    FLAG_COMPRESSED,
    FLAG_ENCRYPTED,
    FLAG_SIGNED,
    InvalidMagic,
    InvalidVersion,
    BufferTooSmall,
    OutOfBounds,
    InvalidOffset,
)
from .evm import (
    ADDRESS_SIZE,
    BLOOM_SIZE,
    HASH_SIZE,
    SIGNATURE_SIZE,
    Address,
    Bloom,
    Hash,
    Signature,
    ZERO_ADDRESS,
    ZERO_HASH,
    address_from_hex,
    hash_from_hex,
)
from .reader import Message, Object, List, parse
from .builder import Builder, ObjectBuilder, ListBuilder

__all__ = [
    "HEADER_SIZE",
    "MAGIC",
    "VERSION",
    "DEFAULT_PORT",
    "ALIGNMENT",
    "FLAG_NONE",
    "FLAG_COMPRESSED",
    "FLAG_ENCRYPTED",
    "FLAG_SIGNED",
    "InvalidMagic",
    "InvalidVersion",
    "BufferTooSmall",
    "OutOfBounds",
    "InvalidOffset",
    "Message",
    "Object",
    "List",
    "parse",
    "Builder",
    "ObjectBuilder",
    "ListBuilder",
    "ADDRESS_SIZE",
    "HASH_SIZE",
    "SIGNATURE_SIZE",
    "BLOOM_SIZE",
    "Address",
    "Hash",
    "Signature",
    "Bloom",
    "ZERO_ADDRESS",
    "ZERO_HASH",
    "address_from_hex",
    "hash_from_hex",
]
