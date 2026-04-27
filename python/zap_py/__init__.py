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
]
