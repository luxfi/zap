"""Wire-format constants and exceptions shared by reader and builder."""

HEADER_SIZE = 16
MAGIC = b"ZAP\x00"
VERSION = 1
DEFAULT_PORT = 9999
ALIGNMENT = 8

FLAG_NONE = 0
FLAG_COMPRESSED = 1 << 0
FLAG_ENCRYPTED = 1 << 1
FLAG_SIGNED = 1 << 2


class ZapError(Exception):
    pass


class InvalidMagic(ZapError):
    pass


class InvalidVersion(ZapError):
    pass


class BufferTooSmall(ZapError):
    pass


class OutOfBounds(ZapError):
    pass


class InvalidOffset(ZapError):
    pass
