"""Build a deterministic ZAP message from Python.

Used by python_interop_test.go to confirm the Go reader accepts what
zap_py emits.

    python python/testdata/gen_python_fixture.py > /tmp/zap_python_fixture.bin
    ZAP_PYTHON_FIXTURE=/tmp/zap_python_fixture.bin go test -run TestPythonFixture
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zap_py import Builder


def build() -> bytes:
    b = Builder(512)

    inner = b.start_object(24)
    inner.set_uint32(0, 7)
    inner.set_text(8, "nested")
    inner_offset = inner.finish()

    lb = b.start_list(4)
    for v in (10, 20, 30, 40):
        lb.add_uint32(v)
    list_offset, list_len = lb.finish()

    root = b.start_object(56)
    root.set_uint32(0, 42)
    root.set_uint64(8, 0xDEADBEEFCAFEBABE)
    root.set_text(16, "from py")
    root.set_bytes(24, b"\x01\x02\x03\x04")
    root.set_object(32, inner_offset)
    root.set_list(40, list_offset, list_len)
    root.finish_as_root()

    return b.finish()


if __name__ == "__main__":
    sys.stdout.buffer.write(build())
