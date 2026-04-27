# zap_py — Python client for ZAP

Pure-stdlib Python reader and builder for the ZAP wire format. Lets non-Go
peers (AI agents, ops scripts, FHE clients, kcolbchain switchboard/monsoon
agents) speak ZAP without leaving Python.

Wire-compatible with `github.com/luxfi/zap`. Tested in both directions.

## Install

No package install — drop the `zap_py/` directory next to your code, or add
`python/` to `PYTHONPATH`. Python ≥ 3.8, no third-party dependencies.

## Read

```python
from zap_py import parse

msg = parse(wire_bytes)
root = msg.root()
print(root.uint32(0))     # 42
print(root.text(16))      # "from go"
print(root.bytes(24))     # b"\x01\x02\x03\x04"

inner = root.object(32)
print(inner.uint32(0))    # 7

lst = root.list(40)
for i in range(len(lst)):
    print(lst.uint32(i))
```

`parse()` accepts `bytes`, `bytearray`, or `memoryview`. The returned
`Message` keeps a `memoryview` over the original buffer — slicing and
`.bytes_view()` stay zero-copy.

## Build

```python
from zap_py import Builder

b = Builder(256)

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

wire = b.finish()              # bytes, ready to send
wire = b.finish_with_flags(0)  # explicit flag word
```

Field offsets and data sizes mirror the Go schema exactly — same constants
work on both sides.

## Tests

```bash
cd python
python -m venv .venv && .venv/bin/pip install pytest
.venv/bin/pytest tests
```

12 tests cover: header validation, scalar/text/bytes roundtrip, lists,
nested objects, null pointers, flag bits, invalid magic/version, and
zero-copy `memoryview` access.

## Cross-language interop

Two parity tests confirm wire compatibility against the Go reference:

**Go-built → Python-parsed:**

```bash
go run ./python/testdata/gen_fixture.go > /tmp/zap_fixture.bin
ZAP_GO_FIXTURE=/tmp/zap_fixture.bin python -m pytest python/tests/test_roundtrip.py::test_go_fixture_interop
```

**Python-built → Go-parsed:**

```bash
python python/testdata/gen_python_fixture.py > /tmp/zap_python_fixture.bin
ZAP_PYTHON_FIXTURE=/tmp/zap_python_fixture.bin go test -run TestPythonFixture
```

Both fixtures use identical schemas; the resulting binaries differ only in
their embedded text payload, byte-for-byte.

## Coverage

| Wire feature | Reader | Builder |
|---|---|---|
| Header (magic/version/flags/size) | ✓ | ✓ |
| `bool`, `uint8/16/32/64`, `int8/16/32/64`, `float32/64` | ✓ | ✓ |
| `text`, `bytes` (zero-copy view available) | ✓ | ✓ |
| Nested objects (relative offsets) | ✓ | ✓ |
| Lists of `uint8`/`uint32`/`uint64`/objects/raw bytes | ✓ | ✓ |
| Null object / null list | ✓ | ✓ |

Not yet ported: EVM helpers (`Address`, `Hash`, `Signature`), MCP bridge,
mDNS node, schema DSL. The reader/builder is enough to interop with any
Go ZAP service that publishes a fixed schema. Higher-level helpers can
follow as Python use cases land.
