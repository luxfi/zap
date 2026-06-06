# zapcodec

ZAP-native little-endian reflection codec for the Lux platform.

See [LLM.md](./LLM.md) for the full module spec, wire format, and history.

```go
import (
    "github.com/luxfi/zapcodec"
    "github.com/luxfi/utils/wrappers"
)

c := zapcodec.NewDefault()
_ = c.RegisterType(&MyConcrete{})

p := &wrappers.Packer{MaxSize: 1 << 20}
_ = c.MarshalInto(value, p)
```

For the canonical version-prefix outer layer used by the SDK wallet,
see `github.com/luxfi/proto/zap_codec.NewVersionedManager`.

Extracted from `github.com/luxfi/codec/zapcodec` in Wave 2G-Archive.
