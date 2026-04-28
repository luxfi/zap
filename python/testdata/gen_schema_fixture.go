// Dump Go-computed offsets and sizes for the predefined EVM schemas as
// JSON. The Python schema-parity test reads this back and compares.
//
//	go run ./python/testdata/gen_schema_fixture.go > /tmp/zap_schemas.json
//	ZAP_GO_SCHEMA_FIXTURE=/tmp/zap_schemas.json pytest python/tests/test_schema.py
//
//go:build ignore

package main

import (
	"encoding/json"
	"os"

	"github.com/luxfi/zap"
)

type fieldDump struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
}

type structDump struct {
	Size   int         `json:"size"`
	Fields []fieldDump `json:"fields"`
}

func dump(s *zap.Struct) structDump {
	out := structDump{Size: s.Size}
	for _, f := range s.Fields {
		out.Fields = append(out.Fields, fieldDump{Name: f.Name, Offset: f.Offset})
	}
	return out
}

func main() {
	out := map[string]structDump{
		"Transaction": dump(zap.TransactionSchema),
		"BlockHeader": dump(zap.BlockHeaderSchema),
		"Log":         dump(zap.LogSchema),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
