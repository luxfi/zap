// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestKATStaticTranscript loads testdata/zap-pq-v1/*.json and replays
// every static-transcript vector through the transcript + KDF
// pipeline, asserting byte-for-byte agreement with the expected
// outputs.
//
// Adding a new vector: drop a JSON file alongside the existing one,
// generate values once with the same code, paste them in, commit.
// Modifying §7 or §8 without bumping the ciphersuite byte will flip
// these and fail the test — that is the point of KATs.
func TestKATStaticTranscript(t *testing.T) {
	dir := filepath.Join("testdata", "zap-pq-v1")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	hits := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		hits++
		path := filepath.Join(dir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			runStaticTranscriptKAT(t, path)
		})
	}
	if hits == 0 {
		t.Fatal("no KAT vectors found in testdata/zap-pq-v1")
	}
}

type katVector struct {
	Name     string                 `json:"name"`
	Spec     string                 `json:"spec"`
	Inputs   map[string]interface{} `json:"inputs"`
	Expected map[string]string      `json:"expected"`
}

func runStaticTranscriptKAT(t *testing.T, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var v katVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.Spec != "SPEC-ZAP-PQ-v1" {
		t.Skipf("vector targets %q, not SPEC-ZAP-PQ-v1", v.Spec)
	}

	hello := katBytes(t, v.Inputs, "hello_body")
	init := katBytes(t, v.Inputs, "kem_init")
	reply := katBytes(t, v.Inputs, "kem_reply")
	pkI := katBytes(t, v.Inputs, "static_pk_initiator")
	pkR := katBytes(t, v.Inputs, "static_pk_responder")
	xShared := katFixed32(t, v.Inputs, "x25519_shared")
	mlkemShared := katFixed32(t, v.Inputs, "mlkem_shared")

	tr := NewTranscript(SuiteX25519MLKEM)
	tr.AbsorbHello(hello)
	h0 := tr.H0()
	tr.AbsorbKEM(init, reply)
	h1 := tr.H1()
	h2 := tr.FinishFull(pkI, pkR, []SuiteID{SuiteX25519MLKEM})
	keys := DeriveSession(h2, xShared, mlkemShared)

	check(t, v.Expected, "H_0", h0[:])
	check(t, v.Expected, "H_1", h1[:])
	check(t, v.Expected, "H_2", h2[:])
	check(t, v.Expected, "k_i2r", keys.KInitToResp[:])
	check(t, v.Expected, "k_r2i", keys.KRespToInit[:])
	check(t, v.Expected, "salt_i2r", keys.SaltInitToResp[:])
	check(t, v.Expected, "salt_r2i", keys.SaltRespToInit[:])
	check(t, v.Expected, "resumption_psk", keys.ResumptionPSK[:])
}

// katBytes resolves a JSON input field to a []byte. Two shapes are
// supported:
//
//   "field": "0xabcd..."                       -> hex string
//   "field": {"pattern_base": "0xAA", "length": N}  -> generated pattern
func katBytes(t *testing.T, in map[string]interface{}, name string) []byte {
	t.Helper()
	raw, ok := in[name]
	if !ok {
		t.Fatalf("KAT missing input %q", name)
	}
	switch v := raw.(type) {
	case string:
		b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err != nil {
			t.Fatalf("KAT input %q hex: %v", name, err)
		}
		return b
	case map[string]interface{}:
		baseStr, _ := v["pattern_base"].(string)
		base, err := strconv.ParseUint(strings.TrimPrefix(baseStr, "0x"), 16, 8)
		if err != nil {
			t.Fatalf("KAT input %q pattern_base: %v", name, err)
		}
		lenF, _ := v["length"].(float64)
		out := make([]byte, int(lenF))
		for i := range out {
			out[i] = byte(int(base) + i)
		}
		return out
	}
	t.Fatalf("KAT input %q unsupported shape %T", name, raw)
	return nil
}

func katFixed32(t *testing.T, in map[string]interface{}, name string) [32]byte {
	t.Helper()
	b := katBytes(t, in, name)
	if len(b) != 32 {
		t.Fatalf("KAT input %q must be 32 bytes, got %d", name, len(b))
	}
	var a [32]byte
	copy(a[:], b)
	return a
}

func check(t *testing.T, expected map[string]string, name string, got []byte) {
	t.Helper()
	wantHex, ok := expected[name]
	if !ok {
		t.Fatalf("KAT expected missing %q", name)
	}
	want, err := hex.DecodeString(strings.TrimPrefix(wantHex, "0x"))
	if err != nil {
		t.Fatalf("KAT expected %q hex: %v", name, err)
	}
	if !equalBytes(got, want) {
		t.Errorf("%s mismatch\n want: %s\n got:  %s", name,
			hex.EncodeToString(want), hex.EncodeToString(got))
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
