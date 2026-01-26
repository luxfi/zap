// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/json"
	"testing"
)

// Simulated protobuf-style message for comparison
// This uses manual varint encoding to simulate protobuf overhead
type ProtoMessage struct {
	Id     uint64
	Value  uint64
	Count  uint32
	Active bool
}

// Simple manual encoding to simulate protobuf overhead
func (m *ProtoMessage) MarshalSimple() []byte {
	buf := make([]byte, 32)
	n := 0
	// Field 1: id (varint)
	buf[n] = 0x08 // field 1, varint
	n++
	n += encodeVarint(buf[n:], m.Id)
	// Field 2: value (varint)
	buf[n] = 0x10 // field 2, varint
	n++
	n += encodeVarint(buf[n:], m.Value)
	// Field 3: count (varint)
	buf[n] = 0x18 // field 3, varint
	n++
	n += encodeVarint(buf[n:], uint64(m.Count))
	// Field 4: active (varint)
	buf[n] = 0x20 // field 4, varint
	n++
	if m.Active {
		buf[n] = 1
	} else {
		buf[n] = 0
	}
	n++
	return buf[:n]
}

func (m *ProtoMessage) UnmarshalSimple(data []byte) error {
	i := 0
	for i < len(data) {
		tag := data[i]
		i++
		field := tag >> 3
		switch field {
		case 1:
			v, n := decodeVarint(data[i:])
			m.Id = v
			i += n
		case 2:
			v, n := decodeVarint(data[i:])
			m.Value = v
			i += n
		case 3:
			v, n := decodeVarint(data[i:])
			m.Count = uint32(v)
			i += n
		case 4:
			m.Active = data[i] != 0
			i++
		}
	}
	return nil
}

func encodeVarint(buf []byte, v uint64) int {
	i := 0
	for v >= 0x80 {
		buf[i] = byte(v) | 0x80
		v >>= 7
		i++
	}
	buf[i] = byte(v)
	return i + 1
}

func decodeVarint(data []byte) (uint64, int) {
	var v uint64
	for i, b := range data {
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1
		}
	}
	return v, len(data)
}

// JSON message for comparison
type JSONMessage struct {
	Id     uint64 `json:"id"`
	Value  uint64 `json:"value"`
	Count  uint32 `json:"count"`
	Active bool   `json:"active"`
}

// Benchmark: Protobuf-style encoding (simulated)
func BenchmarkProtobufEncode(b *testing.B) {
	msg := &ProtoMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg.Id = uint64(i)
		_ = msg.MarshalSimple()
	}
}

// Benchmark: Protobuf-style decoding (simulated)
func BenchmarkProtobufDecode(b *testing.B) {
	msg := &ProtoMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}
	data := msg.MarshalSimple()

	result := &ProtoMessage{}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result.UnmarshalSimple(data)
	}
}

// Benchmark: JSON encoding
func BenchmarkJSONEncode(b *testing.B) {
	msg := &JSONMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		msg.Id = uint64(i)
		_, _ = json.Marshal(msg)
	}
}

// Benchmark: JSON decoding
func BenchmarkJSONDecode(b *testing.B) {
	msg := &JSONMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}
	data, _ := json.Marshal(msg)

	result := &JSONMessage{}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = json.Unmarshal(data, result)
	}
}

// Comparison summary test
func TestSerializationComparison(t *testing.T) {
	// ZAP
	zapBuilder := NewBuilder(256)
	obj := zapBuilder.StartObject(64)
	obj.SetUint64(0, 12345678)
	obj.SetUint64(8, 0xDEADBEEF)
	obj.SetUint32(16, 12345)
	obj.SetBool(20, true)
	obj.FinishAsRoot()
	zapData := zapBuilder.Finish()

	// Protobuf (simulated)
	protoMsg := &ProtoMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}
	protoData := protoMsg.MarshalSimple()

	// JSON
	jsonMsg := &JSONMessage{
		Id:     12345678,
		Value:  0xDEADBEEF,
		Count:  12345,
		Active: true,
	}
	jsonData, _ := json.Marshal(jsonMsg)

	t.Logf("Message sizes:")
	t.Logf("  ZAP:      %d bytes", len(zapData))
	t.Logf("  Protobuf: %d bytes", len(protoData))
	t.Logf("  JSON:     %d bytes", len(jsonData))
}
