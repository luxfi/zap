// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/binary"
)

// node_codec.go decomplects two pieces of wire framing that previously
// appeared in three places each:
//
//  1. The NodeID handshake message (64-byte ZAP object: bytes 0..59 =
//     UTF-8 nodeID, bytes 60..63 = length). Used at connection open
//     by both the dialer (ConnectDirect) and the acceptor (handleConn).
//  2. The Call/response correlation header (8 bytes: reqID u32 LE,
//     flag u32 LE) prepended to a wrapped ZAP message. Used by Call,
//     by the incoming-Call response path in handleConn, and by the
//     handleConn dispatcher to recognise the frame shape.
//
// Both have exactly one encoder and one decoder. Callers wire-encode
// and wire-decode through the same path; bugs surface in one place.

// --- NodeID handshake codec ---

// nodeIDHandshakeSize is the size of the handshake message on the
// wire — header (16) + a single 64-byte object.
const nodeIDHandshakeSize = HeaderSize + 64

// maxNodeIDLen is the largest UTF-8 nodeID we serialise; longer IDs
// are truncated by the encoder and rejected by the decoder.
const maxNodeIDLen = 60

// EncodeNodeIDHandshake builds the NodeID exchange message.
// nodeIDs longer than maxNodeIDLen are truncated; the receiver
// validates length on Decode.
func EncodeNodeIDHandshake(nodeID string) []byte {
	b := NewBuilder(128)
	obj := b.StartObject(64)
	idBytes := []byte(nodeID)
	n := len(idBytes)
	if n > maxNodeIDLen {
		n = maxNodeIDLen
	}
	for i := 0; i < n; i++ {
		obj.SetUint8(i, idBytes[i])
	}
	obj.SetUint32(maxNodeIDLen, uint32(n))
	obj.FinishAsRoot()
	return b.Finish()
}

// DecodeNodeIDHandshake reads a NodeID exchange message and returns
// the peer's nodeID. An empty string (with ok=false) indicates a
// malformed or out-of-range length field.
func DecodeNodeIDHandshake(data []byte) (string, bool) {
	msg, err := Parse(data)
	if err != nil {
		return "", false
	}
	root := msg.Root()
	idLen := root.Uint32(maxNodeIDLen)
	if idLen == 0 || idLen > maxNodeIDLen {
		return "", false
	}
	idBytes := make([]byte, idLen)
	for i := uint32(0); i < idLen; i++ {
		idBytes[i] = root.Uint8(int(i))
	}
	return string(idBytes), true
}

// --- Call/response correlation header ---

// correlatedHeaderSize is the 8-byte ReqID + Flag preamble that
// distinguishes a Call request/response from a Send.
const correlatedHeaderSize = 8

// WrapCorrelated prepends the Call/response correlation header to
// `body`. The result is what writeMessage emits onto the wire.
func WrapCorrelated(reqID uint32, flag uint32, body []byte) []byte {
	out := make([]byte, correlatedHeaderSize+len(body))
	binary.LittleEndian.PutUint32(out[0:4], reqID)
	binary.LittleEndian.PutUint32(out[4:8], flag)
	copy(out[correlatedHeaderSize:], body)
	return out
}

// UnwrapCorrelated reads the correlation header off `data` and
// returns (reqID, flag, body, ok). If `data` is shorter than the
// header or the flag isn't a recognised value, ok is false and
// the caller should treat the message as uncorrelated.
func UnwrapCorrelated(data []byte) (reqID uint32, flag uint32, body []byte, ok bool) {
	if len(data) < correlatedHeaderSize {
		return 0, 0, nil, false
	}
	reqID = binary.LittleEndian.Uint32(data[0:4])
	flag = binary.LittleEndian.Uint32(data[4:8])
	if flag != ReqFlagReq && flag != ReqFlagResp {
		return 0, 0, nil, false
	}
	return reqID, flag, data[correlatedHeaderSize:], true
}
