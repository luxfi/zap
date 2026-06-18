// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package forward is the canonical HIP-0110 "HTTP-over-ZAP" contract.
//
// It is the single source of truth for the gateway↔backend boundary,
// replacing the two inconsistent ad-hoc encodings that previously lived
// in the gateway repo (zap_wire.go and zap_backend.go). Three envelopes
// cover the entire boundary:
//
//	Forward  — gateway → backend, one per inbound HTTP request, carrying
//	           the edge-validated identity (so the backend trusts the edge).
//	Response — backend → gateway, the buffered HTTP response for a Forward.
//	Push     — backend → gateway, one per server-initiated stream frame
//	           (SSE / WebSocket), correlated to a Forward by ConnID.
//
// On-wire bytes are github.com/luxfi/zap Objects. Every field is packed
// at an explicit byte offset within the object's fixed payload.
//
// # Offset discipline
//
// luxfi/zap's ObjectBuilder.SetBytes / SetText write an 8-byte slot at
// the field offset: {relOffset uint32, length uint32}. The variable-
// length data tail is appended after the fixed section in Finish(), and
// the relOffset is patched to point at it. Consequently EVERY text or
// bytes field consumes 8 bytes of fixed payload — adjacent text fields
// MUST be spaced 8 bytes apart or their slots overlap and corrupt each
// other (proven empirically: a 4-byte-spaced layout drops the body).
//
// Fixed scalars use their natural width (bool=1, uint32=4, int64=8) and
// are placed on a natural boundary. These offsets are the contract;
// changing one is a wire break.
package forward

import (
	zaplib "github.com/luxfi/zap"
)

// HIP-0110 message-type IDs. The ZAP dispatcher routes on
// msg.Flags()>>8, and FinishWithFlags(t<<8) tags the message, so a type
// must fit in the upper byte of a uint16 (i.e. uint8). The 0x80+ range
// avoids collision with base/plugins/zap's lower-byte IDs (Collections=100,
// Records=101, Auth=102, Realtime=103).
const (
	MsgTypeForward uint16 = 0x80
	MsgTypePush    uint16 = 0x81
)

// Identity headers injected by the service side so the backend trusts the
// edge's pre-validated identity. These follow the vendor-free X-* header
// convention (no X-Hanzo-*, no X-IAM-*).
const (
	HeaderOrgID       = "X-Org-Id"
	HeaderUserID      = "X-User-Id"
	HeaderUserIsAdmin = "X-User-IsAdmin"
	HeaderUserPerms   = "X-User-Permissions"
)

// Canonical Encoding values on a Push envelope.
const (
	EncSSE      = "sse"
	EncWSText   = "ws-text"
	EncWSBinary = "ws-binary"
)

// Forward field offsets within the object's fixed payload. Text/bytes
// slots are 8 bytes (relOffset+length); scalars are natural-width and
// naturally aligned. See the package-doc "Offset discipline" note.
const (
	fwdIsAdmin     = 0  // bool   (1)
	fwdPermissions = 8  // int64  (8, 8-aligned)
	fwdTenantID    = 16 // text   (8)
	fwdUserID      = 24 // text   (8)
	fwdMethod      = 32 // text   (8)
	fwdPath        = 40 // text   (8)  -- includes raw query string
	fwdConnID      = 48 // text   (8)
	fwdHeaders     = 56 // bytes  (8)  -- JSON map[string][]string
	fwdBody        = 64 // bytes  (8)
	fwdSlotSize    = 72
)

// Response field offsets. status@0 (uint32), then body, then headers-JSON,
// each text/bytes slot 8 bytes apart.
const (
	respStatus   = 0  // uint32 (4)
	respBody     = 8  // bytes  (8)
	respHeaders  = 16 // bytes  (8) -- JSON map[string][]string
	respSlotSize = 24
)

// Push field offsets.
const (
	pushConnID   = 0  // text  (8)
	pushFrame    = 8  // bytes (8) -- pre-encoded SSE / WS payload
	pushEncoding = 16 // text  (8)
	pushSlotSize = 24
)

// Forward is the typed view of the gateway→backend envelope. Path
// includes the raw query string (there is no separate query field).
type Forward struct {
	TenantID    string // X-Org-Id (JWT 'owner')
	UserID      string // X-User-Id (JWT 'sub')
	IsAdmin     bool   // X-User-IsAdmin (JWT 'isAdmin')
	Permissions int64  // X-User-Permissions (bit field)
	Method      string // GET, POST, ...
	Path        string // /v1/iam/users/123?expand=roles  (query included)
	Headers     []byte // JSON map[string][]string, canonicalized client headers
	Body        []byte // raw client body, verbatim
	ConnID      string // gateway-assigned conn id for reverse push
}

// Response is the typed view of the backend→gateway response envelope.
type Response struct {
	Status  int    // HTTP status code
	Headers []byte // JSON map[string][]string
	Body    []byte // raw response body, verbatim
}

// Push is the typed view of the backend→gateway reverse-push envelope.
type Push struct {
	ConnID   string // correlates to the Forward's ConnID
	Frame    []byte // pre-encoded SSE / WebSocket payload
	Encoding string // "sse" | "ws-text" | "ws-binary"
}

// BuildForward serializes f into a ZAP message tagged MsgTypeForward.
func BuildForward(f Forward) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(fwdSlotSize + len(f.Headers) + len(f.Body) +
		len(f.TenantID) + len(f.UserID) + len(f.Method) + len(f.Path) + len(f.ConnID) + 64)
	ob := b.StartObject(fwdSlotSize)
	ob.SetBool(fwdIsAdmin, f.IsAdmin)
	ob.SetInt64(fwdPermissions, f.Permissions)
	ob.SetText(fwdTenantID, f.TenantID)
	ob.SetText(fwdUserID, f.UserID)
	ob.SetText(fwdMethod, f.Method)
	ob.SetText(fwdPath, f.Path)
	ob.SetText(fwdConnID, f.ConnID)
	ob.SetBytes(fwdHeaders, f.Headers)
	ob.SetBytes(fwdBody, f.Body)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgTypeForward << 8))
}

// ReadForward decodes a Forward envelope from a parsed message.
func ReadForward(msg *zaplib.Message) Forward {
	r := msg.Root()
	return Forward{
		IsAdmin:     r.Bool(fwdIsAdmin),
		Permissions: r.Int64(fwdPermissions),
		TenantID:    r.Text(fwdTenantID),
		UserID:      r.Text(fwdUserID),
		Method:      r.Text(fwdMethod),
		Path:        r.Text(fwdPath),
		ConnID:      r.Text(fwdConnID),
		Headers:     r.Bytes(fwdHeaders),
		Body:        r.Bytes(fwdBody),
	}
}

// BuildResponse serializes r into a ZAP message. Status rides as a
// uint32; body and headers-JSON follow, matching the Response read order.
func BuildResponse(r Response) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(respSlotSize + len(r.Body) + len(r.Headers) + 32)
	ob := b.StartObject(respSlotSize)
	ob.SetUint32(respStatus, uint32(r.Status))
	ob.SetBytes(respBody, r.Body)
	ob.SetBytes(respHeaders, r.Headers)
	ob.FinishAsRoot()
	// Response is the reply leg of a Call; the dispatcher does not route
	// it by type, but tag it for symmetry and debuggability.
	return zaplib.Parse(b.FinishWithFlags(MsgTypeForward << 8))
}

// ReadResponse decodes a Response envelope from a parsed message.
func ReadResponse(msg *zaplib.Message) Response {
	r := msg.Root()
	return Response{
		Status:  int(r.Uint32(respStatus)),
		Body:    r.Bytes(respBody),
		Headers: r.Bytes(respHeaders),
	}
}

// BuildPush serializes p into a ZAP message tagged MsgTypePush.
func BuildPush(p Push) (*zaplib.Message, error) {
	b := zaplib.NewBuilder(pushSlotSize + len(p.Frame) + len(p.ConnID) + len(p.Encoding) + 16)
	ob := b.StartObject(pushSlotSize)
	ob.SetText(pushConnID, p.ConnID)
	ob.SetBytes(pushFrame, p.Frame)
	ob.SetText(pushEncoding, p.Encoding)
	ob.FinishAsRoot()
	return zaplib.Parse(b.FinishWithFlags(MsgTypePush << 8))
}

// ReadPush decodes a Push envelope from a parsed message.
func ReadPush(msg *zaplib.Message) Push {
	r := msg.Root()
	return Push{
		ConnID:   r.Text(pushConnID),
		Frame:    r.Bytes(pushFrame),
		Encoding: r.Text(pushEncoding),
	}
}
