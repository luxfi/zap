// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"context"

	zaplib "github.com/luxfi/zap"
)

// relay.go adds the GATEWAY RELAY role to the HIP-0110 boundary.
//
// Production topology:
//
//	ingress (TLS + HTTP→ZAP)  →  gateway (relay: auth/billing on the
//	ENVELOPE)  →  cloud/base (ZAP→HTTP terminal)
//
// The gateway is a pure ZAP→ZAP relay. It runs auth and the prepaid
// balance gate by inspecting the Forward ENVELOPE — its Path and the JWT
// carried in its Headers — injects the validated identity, and forwards
// to the chosen backend. It does this WITHOUT deserializing the request
// body and WITHOUT re-serializing the backend's reply.
//
// # (De)serialization budget — read this before changing anything
//
// Per relayed request the gateway performs exactly ONE envelope
// re-encode and ZERO body deserializations:
//
//   - The inbound Forward is decoded with ReadForward, which references
//     Body as a sub-slice of the message buffer — Body is NEVER JSON-
//     parsed. The Gate reads Path + Headers only.
//   - Identity injection requires re-emitting the Forward, because the
//     identity text fields (TenantID, UserID) live in the object's
//     variable-length tail; growing/shrinking them shifts every later
//     field, so an in-place same-length overwrite is not generally
//     possible. BuildForward(f) therefore runs once. That copies the
//     body BYTES (a memcpy inside the ObjectBuilder's SetBytes) but
//     never interprets them.
//   - The backend Response is returned as the raw *zaplib.Message. It is
//     NOT ReadResponse'd and NOT BuildResponse'd — the bytes pass
//     straight through, correlated back to the original caller by the
//     ZAP request/response layer (reqID), not by message type.
//
// So: 1 envelope re-encode (with a body memcpy), 0 body deserializations,
// 0 response re-encodes.
//
// TODO(zerocopy): eliminate the body memcpy in identity injection. Two
// viable shapes, neither half-implemented here:
//
//  1. Trailing-frame body — carry Body as a separate length-prefixed
//     frame appended after the Forward object, so re-emitting identity
//     only rewrites the (small, fixed-ish) object and re-attaches the
//     untouched body frame by reference.
//  2. Fixed-width identity prefix — reserve a fixed-width region at the
//     head of the object for TenantID/UserID/IsAdmin/Permissions so the
//     gateway can overwrite it in place (same length) and resend the
//     original buffer with no rebuild at all.
//
// Both are wire breaks and want their own HIP revision; do not bolt a
// partial version onto this file.

// Gate is the gateway-supplied policy run on each inbound Forward
// ENVELOPE. It reads f.Headers (to find and validate the JWT) and
// f.Path, runs the prepaid balance gate, and EITHER:
//
//   - mutates f's identity fields in place — f.TenantID, f.UserID,
//     f.IsAdmin, f.Permissions — and returns (nil, nil) to ALLOW, or
//   - returns a non-nil *Response to short-circuit (deny), e.g.
//     {Status: 401} for a bad token or {Status: 402, Body:
//     insufficient_balance JSON} when the balance gate trips.
//
// A Gate MUST NOT read or copy f.Body. It operates on the envelope only.
// If it returns a non-nil error the relay surfaces it to the ZAP layer
// (the caller's Call fails); use a deny *Response for ordinary policy
// rejections so the client sees a clean HTTP status.
type Gate func(ctx context.Context, f *Forward) (deny *Response, err error)

// PeerPicker chooses the backend node for a request path. It mirrors
// pickBackend from the gateway: /v1/base/* routes to the base peer,
// everything else routes to the cloud peer (which fans out to the
// per-subsystem services). It is given the Forward's Path (raw query
// included) and returns the backend NodeID to Call.
type PeerPicker func(path string) (peerID string)

// Relay registers the gateway relay handler on node for MsgTypeForward.
//
// On each inbound Forward the relay:
//
//  1. ReadForward(msg) — decodes the envelope (Body stays a sub-slice;
//     it is not decoded).
//  2. gate(ctx, &f) — runs auth + the balance gate on the envelope. A
//     non-nil deny Response short-circuits: the relay returns it
//     immediately via BuildResponse and NEVER touches a backend. A
//     non-nil error is returned to the ZAP layer. Otherwise the gate has
//     mutated f's identity fields in place and the request is allowed.
//  3. BuildForward(f) — re-emits the Forward carrying the injected
//     identity (the single per-request envelope re-encode; see the
//     budget note above), then node.Call(ctx, pick(f.Path), augmented)
//     forwards it to the chosen backend.
//  4. returns the backend's reply *zaplib.Message VERBATIM — no
//     ReadResponse/BuildResponse round-trip, the response bytes pass
//     through unchanged.
func Relay(node *zaplib.Node, gate Gate, pick PeerPicker) {
	node.Handle(MsgTypeForward, func(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
		// Decode the envelope. ReadForward references Body as a sub-slice
		// of msg's buffer; the body is never deserialized here.
		f := ReadForward(msg)

		// Auth + balance gate on the ENVELOPE (Path + JWT in Headers).
		deny, err := gate(ctx, &f)
		if err != nil {
			return nil, err
		}
		if deny != nil {
			// Short-circuit: deny without ever reaching a backend.
			return BuildResponse(*deny)
		}

		// Allowed: the gate has injected identity into f in place.
		// Re-emit the Forward once (the only envelope re-encode; copies
		// the body bytes via memcpy but never parses them) and forward.
		augmented, err := BuildForward(f)
		if err != nil {
			return nil, err
		}

		// Pass the backend's reply straight back. node.Call returns the
		// backend's Response *Message; we return it verbatim so its bytes
		// flow to the original caller unchanged (no Response decode/encode).
		return node.Call(ctx, pick(f.Path), augmented)
	})
}
