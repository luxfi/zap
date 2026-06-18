// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"

	zaplib "github.com/luxfi/zap"
)

// Forwarder is the gateway-side client: it tunnels an *http.Request to a
// backend Peer over ZAP and returns the *http.Response. It is an
// http.RoundTripper, so it drops into any http.Client/transport chain.
type Forwarder struct {
	Node *zaplib.Node // started ZAP node
	Peer string       // backend NodeID to Call
}

var _ http.RoundTripper = (*Forwarder)(nil)

// RoundTrip serializes req into a Forward (lifting the edge-validated
// identity out of the X-* headers if present), Calls the peer, and rebuilds
// the *http.Response from the Response envelope.
func (f *Forwarder) RoundTrip(req *http.Request) (*http.Response, error) {
	fwd, err := requestToForward(req)
	if err != nil {
		return nil, err
	}
	msg, err := BuildForward(fwd)
	if err != nil {
		return nil, err
	}
	resp, err := f.Node.Call(req.Context(), f.Peer, msg)
	if err != nil {
		return nil, err
	}
	return responseFromEnvelope(req, ReadResponse(resp)), nil
}

// requestToForward reads req (method, path+query, headers, body) into a
// Forward. Identity is taken from the X-* headers when the edge already set
// them; otherwise the identity fields stay zero.
func requestToForward(req *http.Request) (Forward, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return Forward{}, err
		}
		_ = req.Body.Close()
		body = b
	}

	// Path carries the raw query string inline (no separate query field).
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	// Copy headers, but never forward the identity headers as opaque client
	// data — they are promoted to typed Forward fields below.
	h := req.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	// Lift the edge-validated identity out of the X-* headers into the typed
	// fields. These four are only honoured here because by the time a request
	// reaches the gateway-side Forwarder the gateway has ALREADY validated the
	// JWT and re-set them; a request that bypassed the gateway carries no
	// trustworthy values and the full strip below scrubs everything regardless.
	isAdmin, _ := strconv.ParseBool(h.Get(HeaderUserIsAdmin))
	perms, _ := strconv.ParseInt(h.Get(HeaderUserPerms), 10, 64)
	fwd := Forward{
		TenantID:    h.Get(HeaderOrgID),
		UserID:      h.Get(HeaderUserID),
		IsAdmin:     isAdmin,
		Permissions: perms,
		Method:      req.Method,
		Path:        path,
		Body:        body,
	}
	// Strip the FULL canonical identity set (not just the 4 promoted ones) so
	// no forged identity header — X-Roles, X-User-Email, X-IAM-*, X-Hanzo-*,
	// X-Gateway-*, identity cookies — is ever serialized into the envelope.
	// Authorization (the Bearer JWT base validates) is preserved.
	stripClientIdentity(h)

	if len(h) > 0 {
		hdrJSON, err := json.Marshal(map[string][]string(h))
		if err != nil {
			return Forward{}, err
		}
		fwd.Headers = hdrJSON
	}
	return fwd, nil
}

// responseFromEnvelope rebuilds an *http.Response from a decoded Response.
func responseFromEnvelope(req *http.Request, r Response) *http.Response {
	header := http.Header{}
	if len(r.Headers) > 0 {
		var hdrs map[string][]string
		if err := json.Unmarshal(r.Headers, &hdrs); err == nil {
			for k, vs := range hdrs {
				for _, v := range vs {
					header.Add(k, v)
				}
			}
		}
	}
	status := r.Status
	if status == 0 {
		status = http.StatusOK
	}
	// Copy the body: r.Body aliases the ZAP message buffer, which may be
	// released after this Call returns.
	body := append([]byte(nil), r.Body...)
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// --- Reverse-push registry (ported from gateway zap_wire.go) -------------
//
// SSE / WebSocket frames flow backend → gateway as Push envelopes. The
// gateway registers a PushSink per active client connection (keyed by the
// ConnID it minted on the originating Forward); HandleReversePush routes
// each inbound Push to the matching sink.

// PushSink delivers a Push frame to a live client connection.
type PushSink interface {
	Deliver(ctx context.Context, p Push) error
}

var pushRegistry sync.Map // ConnID → PushSink

// RegisterReversePush records the sink for an active SSE / WS subscription.
func RegisterReversePush(connID string, sink PushSink) { pushRegistry.Store(connID, sink) }

// UnregisterReversePush drops the sink when the client connection closes.
func UnregisterReversePush(connID string) { pushRegistry.Delete(connID) }

// HandleReversePush is the zaplib.Handler for MsgTypePush. It decodes the
// Push, looks up the sink for its ConnID, and delivers. An unknown ConnID
// (client already gone) is a silent no-op. A delivery error drops the sink.
func HandleReversePush(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
	p := ReadPush(msg)
	v, ok := pushRegistry.Load(p.ConnID)
	if !ok {
		return nil, nil
	}
	sink, ok := v.(PushSink)
	if !ok {
		return nil, nil
	}
	if err := sink.Deliver(ctx, p); err != nil {
		pushRegistry.Delete(p.ConnID)
		return nil, err
	}
	return nil, nil
}

// RegisterReversePushHandler installs HandleReversePush on node so a
// Forwarder's node receives backend-initiated Push frames.
func RegisterReversePushHandler(node *zaplib.Node) {
	node.Handle(MsgTypePush, HandleReversePush)
}
