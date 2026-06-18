// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"

	zaplib "github.com/luxfi/zap"
)

// Serve registers the canonical MsgTypeForward handler on node, dispatching
// each Forward envelope to h. The handler reconstructs the *http.Request,
// injects the edge-validated identity as X-* headers (so the backend trusts
// the edge), serves it through h, and returns a Response envelope carrying
// the captured status, headers, and body.
//
// Streaming (SSE / chunked) is not yet emitted as Push frames: the full
// response is buffered and returned as one Response. The extension point is
// marked below.
func Serve(node *zaplib.Node, h http.Handler) {
	node.Handle(MsgTypeForward, func(ctx context.Context, from string, msg *zaplib.Message) (*zaplib.Message, error) {
		f := ReadForward(msg)
		return BuildResponse(handle(ctx, h, f))
	})
}

// handle turns one Forward into one Response by invoking h. Exported logic
// lives here (not in the closure) so it is unit-testable without two live
// nodes — feed a Forward, assert the Response.
func handle(ctx context.Context, h http.Handler, f Forward) Response {
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	path := f.Path
	if path == "" {
		path = "/"
	}

	// httptest.NewRequest parses Path (incl. raw query) into URL.Path +
	// URL.RawQuery. The body is the verbatim client bytes.
	req := httptest.NewRequest(method, path, bytes.NewReader(f.Body))
	req = req.WithContext(ctx)
	req.RequestURI = "" // a server-side request must not carry RequestURI

	// Decode the client headers JSON onto the request.
	if len(f.Headers) > 0 {
		var hdrs map[string][]string
		if err := json.Unmarshal(f.Headers, &hdrs); err == nil {
			for k, vs := range hdrs {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}
		}
	}

	// Inject the pre-validated identity. Strip any client-supplied copies
	// first — only the edge may assert identity (gateway already strips
	// these inbound, this is defence-in-depth at the trust boundary).
	req.Header.Del(HeaderOrgID)
	req.Header.Del(HeaderUserID)
	req.Header.Del(HeaderUserIsAdmin)
	req.Header.Del(HeaderUserPerms)
	if f.TenantID != "" {
		req.Header.Set(HeaderOrgID, f.TenantID)
	}
	if f.UserID != "" {
		req.Header.Set(HeaderUserID, f.UserID)
	}
	req.Header.Set(HeaderUserIsAdmin, strconv.FormatBool(f.IsAdmin))
	req.Header.Set(HeaderUserPerms, strconv.FormatInt(f.Permissions, 10))

	// TODO(stream): when h's handler flushes (http.Flusher), a flush-aware
	// ResponseWriter should emit Push frames (BuildPush, Encoding=EncSSE/
	// EncWS*) back to node for ConnID=f.ConnID instead of buffering. For now
	// we buffer the full response — correct, just not incremental.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	hdrJSON, _ := json.Marshal(map[string][]string(rec.Header()))
	return Response{
		Status:  rec.Code,
		Headers: hdrJSON,
		Body:    rec.Body.Bytes(),
	}
}
