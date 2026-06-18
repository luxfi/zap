// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

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

// errorResponse renders a fail-closed JSON error Response. The body is a
// fixed JSON shape so callers (and the bridged *http.Response) get a
// well-formed payload, never leaked internal detail. status is the HTTP
// code to surface to the original client.
func errorResponse(status int, reason string) Response {
	body, _ := json.Marshal(map[string]string{"error": reason})
	hdr, _ := json.Marshal(map[string][]string{"Content-Type": {"application/json"}})
	return Response{Status: status, Headers: hdr, Body: body}
}

// validForwardLine reports whether method+path can be safely turned into an
// *http.Request. It rejects:
//   - methods that are not a single HTTP token (RFC 7230 §3.2.6) — this
//     excludes spaces, CR, LF, NUL, and all separators/control bytes;
//   - paths carrying any control byte (C0 incl. CR/LF/NUL, or DEL), and
//     paths that url.ParseRequestURI cannot parse (e.g. a non-absolute
//     target).
//
// A space in the path is NOT rejected: url.ParseRequestURI percent-encodes
// it to %20 — a space cannot split a header/request line the way the
// control bytes can, so encoding it is the correct, non-lossy outcome.
//
// On success it returns the cleaned method and the parsed *url.URL so the
// caller builds the request from already-validated values. Empty method
// defaults to GET and empty path to "/" (the legacy lenient behaviour),
// but a NON-empty malformed value is rejected, never defaulted.
func validForwardLine(method, path string) (cleanMethod string, u *url.URL, reason string, ok bool) {
	if method == "" {
		method = http.MethodGet
	} else if !isHTTPToken(method) {
		// An HTTP method is a single token (RFC 7230 §3.2.6: 1*tchar). A
		// method with a space ("GE T"), CR, LF, NUL, or any separator/
		// control byte is not a token and is rejected here — this is the
		// exact grammar net/http's own (unexported) validMethod enforces.
		return "", nil, "invalid method", false
	}

	if path == "" {
		path = "/"
	}
	// Reject control bytes (C0 + DEL) outright before parsing. These are the
	// bytes that, left in a path, can ride into a request line / log line and
	// split it; url.Parse would silently encode some and tolerate others, so
	// we refuse them up front. The 3-header identity contract in base
	// (claims.hasControlByte) rejects the same byte class for symmetry.
	if hasControlByte(path) {
		return "", nil, "invalid path", false
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil {
		return "", nil, "invalid path", false
	}
	return method, parsed, "", true
}

// hasControlByte reports whether s contains any C0 control byte (< 0x20,
// includes NUL/TAB/CR/LF) or DEL (0x7f). These are the universal
// primitives for request-line / header / log injection and never appear in
// a legitimate method or request-target. Mirrors base's claims parser.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

// handle turns one Forward into one Response by invoking h. Exported logic
// lives here (not in the closure) so it is unit-testable without two live
// nodes — feed a Forward, assert the Response.
//
// Hostile input is rejected BEFORE any *http.Request is constructed: a
// malformed method or path yields a 400 Response, never a panic. (The prior
// implementation called httptest.NewRequest directly, which panics on a
// method containing a space or a path containing a control byte — an
// unrecovered panic in the dispatch goroutine. node.go's dispatch now also
// recovers as defence in depth, but the contract refuses to generate the
// panic in the first place.)
func handle(ctx context.Context, h http.Handler, f Forward) Response {
	method, u, reason, ok := validForwardLine(f.Method, f.Path)
	if !ok {
		return errorResponse(http.StatusBadRequest, reason)
	}

	// Build the request from already-validated values via the non-panicking
	// constructor. http.NewRequestWithContext re-checks the method and URL
	// and returns an error (never panics) on anything we missed.
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(f.Body))
	if err != nil {
		return errorResponse(http.StatusBadRequest, "invalid request")
	}
	req.RequestURI = "" // a server-side request must not carry RequestURI

	// Decode the client headers JSON onto the request. Reject header NAMES
	// that are not valid HTTP tokens and VALUES that carry CR/LF/NUL so a
	// crafted Headers blob cannot smuggle a header or split a downstream
	// log/response. (req.Header.Add would also reject these at write time in
	// recent Go, but we filter explicitly so behaviour is deterministic and
	// independent of stdlib internals.)
	if len(f.Headers) > 0 {
		var hdrs map[string][]string
		if err := json.Unmarshal(f.Headers, &hdrs); err == nil {
			for k, vs := range hdrs {
				if !isHTTPToken(k) {
					continue
				}
				for _, v := range vs {
					if !validHeaderValue(v) {
						continue
					}
					req.Header.Add(k, v)
				}
			}
		}
	}

	// Strip the FULL canonical identity set the client may have smuggled in
	// the Headers blob, THEN inject the edge-validated identity. Only the
	// edge may assert identity; the gateway strips inbound, this is
	// defence-in-depth at the ZAP trust boundary. Mirrors base's
	// claims.StripIdentityHeaders so the same forged-identity vectors are
	// closed on both legs of the contract.
	stripClientIdentity(req.Header)
	if f.TenantID != "" {
		req.Header.Set(HeaderOrgID, f.TenantID)
	}
	if f.UserID != "" {
		req.Header.Set(HeaderUserID, f.UserID)
	}
	req.Header.Set(HeaderUserIsAdmin, strconv.FormatBool(f.IsAdmin))
	req.Header.Set(HeaderUserPerms, strconv.FormatInt(f.Permissions, 10))

	// Streaming guard: a handler that declares an SSE/streaming response
	// would otherwise be buffered until idle-timeout (no Push path yet —
	// see TODO(stream) below). Detect it post-hoc via the recorder's
	// committed headers and surface a clear 501 instead of hanging.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if isStreamingResponse(rec.Header()) {
		// TODO(stream): when h flushes (http.Flusher) a flush-aware
		// ResponseWriter should emit Push frames (BuildPush, Encoding=
		// EncSSE/EncWS*) back to node for ConnID=f.ConnID instead of
		// buffering. Until then a streaming content-type cannot be served
		// over a single buffered Response — fail loud, don't hang.
		return errorResponse(http.StatusNotImplemented, "streaming not supported over Forward yet")
	}

	hdrJSON, _ := json.Marshal(map[string][]string(rec.Header()))
	return Response{
		Status:  rec.Code,
		Headers: hdrJSON,
		Body:    rec.Body.Bytes(),
	}
}

// isStreamingResponse reports whether the handler committed a streaming
// content type that the buffered Response path cannot carry. SSE is the
// canonical case; chunked text/event-stream is detected by the media type
// regardless of any trailing "; charset=" parameter.
func isStreamingResponse(h http.Header) bool {
	ct := h.Get("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// tokenTable marks the bytes that are valid in an HTTP token (RFC 7230
// §3.2.6: tchar). A token excludes all CTLs (incl. NUL/CR/LF), SP, and the
// separator set ()<>@,;:\"/[]?={}. This is the byte-for-byte table net/http
// uses internally (its private isTokenTable). Kept local so this core
// module needs no golang.org/x/net (which would drag golang.org/x/text via
// idna) for two table lookups.
var tokenTable = [256]bool{
	'!': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'*': true, '+': true, '-': true, '.': true, '^': true, '_': true,
	'`': true, '|': true, '~': true,
	'0': true, '1': true, '2': true, '3': true, '4': true, '5': true,
	'6': true, '7': true, '8': true, '9': true,
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true,
	'G': true, 'H': true, 'I': true, 'J': true, 'K': true, 'L': true,
	'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true,
	'S': true, 'T': true, 'U': true, 'V': true, 'W': true, 'X': true,
	'Y': true, 'Z': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
	'g': true, 'h': true, 'i': true, 'j': true, 'k': true, 'l': true,
	'm': true, 'n': true, 'o': true, 'p': true, 'q': true, 'r': true,
	's': true, 't': true, 'u': true, 'v': true, 'w': true, 'x': true,
	'y': true, 'z': true,
}

// isHTTPToken reports whether s is a non-empty HTTP token (1*tchar). Used
// to validate the request method and every client-supplied header NAME.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenTable[s[i]] {
			return false
		}
	}
	return true
}

// validHeaderValue reports whether s is a safe HTTP header field-value: no
// CR, LF, or NUL (the bytes that split a header / smuggle a response).
// Matches httpguts.ValidHeaderFieldValue's rejection set; TAB and other
// VCHAR/obs-text bytes are permitted as the RFC allows.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\r', '\n', 0x00:
			return false
		}
	}
	return true
}
