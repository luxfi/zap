// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// neverCalled is a handler that fails the test if it is ever invoked. Used
// to prove hostile input is rejected BEFORE reaching the application.
func neverCalled(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler must not run for hostile input; ran for %q %q", r.Method, r.URL)
	})
}

// --- V4: hostile method / path → 400, NEVER a panic ---------------------

func TestHandleHostileMethodPathReturns400NotPanic(t *testing.T) {
	// Every one of these tripped httptest.NewRequest's panic in the old
	// implementation (method/path injected verbatim into a raw HTTP request
	// line fed to http.ReadRequest — a space split the line, CR/LF smuggled
	// a second line, NUL broke the parser). They must now yield a clean 400
	// with the handler NEVER invoked: these are the injection bytes that can
	// split a request/header/log, so the only safe action is to refuse.
	cases := []struct {
		name         string
		method, path string
	}{
		{"method with space", "GE T", "/v1/x"},
		{"method with CRLF", "GET\r\nX-Evil: 1", "/v1/x"},
		{"method with NUL", "GET\x00", "/v1/x"},
		{"method with tab", "GET\t", "/v1/x"},
		{"method with separator comma", "GE,T", "/v1/x"},
		{"method with separator paren", "GET()", "/v1/x"},
		{"path with NUL", http.MethodGet, "/v1/x\x00"},
		{"path with CR", http.MethodGet, "/v1/x\r/y"},
		{"path with LF", http.MethodGet, "/v1/x\n/y"},
		{"path with CRLF header injection", http.MethodGet, "/v1/x\r\nX-Evil: 1"},
		{"path with control byte 0x1f", http.MethodGet, "/v1/\x1f"},
		{"path with DEL 0x7f", http.MethodGet, "/v1/\x7f"},
		{"path not absolute", http.MethodGet, "v1/x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// If handle panicked, the test binary would crash; reaching the
			// assertion at all is half the proof. recover() here would only
			// fire if handle itself re-introduced a panic — it must not.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handle panicked on hostile input (%q %q): %v", tc.method, tc.path, r)
				}
			}()
			resp := handle(context.Background(), neverCalled(t), Forward{
				Method: tc.method,
				Path:   tc.path,
			})
			if resp.Status < 400 || resp.Status >= 500 {
				t.Fatalf("hostile input got status %d, want 4xx", resp.Status)
			}
			// Error body is well-formed JSON with an "error" key, never a leak.
			var e map[string]string
			if err := json.Unmarshal(resp.Body, &e); err != nil {
				t.Fatalf("error body not JSON: %q (%v)", resp.Body, err)
			}
			if e["error"] == "" {
				t.Errorf("error body missing reason: %q", resp.Body)
			}
		})
	}
}

// TestHandleSpaceInPathIsSafelyEncodedNotPanic documents that a SPACE in
// the path — which crashed the old httptest.NewRequest path — is now safely
// percent-encoded by url.ParseRequestURI rather than rejected. The space is
// not an injection byte (it cannot split a header/log the way CR/LF/NUL
// can); encoding it to %20 is the correct, non-lossy, non-panicking
// outcome. The contract is "no panic, no smuggling", which encoding
// satisfies.
func TestHandleSpaceInPathIsSafelyEncodedNotPanic(t *testing.T) {
	var gotPath string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path // decoded form
		w.WriteHeader(http.StatusOK)
	})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("space in path panicked: %v", r)
		}
	}()
	resp := handle(context.Background(), h, Forward{Method: http.MethodGet, Path: "/v1/x y"})
	if resp.Status != http.StatusOK {
		t.Fatalf("space-in-path got %d, want 200 (safely encoded)", resp.Status)
	}
	// The decoded path is intact; no second request line was smuggled.
	if gotPath != "/v1/x y" {
		t.Errorf("decoded path = %q, want %q", gotPath, "/v1/x y")
	}
}

func TestHandleEmptyMethodPathStillDefaults(t *testing.T) {
	// Backwards-compatible leniency: EMPTY method/path default to GET / "/".
	// (Only NON-empty malformed values are rejected.)
	var gotMethod, gotPath string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	resp := handle(context.Background(), h, Forward{}) // all zero
	if resp.Status != http.StatusNoContent {
		t.Fatalf("status: got %d want 204", resp.Status)
	}
	if gotMethod != http.MethodGet || gotPath != "/" {
		t.Errorf("defaults wrong: method=%q path=%q want GET /", gotMethod, gotPath)
	}
}

func TestHandleValidMethodsPass(t *testing.T) {
	for _, m := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions, "PROPFIND", "MKCOL",
	} {
		ran := false
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran = true
			w.WriteHeader(http.StatusOK)
		})
		resp := handle(context.Background(), h, Forward{Method: m, Path: "/v1/x"})
		if !ran {
			t.Errorf("method %q was rejected but is a valid token", m)
		}
		if resp.Status != http.StatusOK {
			t.Errorf("method %q got status %d want 200", m, resp.Status)
		}
	}
}

// --- V2: FULL identity strip — smuggled identity must not survive --------

func TestHandleStripsFullIdentitySet(t *testing.T) {
	// A hostile client packs every identity-bearing header into the Headers
	// blob. None may reach the handler. Edge identity (here: only TenantID)
	// is the sole survivor for the canonical 4, injected AFTER the strip.
	smuggled := map[string][]string{
		HeaderOrgID:            {"evil-org"},
		HeaderUserID:           {"evil-user"},
		HeaderUserIsAdmin:      {"true"},
		HeaderUserPerms:        {"9223372036854775807"},
		"X-Roles":              {"admin,root"},
		"X-User-Email":         {"attacker@evil.test"},
		"X-User-Role":          {"superuser"},
		"X-User-Roles":         {"admin"},
		"X-User-Name":          {"mallory"},
		"X-Tenant-Id":          {"evil-tenant"},
		"X-Tenant-ID":          {"evil-tenant-2"},
		"X-Org":                {"evil"},
		"X-Is-Admin":           {"1"},
		"X-Phone-Number":       {"+10000000000"},
		"X-Gateway-Validated":  {"true"},
		"X-Gateway-User-Id":    {"evil"},
		"X-Gateway-Org-Id":     {"evil"},
		"X-Gateway-User-Email": {"evil@evil.test"},
		"X-IAM-User":           {"evil"},
		"X-IAM-Roles":          {"admin"},
		"X-Hanzo-Org":          {"evil"},
		"X-Hanzo-User-Id":      {"evil"},
		"Cookie":               {"session=hijacked; iam_token=forged"},
		// A benign header that MUST survive the strip.
		"Content-Type": {"application/json"},
		// Authorization MUST survive (the real auth path).
		"Authorization": {"Bearer real.jwt.token"},
	}
	blob, _ := json.Marshal(smuggled)

	var seen http.Header
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	handle(context.Background(), h, Forward{
		TenantID: "real-org", // the only edge-asserted identity
		Method:   http.MethodGet,
		Path:     "/v1/whoami",
		Headers:  blob,
	})

	// 1. Every smuggled identity header is gone or overwritten by the edge.
	if got := seen.Get(HeaderOrgID); got != "real-org" {
		t.Errorf("X-Org-Id: got %q, smuggled value must be replaced by edge 'real-org'", got)
	}
	if got := seen.Get(HeaderUserID); got != "" {
		t.Errorf("X-User-Id: smuggled %q survived (edge asserted none)", got)
	}
	// IsAdmin/Perms are re-injected from the (zero) Forward, overwriting the
	// smuggled "true"/max-int.
	if got := seen.Get(HeaderUserIsAdmin); got != "false" {
		t.Errorf("X-User-IsAdmin: got %q want false (smuggled true must be overridden)", got)
	}
	if got := seen.Get(HeaderUserPerms); got != "0" {
		t.Errorf("X-User-Permissions: got %q want 0 (smuggled max-int must be overridden)", got)
	}

	// 2. Every NON-injected identity header is fully absent.
	for _, h := range []string{
		"X-Roles", "X-User-Email", "X-User-Role", "X-User-Roles", "X-User-Name",
		"X-Tenant-Id", "X-Tenant-ID", "X-Org", "X-Is-Admin", "X-Phone-Number",
		"X-Gateway-Validated", "X-Gateway-User-Id", "X-Gateway-Org-Id", "X-Gateway-User-Email",
		"X-IAM-User", "X-IAM-Roles", "X-Hanzo-Org", "X-Hanzo-User-Id",
		"Cookie",
	} {
		if v := seen.Get(h); v != "" {
			t.Errorf("identity header %q leaked through with value %q", h, v)
		}
	}

	// 3. Authorization is PRESERVED — base validates the forwarded Bearer JWT.
	if got := seen.Get("Authorization"); got != "Bearer real.jwt.token" {
		t.Errorf("Authorization was stripped (%q); base needs it to validate the JWT", got)
	}
	// 4. Benign non-identity header survives.
	if got := seen.Get("Content-Type"); got != "application/json" {
		t.Errorf("benign Content-Type was dropped: %q", got)
	}
}

func TestRequestToForwardStripsFullIdentityFromEnvelope(t *testing.T) {
	// V2 gateway/ingress leg: a forged identity header must never even enter
	// the Forward envelope. requestToForward promotes the edge-validated 4
	// into typed fields and strips the FULL set from the carried Headers.
	req, _ := http.NewRequest(http.MethodPost, "http://backend/v1/x", strings.NewReader("body"))
	req.Header.Set(HeaderOrgID, "real-org")
	req.Header.Set(HeaderUserID, "real-user")
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-User-Email", "x@y.z")
	req.Header.Set("X-IAM-Token", "forged")
	req.Header.Set("X-Hanzo-Org", "evil")
	req.Header.Set("X-Gateway-Validated", "true")
	req.Header.Set("Cookie", "session=hijacked")
	req.Header.Set("Authorization", "Bearer real.jwt")
	req.Header.Set("Content-Type", "text/plain")

	fwd, err := requestToForward(req)
	if err != nil {
		t.Fatalf("requestToForward: %v", err)
	}
	// The 4 are promoted to typed fields.
	if fwd.TenantID != "real-org" || fwd.UserID != "real-user" {
		t.Errorf("identity not promoted: org=%q user=%q", fwd.TenantID, fwd.UserID)
	}
	// The carried Headers blob contains NO identity header, but keeps
	// Authorization + Content-Type.
	var carried map[string][]string
	if len(fwd.Headers) > 0 {
		_ = json.Unmarshal(fwd.Headers, &carried)
	}
	get := func(k string) string {
		// http.Header canonicalization is applied by Clone()+Del; the JSON
		// keys are canonical. Look up case-insensitively to be safe.
		for kk, vv := range carried {
			if strings.EqualFold(kk, k) && len(vv) > 0 {
				return vv[0]
			}
		}
		return ""
	}
	for _, leak := range []string{
		HeaderOrgID, HeaderUserID, "X-Roles", "X-User-Email",
		"X-IAM-Token", "X-Hanzo-Org", "X-Gateway-Validated", "Cookie",
	} {
		if v := get(leak); v != "" {
			t.Errorf("envelope carried forged identity header %q=%q", leak, v)
		}
	}
	if get("Authorization") != "Bearer real.jwt" {
		t.Errorf("Authorization missing from envelope; got %q", get("Authorization"))
	}
	if get("Content-Type") != "text/plain" {
		t.Errorf("benign Content-Type missing from envelope; got %q", get("Content-Type"))
	}
}

// --- V4: hostile header name/value in the Headers blob is filtered -------

func TestHandleFiltersHostileHeaderNamesAndValues(t *testing.T) {
	// A crafted Headers blob with an invalid header name and a CRLF-bearing
	// value must not inject headers into the served request.
	blob, _ := json.Marshal(map[string][]string{
		"X-Good":     {"fine"},
		"X-Bad Name": {"has space in name"},         // invalid token name
		"X-Inject":   {"ok\r\nX-Smuggled: evil"},    // CRLF in value
		"X-NulVal":   {"ok\x00evil"},                // NUL in value
		"X-Mixed":    {"first-ok", "bad\r\nsecond"}, // one good, one bad value
	})
	var seen http.Header
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	resp := handle(context.Background(), h, Forward{Method: http.MethodGet, Path: "/v1/x", Headers: blob})
	if resp.Status != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.Status)
	}
	if seen.Get("X-Good") != "fine" {
		t.Errorf("valid header dropped: X-Good=%q", seen.Get("X-Good"))
	}
	if got := seen.Get("X-Bad Name"); got != "" {
		t.Errorf("invalid header name was added: %q", got)
	}
	if got := seen.Get("X-Smuggled"); got != "" {
		t.Errorf("CRLF value smuggled a second header X-Smuggled=%q", got)
	}
	if got := seen.Get("X-Inject"); got != "" {
		t.Errorf("CRLF-bearing value was added: %q", got)
	}
	if got := seen.Get("X-NulVal"); got != "" {
		t.Errorf("NUL-bearing value was added: %q", got)
	}
	// X-Mixed: only the good value survives.
	if vals := seen.Values("X-Mixed"); len(vals) != 1 || vals[0] != "first-ok" {
		t.Errorf("X-Mixed values: got %v want [first-ok]", vals)
	}
}

// --- V6: streaming response over Forward → 501, not a hang ---------------

func TestHandleStreamingResponseReturns501(t *testing.T) {
	for _, ct := range []string{
		"text/event-stream",
		"text/event-stream; charset=utf-8",
		"Text/Event-Stream",
	} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: hi\n\n"))
		})
		resp := handle(context.Background(), h, Forward{Method: http.MethodGet, Path: "/v1/stream"})
		if resp.Status != http.StatusNotImplemented {
			t.Errorf("ct=%q: got status %d want 501", ct, resp.Status)
		}
		if !strings.Contains(string(resp.Body), "streaming not supported") {
			t.Errorf("ct=%q: body %q lacks streaming-not-supported reason", ct, resp.Body)
		}
	}
}

func TestHandleNonStreamingResponsePassesThrough(t *testing.T) {
	// A normal JSON response is NOT mistaken for streaming.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	resp := handle(context.Background(), h, Forward{Method: http.MethodGet, Path: "/v1/x"})
	if resp.Status != http.StatusOK {
		t.Fatalf("non-streaming response got %d want 200", resp.Status)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Errorf("body: %q", resp.Body)
	}
}
