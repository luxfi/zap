// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	zaplib "github.com/luxfi/zap"
)

// --- Round-trip: proves the Object offsets pack/unpack correctly --------

func TestForwardRoundTrip(t *testing.T) {
	hdr, _ := json.Marshal(map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"text/event-stream", "*/*"},
	})
	in := Forward{
		TenantID:    "acme",
		UserID:      "user-42",
		IsAdmin:     true,
		Permissions: 0x0FED_CBA9_8765_4321,
		Method:      http.MethodPost,
		Path:        "/v1/iam/users/123?expand=roles&page=2",
		Headers:     hdr,
		Body:        []byte(`{"name":"bob","roles":["admin"]}`),
		ConnID:      "conn-abc-123",
	}
	msg, err := BuildForward(in)
	if err != nil {
		t.Fatalf("BuildForward: %v", err)
	}
	out := ReadForward(msg)

	if out.TenantID != in.TenantID || out.UserID != in.UserID {
		t.Errorf("identity strings: got %q/%q want %q/%q", out.TenantID, out.UserID, in.TenantID, in.UserID)
	}
	if out.IsAdmin != in.IsAdmin {
		t.Errorf("IsAdmin: got %v want %v", out.IsAdmin, in.IsAdmin)
	}
	if out.Permissions != in.Permissions {
		t.Errorf("Permissions: got %#x want %#x", out.Permissions, in.Permissions)
	}
	if out.Method != in.Method || out.Path != in.Path {
		t.Errorf("method/path: got %q/%q want %q/%q", out.Method, out.Path, in.Method, in.Path)
	}
	if out.ConnID != in.ConnID {
		t.Errorf("ConnID: got %q want %q", out.ConnID, in.ConnID)
	}
	if !bytes.Equal(out.Headers, in.Headers) {
		t.Errorf("Headers: got %s want %s", out.Headers, in.Headers)
	}
	if !bytes.Equal(out.Body, in.Body) {
		t.Errorf("Body: got %s want %s", out.Body, in.Body)
	}
}

func TestForwardRoundTripEmpty(t *testing.T) {
	// Zero values: empty strings, nil bytes, false, 0 must survive.
	out := ReadForward(mustBuild(BuildForward(Forward{})))
	if out.TenantID != "" || out.UserID != "" || out.Method != "" || out.Path != "" || out.ConnID != "" {
		t.Errorf("empty strings not preserved: %+v", out)
	}
	if out.IsAdmin || out.Permissions != 0 {
		t.Errorf("zero scalars not preserved: IsAdmin=%v Permissions=%d", out.IsAdmin, out.Permissions)
	}
	if len(out.Headers) != 0 || len(out.Body) != 0 {
		t.Errorf("nil bytes not preserved: headers=%v body=%v", out.Headers, out.Body)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	hdr, _ := json.Marshal(map[string][]string{
		"Content-Type":  {"application/json"},
		"X-Request-Id":  {"req-789"},
		"Cache-Control": {"no-store"},
	})
	in := Response{
		Status:  http.StatusCreated,
		Headers: hdr,
		Body:    []byte(`{"id":"123","status":"ok"}`),
	}
	out := ReadResponse(mustBuild(BuildResponse(in)))
	if out.Status != in.Status {
		t.Errorf("Status: got %d want %d", out.Status, in.Status)
	}
	if !bytes.Equal(out.Headers, in.Headers) {
		t.Errorf("Headers: got %s want %s", out.Headers, in.Headers)
	}
	if !bytes.Equal(out.Body, in.Body) {
		t.Errorf("Body: got %s want %s", out.Body, in.Body)
	}
}

func TestResponseRoundTripStatusCodes(t *testing.T) {
	for _, code := range []int{200, 201, 204, 301, 400, 401, 403, 404, 429, 500, 502, 503} {
		out := ReadResponse(mustBuild(BuildResponse(Response{Status: code, Body: []byte("x")})))
		if out.Status != code {
			t.Errorf("status %d round-tripped to %d", code, out.Status)
		}
	}
}

func TestPushRoundTrip(t *testing.T) {
	for _, enc := range []string{EncSSE, EncWSText, EncWSBinary} {
		in := Push{
			ConnID:   "conn-xyz",
			Frame:    []byte("data: {\"token\":\"hello\"}\n\n"),
			Encoding: enc,
		}
		out := ReadPush(mustBuild(BuildPush(in)))
		if out.ConnID != in.ConnID || out.Encoding != in.Encoding || !bytes.Equal(out.Frame, in.Frame) {
			t.Errorf("push[%s] mismatch: got %+v want %+v", enc, out, in)
		}
	}
}

// --- Service-side handler: identity injection + passthrough -------------

func TestHandleInjectsIdentityAndPassesThrough(t *testing.T) {
	var gotOrg, gotUser, gotAdmin, gotPerms, gotCT string
	var gotMethod, gotPath, gotRawQuery, gotBody string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get(HeaderOrgID)
		gotUser = r.Header.Get(HeaderUserID)
		gotAdmin = r.Header.Get(HeaderUserIsAdmin)
		gotPerms = r.Header.Get(HeaderUserPerms)
		gotCT = r.Header.Get("Content-Type")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", "1")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	reqHdr, _ := json.Marshal(map[string][]string{"Content-Type": {"application/json"}})
	resp := handle(context.Background(), h, Forward{
		TenantID:    "acme",
		UserID:      "user-42",
		IsAdmin:     true,
		Permissions: 7,
		Method:      http.MethodPost,
		Path:        "/v1/chat?stream=true",
		Headers:     reqHdr,
		Body:        []byte(`{"prompt":"hi"}`),
	})

	// Identity injected as X-* headers.
	if gotOrg != "acme" || gotUser != "user-42" || gotAdmin != "true" || gotPerms != "7" {
		t.Errorf("identity not injected: org=%q user=%q admin=%q perms=%q", gotOrg, gotUser, gotAdmin, gotPerms)
	}
	// Client header survived.
	if gotCT != "application/json" {
		t.Errorf("client Content-Type lost: %q", gotCT)
	}
	// Method, path, query, body passthrough.
	if gotMethod != http.MethodPost || gotPath != "/v1/chat" || gotRawQuery != "stream=true" {
		t.Errorf("req line wrong: method=%q path=%q query=%q", gotMethod, gotPath, gotRawQuery)
	}
	if gotBody != `{"prompt":"hi"}` {
		t.Errorf("body wrong: %q", gotBody)
	}
	// Response passthrough.
	if resp.Status != http.StatusTeapot {
		t.Errorf("status: got %d want %d", resp.Status, http.StatusTeapot)
	}
	if !bytes.Equal(resp.Body, []byte(`{"ok":true}`)) {
		t.Errorf("resp body: %s", resp.Body)
	}
	var rh map[string][]string
	_ = json.Unmarshal(resp.Headers, &rh)
	if got := rh["X-Echo"]; len(got) != 1 || got[0] != "1" {
		t.Errorf("resp header X-Echo missing: %v", rh)
	}
}

func TestHandleStripsClientSuppliedIdentity(t *testing.T) {
	// A malicious client tries to assert admin identity via headers. The
	// edge identity (empty here) must win — handle strips client copies.
	var gotOrg, gotAdmin string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get(HeaderOrgID)
		gotAdmin = r.Header.Get(HeaderUserIsAdmin)
		w.WriteHeader(http.StatusOK)
	})
	clientHdr, _ := json.Marshal(map[string][]string{
		HeaderOrgID:       {"evil-org"},
		HeaderUserIsAdmin: {"true"},
	})
	handle(context.Background(), h, Forward{
		// No edge identity asserted.
		Method:  http.MethodGet,
		Path:    "/v1/whoami",
		Headers: clientHdr,
	})
	if gotOrg == "evil-org" {
		t.Errorf("client-spoofed X-Org-Id leaked through: %q", gotOrg)
	}
	// IsAdmin=false from the (empty) Forward must overwrite the spoofed true.
	if gotAdmin != "false" {
		t.Errorf("client-spoofed X-User-IsAdmin not overridden: got %q want false", gotAdmin)
	}
}

// --- End-to-end: Forwarder.RoundTrip over two live ZAP nodes ------------

func TestRoundTripEndToEnd(t *testing.T) {
	gwPort := pickFreePort(t)
	bePort := pickFreePort(t)

	gw := zaplib.NewNode(zaplib.NodeConfig{NodeID: "gateway", Port: gwPort, NoDiscovery: true})
	be := zaplib.NewNode(zaplib.NodeConfig{NodeID: "backend", Port: bePort, NoDiscovery: true})
	if err := gw.Start(); err != nil {
		t.Fatalf("gw.Start: %v", err)
	}
	defer gw.Stop()
	if err := be.Start(); err != nil {
		t.Fatalf("be.Start: %v", err)
	}
	defer be.Stop()

	// Backend echoes identity + request facts back to the caller.
	Serve(be, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		out := map[string]any{
			"org":    r.Header.Get(HeaderOrgID),
			"user":   r.Header.Get(HeaderUserID),
			"admin":  r.Header.Get(HeaderUserIsAdmin),
			"perms":  r.Header.Get(HeaderUserPerms),
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", "zap")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(out)
	}))

	// Gateway dials the backend.
	if err := gw.ConnectDirect("127.0.0.1:" + strconv.Itoa(bePort)); err != nil {
		t.Fatalf("ConnectDirect: %v", err)
	}
	waitPeers(t, gw)

	fwd := &Forwarder{Node: gw, Peer: "backend"}

	// Build a request with edge identity already set as X-* headers (the
	// gateway sets these after JWT validation).
	req, _ := http.NewRequest(http.MethodPost, "http://backend/v1/chat?stream=true",
		bytes.NewReader([]byte(`{"prompt":"hi"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderOrgID, "acme")
	req.Header.Set(HeaderUserID, "user-42")
	req.Header.Set(HeaderUserIsAdmin, "true")
	req.Header.Set(HeaderUserPerms, "7")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := fwd.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	// Status passthrough.
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status: got %d want %d", resp.StatusCode, http.StatusAccepted)
	}
	// Header round-trip.
	if got := resp.Header.Get("X-Backend"); got != "zap" {
		t.Errorf("resp header X-Backend: got %q want zap", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("resp Content-Type: got %q", got)
	}
	// Body round-trip + identity injection (the backend saw our X-* identity).
	var echoed map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("decode echoed body %q: %v", body, err)
	}
	want := map[string]string{
		"org": "acme", "user": "user-42", "admin": "true", "perms": "7",
		"method": "POST", "path": "/v1/chat", "query": "stream=true", "body": `{"prompt":"hi"}`,
	}
	for k, v := range want {
		if got, _ := echoed[k].(string); got != v {
			t.Errorf("echoed[%q]: got %q want %q", k, got, v)
		}
	}
}

// --- Reverse-push registry ----------------------------------------------

type capturingSink struct {
	mu     chan Push
	failOn bool
}

func (s *capturingSink) Deliver(ctx context.Context, p Push) error {
	if s.failOn {
		return io.EOF
	}
	s.mu <- p
	return nil
}

func TestReversePushRegistry(t *testing.T) {
	sink := &capturingSink{mu: make(chan Push, 1)}
	RegisterReversePush("conn-1", sink)
	defer UnregisterReversePush("conn-1")

	msg, err := BuildPush(Push{ConnID: "conn-1", Frame: []byte("data: hi\n\n"), Encoding: EncSSE})
	if err != nil {
		t.Fatalf("BuildPush: %v", err)
	}
	if _, err := HandleReversePush(context.Background(), "backend", msg); err != nil {
		t.Fatalf("HandleReversePush: %v", err)
	}
	select {
	case p := <-sink.mu:
		if p.Encoding != EncSSE || string(p.Frame) != "data: hi\n\n" {
			t.Errorf("delivered push wrong: %+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("push never delivered to sink")
	}

	// Unknown ConnID is a silent no-op.
	unknown, _ := BuildPush(Push{ConnID: "nope", Frame: []byte("x"), Encoding: EncSSE})
	if _, err := HandleReversePush(context.Background(), "backend", unknown); err != nil {
		t.Fatalf("unknown ConnID should be no-op, got %v", err)
	}

	// A failing sink is dropped from the registry.
	bad := &capturingSink{mu: make(chan Push, 1), failOn: true}
	RegisterReversePush("conn-bad", bad)
	badMsg, _ := BuildPush(Push{ConnID: "conn-bad", Frame: []byte("x"), Encoding: EncSSE})
	if _, err := HandleReversePush(context.Background(), "backend", badMsg); err == nil {
		t.Fatal("failing sink should surface error")
	}
	if _, ok := pushRegistry.Load("conn-bad"); ok {
		t.Error("failing sink should have been dropped from registry")
	}
}

// --- helpers ------------------------------------------------------------

// mustBuild unwraps a Build* result. It takes exactly the two builder
// return values so call sites can write mustBuild(BuildX(in)); a build
// failure here is a test bug, so panic (the test runner reports it).
func mustBuild(msg *zaplib.Message, err error) *zaplib.Message {
	if err != nil {
		panic("forward: build failed in test: " + err.Error())
	}
	return msg
}

func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitPeers(t *testing.T, n *zaplib.Node) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Peers()) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no peers after 2s")
}
