// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zaplib "github.com/luxfi/zap"
)

// relayTopology spins up the production-shaped three-node chain:
//
//	ingress  →  gateway (Relay)  →  backend (Serve)
//
// ingress is the caller (a Forwarder lives on it), gateway runs the relay
// under test, backend is the ZAP→HTTP terminal. Returns the started nodes
// and a cleanup. The gateway is wired with the supplied gate; pick always
// routes to the single backend unless overridden by the caller.
type relayTopology struct {
	ingress *zaplib.Node
	gateway *zaplib.Node
	backend *zaplib.Node
}

func newRelayTopology(t *testing.T, gate Gate, h http.Handler) *relayTopology {
	t.Helper()
	gwPort := pickFreePort(t)
	bePort := pickFreePort(t)
	top := &relayTopology{
		ingress: zaplib.NewNode(zaplib.NodeConfig{NodeID: "ingress", Port: pickFreePort(t), NoDiscovery: true}),
		gateway: zaplib.NewNode(zaplib.NodeConfig{NodeID: "gateway", Port: gwPort, NoDiscovery: true}),
		backend: zaplib.NewNode(zaplib.NodeConfig{NodeID: "backend", Port: bePort, NoDiscovery: true}),
	}
	for _, n := range []*zaplib.Node{top.ingress, top.gateway, top.backend} {
		if err := n.Start(); err != nil {
			t.Fatalf("%s.Start: %v", n.NodeID(), err)
		}
	}
	t.Cleanup(func() {
		top.ingress.Stop()
		top.gateway.Stop()
		top.backend.Stop()
	})

	// Backend terminal.
	Serve(top.backend, h)
	// Gateway relay: everything → backend (single-backend tests).
	Relay(top.gateway, gate, func(string) string { return "backend" })

	// Wire the chain: ingress→gateway and gateway→backend.
	if err := top.ingress.ConnectDirect("127.0.0.1:" + strconv.Itoa(gwPort)); err != nil {
		t.Fatalf("ingress→gateway: %v", err)
	}
	if err := top.gateway.ConnectDirect("127.0.0.1:" + strconv.Itoa(bePort)); err != nil {
		t.Fatalf("gateway→backend: %v", err)
	}
	waitPeers(t, top.ingress)
	waitPeers(t, top.gateway)
	return top
}

// call drives one request from the ingress through the gateway relay.
func (top *relayTopology) call(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fwd := &Forwarder{Node: top.ingress, Peer: "gateway"}
	resp, err := fwd.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("RoundTrip through relay: %v", err)
	}
	return resp
}

// --- ALLOW: gate injects identity, reaches backend, response unchanged --

func TestRelayAllowInjectsIdentityAndPassesResponse(t *testing.T) {
	// The gate "validates a JWT" (here: trusts an Authorization header it
	// finds in the envelope) and stamps the resolved identity onto f.
	gate := func(_ context.Context, f *Forward) (*Response, error) {
		var hdrs map[string][]string
		_ = json.Unmarshal(f.Headers, &hdrs)
		if got := hdrs["Authorization"]; len(got) == 0 || got[0] != "Bearer good" {
			return &Response{Status: http.StatusUnauthorized}, nil
		}
		// Inject the validated identity in place — this is the only thing
		// the gate mutates; it does not touch f.Body.
		f.TenantID = "acme"
		f.UserID = "user-42"
		f.IsAdmin = true
		f.Permissions = 7
		return nil, nil
	}

	// Backend echoes the identity it received (proves injection survived
	// the relay's re-emit) plus the request line + body.
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		out := map[string]string{
			"org": r.Header.Get(HeaderOrgID), "user": r.Header.Get(HeaderUserID),
			"admin": r.Header.Get(HeaderUserIsAdmin), "perms": r.Header.Get(HeaderUserPerms),
			"method": r.Method, "path": r.URL.Path, "query": r.URL.RawQuery, "body": string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", "zap")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(out)
	})

	top := newRelayTopology(t, gate, backend)

	req, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions?stream=true",
		bytes.NewReader([]byte(`{"prompt":"hi"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer good")

	resp := top.call(t, req)

	// Backend's Response flowed back unchanged: status, headers, body.
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status: got %d want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("X-Backend"); got != "zap" {
		t.Errorf("resp header X-Backend: got %q want zap", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("resp Content-Type: got %q", got)
	}
	var echoed map[string]string
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("decode echoed body %q: %v", body, err)
	}
	want := map[string]string{
		"org": "acme", "user": "user-42", "admin": "true", "perms": "7",
		"method": "POST", "path": "/v1/chat/completions", "query": "stream=true",
		"body": `{"prompt":"hi"}`,
	}
	for k, v := range want {
		if echoed[k] != v {
			t.Errorf("echoed[%q]: got %q want %q", k, echoed[k], v)
		}
	}
}

// --- ALLOW (no edge identity → bad JWT → 401 from the gate) -------------

func TestRelayDenyUnauthorized(t *testing.T) {
	var backendHit atomic.Bool
	gate := func(_ context.Context, f *Forward) (*Response, error) {
		// No valid token in the envelope.
		return &Response{
			Status:  http.StatusUnauthorized,
			Headers: mustJSON(map[string][]string{"Content-Type": {"application/json"}}),
			Body:    []byte(`{"error":"unauthorized"}`),
		}, nil
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit.Store(true)
		w.WriteHeader(http.StatusOK)
	})

	top := newRelayTopology(t, gate, backend)

	req, _ := http.NewRequest(http.MethodGet, "http://gateway/v1/chat/completions", nil)
	resp := top.call(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", resp.StatusCode)
	}
	if backendHit.Load() {
		t.Error("backend was called on a denied (401) request")
	}
}

// --- DENY: balance gate returns 402, backend is NEVER called -----------

func TestRelayDenyInsufficientBalanceSkipsBackend(t *testing.T) {
	var backendHit atomic.Bool
	gate := func(_ context.Context, f *Forward) (*Response, error) {
		// Token is fine, but the prepaid balance gate trips.
		return &Response{
			Status:  http.StatusPaymentRequired,
			Headers: mustJSON(map[string][]string{"Content-Type": {"application/json"}}),
			Body:    []byte(`{"error":"insufficient_balance"}`),
		}, nil
	}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should never run"))
	})

	top := newRelayTopology(t, gate, backend)

	req, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions",
		bytes.NewReader([]byte(`{"prompt":"hi"}`)))
	resp := top.call(t, req)

	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status: got %d want 402", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("insufficient_balance")) {
		t.Errorf("402 body: got %q want insufficient_balance", body)
	}
	if backendHit.Load() {
		t.Error("backend was called on a 402-denied request — relay did not short-circuit")
	}
}

// --- BODY INTEGRITY: a 4 KB body arrives byte-identical -----------------

func TestRelayBodyIntegrity(t *testing.T) {
	// 4 KB of random bytes — proves the body is neither corrupted nor
	// round-tripped through JSON (random bytes are not valid JSON).
	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	gate := func(_ context.Context, f *Forward) (*Response, error) {
		// Allow; explicitly do not touch f.Body.
		f.TenantID = "acme"
		return nil, nil
	}

	// gotEqual is written on the backend's serve goroutine and read on the
	// test goroutine, so it must be synchronized (atomic). The body is
	// echoed back as well, giving an independent end-to-end check on the
	// test goroutine via the response.
	var gotEqual atomic.Bool
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		gotEqual.Store(bytes.Equal(got, payload))
		// Echo the body straight back so we also verify the Response leg
		// carries arbitrary bytes unchanged.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(got)
	})

	top := newRelayTopology(t, gate, backend)

	req, _ := http.NewRequest(http.MethodPost, "http://gateway/v1/raw",
		bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp := top.call(t, req)

	// Equality at the backend (subsumes length) — bytes arrived intact.
	if !gotEqual.Load() {
		t.Error("backend body bytes differ from sent payload — corruption in relay")
	}
	// Independent end-to-end check entirely on the test goroutine.
	echoed, _ := io.ReadAll(resp.Body)
	if len(echoed) != len(payload) {
		t.Errorf("echoed body length: got %d want %d", len(echoed), len(payload))
	}
	if !bytes.Equal(echoed, payload) {
		t.Error("echoed response body bytes differ from sent payload")
	}
}

// --- PEER ROUTING: /v1/base/* → base peer; else → cloud peer -----------

func TestRelayPeerRouting(t *testing.T) {
	// pickBackend semantics from the gateway: /v1/base/* → base, else cloud.
	pick := func(path string) string {
		if strings.HasPrefix(path, "/v1/base/") {
			return "base"
		}
		return "cloud"
	}

	gwPort := pickFreePort(t)
	basePort := pickFreePort(t)
	cloudPort := pickFreePort(t)
	ingress := zaplib.NewNode(zaplib.NodeConfig{NodeID: "ingress", Port: pickFreePort(t), NoDiscovery: true})
	gateway := zaplib.NewNode(zaplib.NodeConfig{NodeID: "gateway", Port: gwPort, NoDiscovery: true})
	base := zaplib.NewNode(zaplib.NodeConfig{NodeID: "base", Port: basePort, NoDiscovery: true})
	cloud := zaplib.NewNode(zaplib.NodeConfig{NodeID: "cloud", Port: cloudPort, NoDiscovery: true})
	for _, n := range []*zaplib.Node{ingress, gateway, base, cloud} {
		if err := n.Start(); err != nil {
			t.Fatalf("%s.Start: %v", n.NodeID(), err)
		}
		defer n.Stop()
	}

	// Each backend reports which one it is.
	mkBackend := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(name))
		})
	}
	Serve(base, mkBackend("base"))
	Serve(cloud, mkBackend("cloud"))

	gate := func(_ context.Context, f *Forward) (*Response, error) { return nil, nil }
	Relay(gateway, gate, pick)

	mustConnect := func(from *zaplib.Node, toPort int) {
		if err := from.ConnectDirect("127.0.0.1:" + strconv.Itoa(toPort)); err != nil {
			t.Fatalf("%s→:%d: %v", from.NodeID(), toPort, err)
		}
	}
	mustConnect(ingress, gwPort)
	mustConnect(gateway, basePort)
	mustConnect(gateway, cloudPort)
	waitPeers(t, ingress)
	// Gateway must see both backends before routing.
	deadline := time.Now().Add(2 * time.Second)
	for len(gateway.Peers()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(gateway.Peers()) < 2 {
		t.Fatalf("gateway sees %d peers, want 2", len(gateway.Peers()))
	}

	fwd := &Forwarder{Node: ingress, Peer: "gateway"}
	hit := func(path string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequest(http.MethodGet, "http://gateway"+path, nil)
		resp, err := fwd.RoundTrip(req.WithContext(ctx))
		if err != nil {
			t.Fatalf("RoundTrip %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	if got := hit("/v1/base/records"); got != "base" {
		t.Errorf("/v1/base/records routed to %q, want base", got)
	}
	if got := hit("/v1/chat/completions"); got != "cloud" {
		t.Errorf("/v1/chat/completions routed to %q, want cloud", got)
	}
}

// --- helpers ------------------------------------------------------------

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("forward: test JSON marshal: " + err.Error())
	}
	return b
}
