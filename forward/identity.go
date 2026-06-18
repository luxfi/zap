// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package forward

import (
	"net/http"
	"strings"
)

// identity.go is the single source of truth for which inbound headers may
// carry an authenticated principal across the HTTP-over-ZAP boundary.
//
// Only the EDGE may assert identity. The gateway validates the IAM JWT and
// promotes the result into the typed Forward identity fields (TenantID,
// UserID, IsAdmin, Permissions); the backend re-injects those as the
// canonical X-* headers AFTER stripping every client-supplied copy. A
// client that sets any identity header directly must never have it survive
// into a backend handler.
//
// This list mirrors the authoritative set in
// github.com/hanzoai/base/tools/claims.StripIdentityHeaders. The two MUST
// stay in lock-step: base strips on its own ingress as defence-in-depth,
// and this contract strips on BOTH legs (gateway-side in client.go before
// the envelope is built, backend-side in serve.go before identity is
// injected) so a forged identity header never enters the envelope and never
// reaches a handler even if the envelope is crafted directly.
var clientIdentityHeaders = []string{
	// Canonical edge-injected identity (this contract's own 4).
	HeaderOrgID,       // X-Org-Id
	HeaderUserID,      // X-User-Id
	HeaderUserIsAdmin, // X-User-IsAdmin
	HeaderUserPerms,   // X-User-Permissions

	// Base's canonical roles header + gateway auxiliaries (JWT derivatives).
	"X-Roles",
	"X-User-Email",
	"X-Phone-Number",

	// Non-canonical legacy identity headers shipped across the ecosystem.
	"X-User-Role",  // singular
	"X-User-Roles", // plural — renamed to X-Roles
	"X-User-Name",
	"X-Tenant-Id",
	"X-Org",
	"X-Is-Admin",

	// Pre-validation hints from older gateway flows. The X-Gateway-* prefix
	// is also caught by the prefix sweep below; listed here for parity with
	// base's authoritative set.
	"X-Gateway-Validated",
	"X-Gateway-User-Id",
	"X-Gateway-Org-Id",
	"X-Gateway-User-Email",
}

// stripClientIdentity removes every client-supplied identity-bearing header
// from h. It deletes the explicit list above (case-insensitive via
// http.Header's canonicalization) and, unconditionally, every header whose
// name starts with "X-IAM-", "X-Hanzo-", or "X-Gateway-" — closing the
// "clever-new-prefix" smuggling vector. It also drops the Cookie header
// entirely: cookies can carry session/identity material the edge has
// already lifted into the typed fields, and the backend's auth path is the
// forwarded Authorization Bearer JWT, not cookies, so a forwarded Cookie is
// only a smuggling surface here.
//
// Authorization is deliberately PRESERVED: base validates the forwarded
// Bearer JWT — that is the real authentication path and must survive.
func stripClientIdentity(h http.Header) {
	for _, name := range clientIdentityHeaders {
		h.Del(name)
	}
	for key := range h {
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "X-IAM-") ||
			strings.HasPrefix(upper, "X-HANZO-") ||
			strings.HasPrefix(upper, "X-GATEWAY-") {
			h.Del(key)
		}
	}
	// Cookies are an identity-bearing surface the edge does not promote;
	// drop them so a forwarded Cookie cannot smuggle a session. Authorization
	// (the Bearer JWT base validates) is intentionally left intact.
	h.Del("Cookie")
}
