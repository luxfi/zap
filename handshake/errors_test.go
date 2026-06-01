// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestAlertCodeStringCoverage ensures every defined AlertCode has a
// human-readable name and that unknown codes render as a hex tag.
// Audit pipelines grep on these strings — drift here breaks them.
func TestAlertCodeStringCoverage(t *testing.T) {
	cases := []struct {
		code AlertCode
		want string
	}{
		{AlertNone, "none"},
		{AlertDecodeError, "decode_error"},
		{AlertUnsupportedSuite, "unsupported_ciphersuite"},
		{AlertAuthFailed, "auth_failed"},
		{AlertReplayDetected, "replay_detected"},
		{AlertDowngradeRefused, "downgrade_refused"},
		{AlertHandshakeTimeout, "handshake_timeout"},
		{AlertNonceViolation, "nonce_violation"},
		{AlertPSKUnknown, "psk_unknown"},
		{AlertVMIdentityMismatch, "vm_identity_mismatch"},
		{AlertAuthoritySigFailed, "authority_sig_failed"},
		{AlertPolicyRefused, "policy_refused"},
	}
	for _, c := range cases {
		if got := c.code.String(); got != c.want {
			t.Errorf("AlertCode(0x%02x).String() = %q, want %q", byte(c.code), got, c.want)
		}
	}
	// Unknown code falls into the hex fallback.
	if got := AlertCode(0xCC).String(); !strings.Contains(got, "0xcc") {
		t.Errorf("unknown alert code string %q does not contain hex tag", got)
	}
}

// TestErrorForAlertRoundTrip: errorForAlert maps every documented
// code to the corresponding sentinel.
func TestErrorForAlertRoundTrip(t *testing.T) {
	cases := []struct {
		code AlertCode
		want error
	}{
		{AlertDecodeError, ErrDecodeError},
		{AlertUnsupportedSuite, ErrUnsupportedSuite},
		{AlertAuthFailed, ErrAuthFailed},
		{AlertReplayDetected, ErrReplayDetected},
		{AlertDowngradeRefused, ErrDowngradeRefused},
		{AlertHandshakeTimeout, ErrHandshakeTimeout},
		{AlertNonceViolation, ErrNonceViolation},
		{AlertPSKUnknown, ErrPSKUnknown},
		{AlertVMIdentityMismatch, ErrVMIdentityMismatch},
		{AlertAuthoritySigFailed, ErrAuthoritySigFailed},
		{AlertPolicyRefused, ErrPolicyRefused},
	}
	for _, c := range cases {
		got := errorForAlert(c.code)
		if !errors.Is(got, c.want) {
			t.Errorf("errorForAlert(0x%02x) = %v, want sentinel %v", byte(c.code), got, c.want)
		}
	}
	// Unknown code wraps ErrDecodeError so callers still close.
	if got := errorForAlert(0xCC); !errors.Is(got, ErrDecodeError) {
		t.Errorf("unknown errorForAlert chain = %v, want wraps ErrDecodeError", got)
	}
}

// TestAlertForErrorRoundTrip: every sentinel must map back to the
// right wire code so writeAlertFor emits the right §14 byte.
func TestAlertForErrorRoundTrip(t *testing.T) {
	cases := []struct {
		err  error
		want AlertCode
	}{
		{ErrAuthFailed, AlertAuthFailed},
		{ErrReplayDetected, AlertReplayDetected},
		{ErrDowngradeRefused, AlertDowngradeRefused},
		{ErrHandshakeTimeout, AlertHandshakeTimeout},
		{ErrNonceViolation, AlertNonceViolation},
		{ErrPSKUnknown, AlertPSKUnknown},
		{ErrUnsupportedSuite, AlertUnsupportedSuite},
		{ErrVMIdentityMismatch, AlertVMIdentityMismatch},
		{ErrAuthoritySigFailed, AlertAuthoritySigFailed},
		{ErrPolicyRefused, AlertPolicyRefused},
	}
	for _, c := range cases {
		if got := alertForError(c.err); got != c.want {
			t.Errorf("alertForError(%v) = 0x%02x, want 0x%02x", c.err, byte(got), byte(c.want))
		}
	}
	// Unknown / generic error → decode_error catch-all.
	if got := alertForError(fmt.Errorf("anything")); got != AlertDecodeError {
		t.Errorf("alertForError(generic) = 0x%02x, want AlertDecodeError", byte(got))
	}
}

// TestAlertForErrorWrappedSentinels: errors.Is chain must be honoured
// — a wrapped sentinel produces the right wire code.
func TestAlertForErrorWrappedSentinels(t *testing.T) {
	wrapped := fmt.Errorf("context: %w", ErrAuthFailed)
	if got := alertForError(wrapped); got != AlertAuthFailed {
		t.Errorf("wrapped sentinel got 0x%02x, want AlertAuthFailed", byte(got))
	}
}

// TestSentinelDistinct: ensure all §14 sentinel errors are distinct
// values — accidental sharing would conflate failure modes in
// errors.Is checks.
func TestSentinelDistinct(t *testing.T) {
	all := []error{
		ErrDecodeError, ErrUnsupportedSuite, ErrAuthFailed, ErrReplayDetected,
		ErrDowngradeRefused, ErrHandshakeTimeout, ErrNonceViolation,
		ErrPSKUnknown, ErrVMIdentityMismatch, ErrAuthoritySigFailed,
		ErrPolicyRefused, ErrMagicMismatch, ErrSessionClosed, ErrEpochExhausted,
	}
	seen := make(map[string]struct{}, len(all))
	for _, e := range all {
		msg := e.Error()
		if _, dup := seen[msg]; dup {
			t.Fatalf("duplicate sentinel message %q", msg)
		}
		seen[msg] = struct{}{}
	}
}
