// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"errors"
	"fmt"
)

// AlertCode is the §14 error code carried in ALERT frame bodies.
// Each code maps 1:1 to a sentinel error so callers can branch with
// errors.Is on the named sentinel rather than parsing the byte.
type AlertCode uint8

const (
	AlertNone               AlertCode = 0x00 // reserved
	AlertDecodeError        AlertCode = 0x01
	AlertUnsupportedSuite   AlertCode = 0x02
	AlertAuthFailed         AlertCode = 0x03
	AlertReplayDetected     AlertCode = 0x04
	AlertDowngradeRefused   AlertCode = 0x05
	AlertHandshakeTimeout   AlertCode = 0x06
	AlertNonceViolation     AlertCode = 0x07
	AlertPSKUnknown         AlertCode = 0x08
	AlertVMIdentityMismatch AlertCode = 0x09
	AlertAuthoritySigFailed AlertCode = 0x0A
	AlertPolicyRefused      AlertCode = 0x0B
)

// String returns the canonical §14 name. Audit pipelines match on
// these strings; renaming here breaks every downstream parser.
func (c AlertCode) String() string {
	switch c {
	case AlertNone:
		return "none"
	case AlertDecodeError:
		return "decode_error"
	case AlertUnsupportedSuite:
		return "unsupported_ciphersuite"
	case AlertAuthFailed:
		return "auth_failed"
	case AlertReplayDetected:
		return "replay_detected"
	case AlertDowngradeRefused:
		return "downgrade_refused"
	case AlertHandshakeTimeout:
		return "handshake_timeout"
	case AlertNonceViolation:
		return "nonce_violation"
	case AlertPSKUnknown:
		return "psk_unknown"
	case AlertVMIdentityMismatch:
		return "vm_identity_mismatch"
	case AlertAuthoritySigFailed:
		return "authority_sig_failed"
	case AlertPolicyRefused:
		return "policy_refused"
	}
	return fmt.Sprintf("alert(0x%02x)", uint8(c))
}

// Sentinel errors — one per §14 code, plus a few non-wire local
// conditions (magic mismatch, handshake-state misuse).
var (
	ErrDecodeError        = errors.New("zap-pq: decode_error")
	ErrUnsupportedSuite   = errors.New("zap-pq: unsupported_ciphersuite")
	ErrAuthFailed         = errors.New("zap-pq: auth_failed")
	ErrReplayDetected     = errors.New("zap-pq: replay_detected")
	ErrDowngradeRefused   = errors.New("zap-pq: downgrade_refused")
	ErrHandshakeTimeout   = errors.New("zap-pq: handshake_timeout")
	ErrNonceViolation     = errors.New("zap-pq: nonce_violation")
	ErrPSKUnknown         = errors.New("zap-pq: psk_unknown")
	ErrVMIdentityMismatch = errors.New("zap-pq: vm_identity_mismatch")
	ErrAuthoritySigFailed = errors.New("zap-pq: authority_sig_failed")
	ErrPolicyRefused      = errors.New("zap-pq: policy_refused")

	// Non-wire local errors.
	ErrMagicMismatch  = errors.New("zap-pq: magic prefix mismatch")
	ErrSessionClosed  = errors.New("zap-pq: session closed")
	ErrEpochExhausted = errors.New("zap-pq: epoch wrap forbidden, reconnect required")
)

// errorForAlert maps a wire ALERT code back to the local sentinel.
// Unknown codes return a wrapped ErrDecodeError so the channel still
// fails closed.
func errorForAlert(c AlertCode) error {
	switch c {
	case AlertDecodeError:
		return ErrDecodeError
	case AlertUnsupportedSuite:
		return ErrUnsupportedSuite
	case AlertAuthFailed:
		return ErrAuthFailed
	case AlertReplayDetected:
		return ErrReplayDetected
	case AlertDowngradeRefused:
		return ErrDowngradeRefused
	case AlertHandshakeTimeout:
		return ErrHandshakeTimeout
	case AlertNonceViolation:
		return ErrNonceViolation
	case AlertPSKUnknown:
		return ErrPSKUnknown
	case AlertVMIdentityMismatch:
		return ErrVMIdentityMismatch
	case AlertAuthoritySigFailed:
		return ErrAuthoritySigFailed
	case AlertPolicyRefused:
		return ErrPolicyRefused
	}
	return fmt.Errorf("%w: unknown alert 0x%02x", ErrDecodeError, uint8(c))
}

// alertForError is the inverse: which §14 code should be on the wire
// when the local pipeline raises err. Defaults to decode_error which
// is the catch-all per spec.
func alertForError(err error) AlertCode {
	switch {
	case errors.Is(err, ErrAuthFailed):
		return AlertAuthFailed
	case errors.Is(err, ErrReplayDetected):
		return AlertReplayDetected
	case errors.Is(err, ErrDowngradeRefused):
		return AlertDowngradeRefused
	case errors.Is(err, ErrHandshakeTimeout):
		return AlertHandshakeTimeout
	case errors.Is(err, ErrNonceViolation):
		return AlertNonceViolation
	case errors.Is(err, ErrPSKUnknown):
		return AlertPSKUnknown
	case errors.Is(err, ErrUnsupportedSuite):
		return AlertUnsupportedSuite
	case errors.Is(err, ErrVMIdentityMismatch):
		return AlertVMIdentityMismatch
	case errors.Is(err, ErrAuthoritySigFailed):
		return AlertAuthoritySigFailed
	case errors.Is(err, ErrPolicyRefused):
		return AlertPolicyRefused
	}
	return AlertDecodeError
}
