// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// pq_attestation.go — strict-PQ identity binding on ZAP handshakes.
//
// Go 1.26's crypto/tls ships X25519MLKEM768 / SecP256r1MLKEM768 /
// SecP384r1MLKEM1024 as TLS 1.3 hybrid post-quantum key exchange
// groups — enabled by default. ZAP's TLS-wrapped transport already
// gets a quantum-secure session key OUT OF THE BOX via that
// hybrid KEX.
//
// What standard TLS does NOT yet ship is post-quantum certificate
// signatures: the cert authenticating each TLS endpoint is still
// classical ECDSA (or Ed25519 when Go ships it for TLS cert use).
// A quantum adversary that compromises an ECDSA cert key can
// impersonate the endpoint even though the session-key KEX was
// post-quantum.
//
// This package closes that gap by binding the TLS cert to the
// peer's post-quantum identity at the application layer: each
// peer sends an Attestation as the first ZAP message after the
// handshake completes. The attestation is a FIPS 204 ML-DSA-65
// signature over a SHAKE256-384 transcript that includes:
//
//   - the TLS cert fingerprint (so a stolen cert can't be paired
//     with a different PQ identity),
//   - the chain id (so a replay across chains fails),
//   - a per-session nonce (so a replay within a chain fails).
//
// The verifier checks the signature against the peer's PQ public
// key AND that the public key is a member of the chain's
// validator set. Either check failing closes the connection.
//
// This package is verifier-agnostic on purpose: the actual
// ML-DSA-65 verification lives in luxfi/crypto/mldsa, but zap
// avoids the dep (zap is at the bottom of the dependency tree
// and shouldn't carry crypto transitively). Callers supply an
// AttestationVerifier that wraps mldsa65.Verify.

package zap

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// SecurityProfile is the ZAP security posture a deployment pins.
// Matches the shape used by lux/warp, lx/dex, lux/fhe, luxfi/evm
// so downstream consumers see one vocabulary across every layer.
type SecurityProfile int

const (
	// ProfileClassical accepts ZAP connections without a PQ
	// Attestation. TLS handshake is the only identity check.
	// Suitable for legacy deployments before any peer has
	// generated ML-DSA validator material.
	ProfileClassical SecurityProfile = iota

	// ProfileHybrid validates an Attestation WHEN the peer sends
	// one, but accepts connections without one (falling back to
	// TLS identity alone with a stale-PQ warning). Safe migration
	// middle.
	ProfileHybrid

	// ProfileStrictPQ REFUSES every ZAP connection whose peer
	// does NOT present a valid Attestation bound to the TLS cert
	// fingerprint. Canonical Liquid / strict Lux / strict Zoo
	// profile.
	ProfileStrictPQ
)

// String returns the canonical wire name. Audit pipelines match
// on these strings; renaming here breaks every downstream consumer.
func (p SecurityProfile) String() string {
	switch p {
	case ProfileClassical:
		return "classical"
	case ProfileHybrid:
		return "hybrid"
	case ProfileStrictPQ:
		return "strict-pq"
	default:
		return "unknown"
	}
}

// IsPostQuantum reports whether this profile REFUSES connections
// missing a PQ Attestation. Only ProfileStrictPQ returns true.
func (p SecurityProfile) IsPostQuantum() bool {
	return p == ProfileStrictPQ
}

// IsPQAware reports whether this profile VALIDATES an attestation
// when the peer presents one. Both ProfileHybrid and
// ProfileStrictPQ return true; ProfileClassical ignores
// attestations even when they're sent.
func (p SecurityProfile) IsPQAware() bool {
	return p == ProfileHybrid || p == ProfileStrictPQ
}

// ProfileFromString parses an operator-supplied profile string.
// Refuses unknown values rather than defaulting.
func ProfileFromString(s string) (SecurityProfile, error) {
	switch s {
	case "classical":
		return ProfileClassical, nil
	case "hybrid":
		return ProfileHybrid, nil
	case "strict-pq":
		return ProfileStrictPQ, nil
	default:
		return ProfileClassical, fmt.Errorf("zap: unknown profile %q (want classical|hybrid|strict-pq)", s)
	}
}

// ErrClassicalAuthForbidden is returned when a strict-PQ ZAP
// connection is missing a PQ Attestation. Name and shape match
// lux/warp, lx/dex, luxfi/evm so audit pipelines can grep one
// identifier across every strict-PQ refusal site in the system.
var ErrClassicalAuthForbidden = errors.New(
	"zap: classical authentication forbidden under strict-PQ profile (PQ Attestation required)")

// Attestation is the wire shape a ZAP peer presents after the
// TLS handshake completes. PubKey + Sig are opaque bytes from
// zap's perspective; the AttestationVerifier owns the format
// (FIPS 204 ML-DSA-65 pubkey 1952 bytes, signature 3293 bytes
// for Liquid; the same wire format works for ML-DSA-87 with
// different byte counts for high-value Zoo chains).
type Attestation struct {
	// PubKey is the peer's strict-PQ public key. Verifier
	// confirms membership in the chain's validator set BEFORE
	// trusting the signature.
	PubKey []byte
	// Sig is the signature over TranscriptHash(...).
	Sig []byte
}

// AttestationContext bundles the inputs a verifier needs to
// rebuild the transcript hash. Same inputs on both peers; the
// PQ signature anchors the binding.
type AttestationContext struct {
	// TLSCertFingerprint is sha256 of the peer's TLS certificate
	// DER. Binding the attestation to this fingerprint means a
	// stolen-but-orthogonal TLS cert can't be paired with a
	// different PQ identity to MITM the channel.
	TLSCertFingerprint [32]byte
	// ChainID is the 32-byte chain identifier this connection is
	// scoped to. Different chains produce different transcripts,
	// so an attestation harvested on chain A is useless on chain B.
	ChainID [32]byte
	// PeerMLKEMPub is the peer's ML-KEM-768 public key (1184
	// bytes). Including it in the transcript binds the
	// attestation to the same KEM key the TLS handshake used
	// (when X25519MLKEM768 hybrid was negotiated). On classical
	// TLS this is empty and the field doesn't contribute.
	PeerMLKEMPub []byte
	// Timestamp (unix seconds) of the connection. Verifier checks
	// |now - timestamp| < some window (e.g. 60s) to refuse
	// replays of old captured attestations.
	Timestamp uint64
	// Nonce is per-session entropy from the verifier — 32 bytes.
	// Refuses an attacker who records one valid attestation from
	// replaying it on a future session.
	Nonce [32]byte
}

// TranscriptHash returns the 48-byte SHAKE256-384 commitment a
// PQ Attestation signature MUST cover. Domain-separated with the
// "ZAP-PQ-V1" string so a signature produced for ZAP cannot be
// replayed on any other ML-DSA-signed transcript (warp envelopes,
// validator-set commitments, etc.).
//
// SP 800-185 left_encode framing on each field so a malicious
// transcript field whose first bytes spell another field's
// payload cannot collide with a legitimate transcript.
func TranscriptHash(ctx *AttestationContext) [48]byte {
	const domainTag = "ZAP-PQ-V1"
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(domainTag)) * 8))
	_, _ = h.Write([]byte(domainTag))

	_, _ = h.Write(leftEncode(uint64(len(ctx.TLSCertFingerprint)) * 8))
	_, _ = h.Write(ctx.TLSCertFingerprint[:])

	_, _ = h.Write(leftEncode(uint64(len(ctx.ChainID)) * 8))
	_, _ = h.Write(ctx.ChainID[:])

	_, _ = h.Write(leftEncode(uint64(len(ctx.PeerMLKEMPub)) * 8))
	_, _ = h.Write(ctx.PeerMLKEMPub)

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], ctx.Timestamp)
	_, _ = h.Write(leftEncode(8 * 8))
	_, _ = h.Write(tsBuf[:])

	_, _ = h.Write(leftEncode(uint64(len(ctx.Nonce)) * 8))
	_, _ = h.Write(ctx.Nonce[:])

	var out [48]byte
	_, _ = h.Read(out[:])
	return out
}

// TLSCertFingerprintFromBytes returns sha256(certBytes) sized for
// the AttestationContext field. Helper so callers don't need to
// reach into crypto/sha256 separately.
func TLSCertFingerprintFromBytes(certDER []byte) [32]byte {
	return sha256.Sum256(certDER)
}

// AttestationVerifier validates a peer's PQ attestation. Callers
// (e.g. lux/node, lux/kms) supply this — typically a one-line
// wrapper over mldsa65.PublicKeyFromBytes(...).VerifySignature(...)
// that ALSO confirms the public key is a member of the chain's
// validator set.
type AttestationVerifier func(pubKey, sig, transcriptHash []byte) error

// RequireAttestationForProfile is the single seam every ZAP
// transport-init should call BEFORE trusting a connection's
// peer identity.
//
//   - ProfileClassical: returns nil regardless (TLS identity OK).
//   - ProfileHybrid: returns nil regardless — if the peer sent
//     an attestation, validate it via the verifier; if not, fall
//     back to TLS identity alone (with a stale-PQ warning logged
//     by the caller).
//   - ProfileStrictPQ: returns ErrClassicalAuthForbidden if the
//     attestation is nil. Otherwise calls the verifier; verifier
//     errors propagate.
func RequireAttestationForProfile(
	profile SecurityProfile,
	att *Attestation,
	ctx *AttestationContext,
	verify AttestationVerifier,
) error {
	if !profile.IsPQAware() {
		// Classical profile: never validate, never refuse.
		return nil
	}
	if att == nil {
		if profile.IsPostQuantum() {
			return ErrClassicalAuthForbidden
		}
		// Hybrid + nil attestation: accept, caller decides
		// whether to log a stale-PQ warning.
		return nil
	}
	if verify == nil {
		return errors.New("zap: nil AttestationVerifier supplied to RequireAttestationForProfile")
	}
	if ctx == nil {
		return errors.New("zap: nil AttestationContext")
	}
	hash := TranscriptHash(ctx)
	return verify(att.PubKey, att.Sig, hash[:])
}

// leftEncode is the SP 800-185 §2.3.1 left_encode operation —
// length-prefix framing so concatenated fields can't be
// ambiguously parsed. Local copy avoids a dep on luxfi/ids /
// luxfi/consensus from a leaf package.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}
