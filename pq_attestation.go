// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// pq_attestation.go — ZAP channel-binding ML-DSA-65 attestation.
//
// Go 1.26's crypto/tls ships X25519MLKEM768 hybrid PQ key exchange
// by default; every ZAP TLS transport gets a quantum-secure session
// key out of the box. The remaining gap is identity: TLS cert
// signatures are still classical ECDSA / Ed25519 because Go doesn't
// yet ship ML-DSA cert sigs.
//
// This file binds the TLS endpoint to the peer's strict-PQ identity
// at the application layer. After the TLS handshake completes,
// each peer sends an Attestation as the first ZAP message:
//
//   Attestation = {
//     PubKey: peer's FIPS 204 ML-DSA-65 public key (1952 bytes),
//     Sig:    mldsa65.Sign(privKey, TranscriptHash(ctx)),
//   }
//
//   TranscriptHash = SHAKE256-384(
//     "ZAP-PQ-V1"
//     || TLS cert fingerprint   (stolen cert can't be paired with a
//                                different PQ identity)
//     || chain id               (cross-chain replay protection)
//     || peer ML-KEM-768 pubkey  (binds to the same KEM key the TLS
//                                handshake used)
//     || timestamp              (intra-chain replay window)
//     || per-session nonce      (cross-session replay protection)
//   )
//
// Profile dispatch routes through lux/pq.ValidateMode:
//
//   profile, _ := pq.ModeFromString(cfg.ZAPProfile)
//   verify := func() error {
//       hash := zap.TranscriptHash(ctx)
//       return verifier(att.PubKey, att.Sig, hash[:])
//   }
//   if err := pq.ValidateMode(profile, att, verify); err != nil {
//       // strict-PQ refused a missing attestation, or the verifier
//       // returned a non-nil error
//   }
//
// Same gate, same sentinel, same mode vocabulary as lux/warp,
// lx/dex, lux/fhe, luxfi/evm.

package zap

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Attestation is the wire shape a ZAP peer presents after the
// TLS handshake completes. PubKey + Sig are opaque bytes from
// zap's perspective; the AttestationVerifier owns the format
// (FIPS 204 ML-DSA-65 pubkey 1952 bytes, signature 3293 bytes
// for Liquid; ML-DSA-87 with different byte counts for
// high-value Zoo chains).
type Attestation struct {
	// PubKey is the peer's strict-PQ public key. The verifier
	// confirms membership in the chain's validator set BEFORE
	// trusting the signature.
	PubKey []byte
	// Sig is the signature over TranscriptHash(...).
	Sig []byte
}

// HasPQEvidence implements pq.PQEvidencer. A non-nil Attestation
// with a non-empty Sig counts as evidence — the gate then
// dispatches to the verifier, which actually checks the
// signature + validator-set membership.
func (a *Attestation) HasPQEvidence() bool {
	return a != nil && len(a.PubKey) > 0 && len(a.Sig) > 0
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

// leftEncode is the SP 800-185 §2.3.1 left_encode operation —
// length-prefix framing so concatenated fields can't be
// ambiguously parsed.
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
