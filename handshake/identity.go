// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	cryptorand "crypto/rand"
	"errors"
	"io"

	"github.com/luxfi/crypto/mldsa"
	"golang.org/x/crypto/sha3"
)

// Identity holds a node's or VM's static ML-DSA-65 keypair.
//
// The PrivateKey field is non-nil for our own identity; for a pinned
// peer identity (Initiator.Expected, Responder.Local), PrivateKey is
// nil and only PublicKey is consulted.
type Identity struct {
	PublicKey  *mldsa.PublicKey
	PrivateKey *mldsa.PrivateKey // nil for peer-only identities
}

// ID returns the §10.1 client_id / VM ID: SHA3-256 of the wire
// encoding of the public key. The result is also what the spec calls
// VMID when the identity belongs to a VM plugin.
func (id *Identity) ID() [IDLen]byte {
	if id == nil || id.PublicKey == nil {
		return [IDLen]byte{}
	}
	return sha3.Sum256(id.PublicKey.Bytes())
}

// PublicBytes returns the wire encoding of the public key. Always
// exactly MLDSA65PubLen bytes for a valid identity.
func (id *Identity) PublicBytes() []byte {
	if id == nil || id.PublicKey == nil {
		return nil
	}
	return id.PublicKey.Bytes()
}

// GenerateIdentity returns a fresh ML-DSA-65 keypair using crypto/rand.
// Test code MAY pass a deterministic reader to GenerateIdentityFrom.
func GenerateIdentity() (*Identity, error) {
	return GenerateIdentityFrom(cryptorand.Reader)
}

// GenerateIdentityFrom is GenerateIdentity but lets the caller supply
// the entropy source — KAT vectors need this for reproducibility.
func GenerateIdentityFrom(r io.Reader) (*Identity, error) {
	if r == nil {
		r = cryptorand.Reader
	}
	priv, err := mldsa.GenerateKey(r, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}
	return &Identity{PublicKey: priv.PublicKey, PrivateKey: priv}, nil
}

// IdentityFromPrivate wraps an existing ML-DSA-65 private key.
func IdentityFromPrivate(priv *mldsa.PrivateKey) (*Identity, error) {
	if priv == nil {
		return nil, errors.New("zap-pq: nil ML-DSA private key")
	}
	return &Identity{PublicKey: priv.PublicKey, PrivateKey: priv}, nil
}

// IdentityFromPublicBytes wraps an exported ML-DSA-65 public key. The
// returned Identity has a nil PrivateKey and is only usable as a
// pinned peer identity.
func IdentityFromPublicBytes(pub []byte) (*Identity, error) {
	pk, err := mldsa.PublicKeyFromBytes(pub, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}
	return &Identity{PublicKey: pk}, nil
}

// Sign produces the §6.4 AUTH signature for the supplied transcript
// hash and role using the FIPS 204 hedged (randomized) variant.
// Returns an error if the identity has no private key.
//
// rand is reserved for future use; the underlying ML-DSA-65
// implementation reads randomness from crypto/rand internally. The
// parameter is preserved on the signature to keep call sites
// compatible with a future deterministic-rand plumbing without
// another API break.
func (id *Identity) Sign(rand io.Reader, h2 [TranscriptLen]byte, role AuthRole, suite SuiteID) ([]byte, error) {
	if id == nil || id.PrivateKey == nil {
		return nil, errors.New("zap-pq: identity has no private key")
	}
	if rand == nil {
		rand = cryptorand.Reader
	}
	msg := signInput(h2, role, suite)
	sig, err := id.PrivateKey.SignCtx(rand, msg, SignCtx)
	if err != nil {
		return nil, err
	}
	if len(sig) != MLDSA65SigLen {
		return nil, errors.New("zap-pq: unexpected ML-DSA signature length")
	}
	return sig, nil
}

// SignDeterministic produces the §6.4 AUTH signature using FIPS 204
// §5.2 deterministic ML-DSA-65 (no randomness; sig is a pure function
// of (sk, h2, role, suite)).
//
// Production handshakes call Sign; SignDeterministic exists for KAT
// vectors and reproducible test fixtures. Same wire format, same
// verification path — only the per-signature entropy source differs.
//
// SECURITY NOTE: the deterministic variant is secure under standard
// ML-DSA assumptions but loses the side-channel defense-in-depth that
// the hedged (randomized) variant provides. Production node identities
// SHOULD use Sign; only test code should call this.
func (id *Identity) SignDeterministic(h2 [TranscriptLen]byte, role AuthRole, suite SuiteID) ([]byte, error) {
	if id == nil || id.PrivateKey == nil {
		return nil, errors.New("zap-pq: identity has no private key")
	}
	msg := signInput(h2, role, suite)
	sig, err := id.PrivateKey.SignCtxDeterministic(msg, SignCtx)
	if err != nil {
		return nil, err
	}
	if len(sig) != MLDSA65SigLen {
		return nil, errors.New("zap-pq: unexpected ML-DSA signature length")
	}
	return sig, nil
}

// VerifyAuth checks a §6.4 AUTH signature against this identity's
// public key. Returns ErrAuthFailed on any verification failure so
// callers can map cleanly to ALERT 0x03.
func (id *Identity) VerifyAuth(
	h2 [TranscriptLen]byte,
	role AuthRole,
	suite SuiteID,
	sig []byte,
) error {
	if id == nil || id.PublicKey == nil {
		return ErrAuthFailed
	}
	if len(sig) != MLDSA65SigLen {
		return ErrAuthFailed
	}
	msg := signInput(h2, role, suite)
	if !id.PublicKey.VerifySignatureCtx(msg, sig, SignCtx) {
		return ErrAuthFailed
	}
	return nil
}

// signInput assembles the §6.4 sign-input string:
//
//	LBL_PROTOCOL ∥ 0x00 ∥ ciphersuite ∥ 0x00 ∥ H_2 ∥ LBL_AUTH_{I|R}
//
// H_2 is exactly TranscriptLen bytes, the surrounding fields are
// fixed-length labels, so the encoding is unambiguous without a
// length prefix.
func signInput(h2 [TranscriptLen]byte, role AuthRole, suite SuiteID) []byte {
	roleLbl := role.Label()
	out := make([]byte, 0, len(LblProtocol)+1+1+1+TranscriptLen+len(roleLbl))
	out = append(out, LblProtocol...)
	out = append(out, 0x00)
	out = append(out, byte(suite))
	out = append(out, 0x00)
	out = append(out, h2[:]...)
	out = append(out, roleLbl...)
	return out
}
