// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"errors"
	"fmt"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/zap/handshake"
	"golang.org/x/crypto/sha3"
)

// VMRegistry is loaded from a signed chain config and consulted by
// the node side of every ZAP-PQ handshake to a VM plugin (§10.2).
//
// A node holds one VMRegistry per chain it serves; the registry is
// populated from on-chain VMRegistration records each of which is
// signed by the chain authority.
type VMRegistry interface {
	Lookup(vmID [32]byte) (*VMRegistration, bool)
}

// VMRegistration is the §10.2 chain-authority-signed record binding
// a VM plugin's ML-DSA-65 identity to its VMID.
//
//   - VMID          : SHA3-256(VMPubKey) — the canonical handle
//   - VMPubKey      : ML-DSA-65 public key bytes (MLDSA65PubLen)
//   - AuthoritySig  : chain-authority ML-DSA-65 signature over
//     (VMID ∥ VMPubKey)
//   - PrevVMSig     : optional — prior VM key's signature over the
//     same payload. Required for rotation; nil/empty for the
//     initial registration.
type VMRegistration struct {
	VMID         [32]byte
	VMPubKey     []byte
	AuthoritySig []byte
	PrevVMSig    []byte

	// PrevVMPubKey is the prior VM key for rotation. Verifiers
	// supply this out of band (from chain state) when checking
	// PrevVMSig. Stored here so a single struct round-trips the
	// rotation evidence.
	PrevVMPubKey []byte
}

// ErrRegistrationMalformed is returned when fields are missing or
// the wrong length.
var ErrRegistrationMalformed = errors.New("zap-pq: VMRegistration malformed")

// RegistrationMode selects which signatures VerifyRegistration
// requires. The chain-state loader decides which to pass based on
// whether the registry already holds an entry for this VMID.
//
// Passing the wrong mode is a contract bug detectable at the call
// site: ModeInitial refuses any registration that carries a
// PrevVMSig; ModeRotation requires both PrevVMSig and PrevVMPubKey.
// A loader that always calls ModeInitial would let a compromised
// chain authority overwrite an existing VM key without the old
// key's consent — which §10.2 forbids.
type RegistrationMode int

const (
	// ModeInitial: this VMID is being registered for the first time.
	// PrevVMSig MUST be empty; the chain-authority signature alone
	// is sufficient.
	ModeInitial RegistrationMode = iota
	// ModeRotation: this VMID already exists in the registry; the
	// caller is replacing its public key. Both the chain-authority
	// AND the previous VM key must sign the new (VMID, VMPubKey).
	ModeRotation
)

// VerifyRegistration checks AuthoritySig — and PrevVMSig under
// ModeRotation — against the chain authority public key. Returns the
// verified VM public key on success.
//
// Signing context for both signatures is the §6.4 SignCtx
// ("lux-zap-pq-v1") so the same audited verifier handles them.
// Payload is `VMID ∥ VMPubKey` so a signature over one (VMID, pubkey)
// pair cannot be re-used for a different pair.
func VerifyRegistration(
	reg *VMRegistration,
	chainAuthority *mldsa.PublicKey,
	mode RegistrationMode,
) (*mldsa.PublicKey, error) {
	if reg == nil {
		return nil, ErrRegistrationMalformed
	}
	if len(reg.VMPubKey) != handshake.MLDSA65PubLen {
		return nil, fmt.Errorf("%w: VMPubKey length %d", ErrRegistrationMalformed, len(reg.VMPubKey))
	}
	if len(reg.AuthoritySig) != handshake.MLDSA65SigLen {
		return nil, fmt.Errorf("%w: AuthoritySig length %d", ErrRegistrationMalformed, len(reg.AuthoritySig))
	}
	if chainAuthority == nil {
		return nil, fmt.Errorf("%w: nil chain authority", ErrRegistrationMalformed)
	}

	// VMID must equal SHA3-256(VMPubKey).
	wantVMID := sha3.Sum256(reg.VMPubKey)
	if reg.VMID != wantVMID {
		return nil, fmt.Errorf("%w: VMID ≠ SHA3-256(VMPubKey)", handshake.ErrVMIdentityMismatch)
	}

	payload := make([]byte, 0, 32+handshake.MLDSA65PubLen)
	payload = append(payload, reg.VMID[:]...)
	payload = append(payload, reg.VMPubKey...)

	if !chainAuthority.VerifySignatureCtx(payload, reg.AuthoritySig, handshake.SignCtx) {
		return nil, handshake.ErrAuthoritySigFailed
	}

	switch mode {
	case ModeInitial:
		if len(reg.PrevVMSig) != 0 || len(reg.PrevVMPubKey) != 0 {
			return nil, fmt.Errorf("%w: PrevVMSig/PrevVMPubKey present under ModeInitial",
				ErrRegistrationMalformed)
		}
	case ModeRotation:
		if len(reg.PrevVMPubKey) != handshake.MLDSA65PubLen {
			return nil, fmt.Errorf("%w: PrevVMPubKey length %d under ModeRotation",
				ErrRegistrationMalformed, len(reg.PrevVMPubKey))
		}
		if len(reg.PrevVMSig) != handshake.MLDSA65SigLen {
			return nil, fmt.Errorf("%w: PrevVMSig length %d under ModeRotation",
				ErrRegistrationMalformed, len(reg.PrevVMSig))
		}
		prev, err := mldsa.PublicKeyFromBytes(reg.PrevVMPubKey, mldsa.MLDSA65)
		if err != nil {
			return nil, fmt.Errorf("%w: PrevVMPubKey: %v", ErrRegistrationMalformed, err)
		}
		if !prev.VerifySignatureCtx(payload, reg.PrevVMSig, handshake.SignCtx) {
			return nil, handshake.ErrAuthoritySigFailed
		}
	default:
		return nil, fmt.Errorf("%w: unknown RegistrationMode %d", ErrRegistrationMalformed, mode)
	}

	return mldsa.PublicKeyFromBytes(reg.VMPubKey, mldsa.MLDSA65)
}

// StaticVMRegistry is an in-memory map implementation of VMRegistry
// suitable for genesis-loaded registrations. Production deployments
// will typically back this with an indexed chain-state cache, but
// the interface stays the same.
type StaticVMRegistry struct {
	entries map[[32]byte]*VMRegistration
}

// NewStaticVMRegistry returns an empty registry.
func NewStaticVMRegistry() *StaticVMRegistry {
	return &StaticVMRegistry{entries: make(map[[32]byte]*VMRegistration)}
}

// Add inserts a registration. The caller is responsible for having
// verified the registration via VerifyRegistration first.
func (r *StaticVMRegistry) Add(reg *VMRegistration) {
	r.entries[reg.VMID] = reg
}

// Lookup implements VMRegistry.
func (r *StaticVMRegistry) Lookup(vmID [32]byte) (*VMRegistration, bool) {
	reg, ok := r.entries[vmID]
	return reg, ok
}
