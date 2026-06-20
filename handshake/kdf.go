// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// SessionKeys is §8.3's five-expand output — the post-handshake
// secrets every Session is keyed from.
type SessionKeys struct {
	KInitToResp    [AEADKeyLen]byte
	KRespToInit    [AEADKeyLen]byte
	SaltInitToResp [NonceSaltLen]byte
	SaltRespToInit [NonceSaltLen]byte
	ResumptionPSK  [PSKKeyLen]byte
}

// Zeroize overwrites every key field with zeros. Callers MUST invoke
// this on the old SessionKeys after a rekey or on session close so
// stale key material does not linger on the heap.
func (k *SessionKeys) Zeroize() {
	for i := range k.KInitToResp {
		k.KInitToResp[i] = 0
	}
	for i := range k.KRespToInit {
		k.KRespToInit[i] = 0
	}
	for i := range k.SaltInitToResp {
		k.SaltInitToResp[i] = 0
	}
	for i := range k.SaltRespToInit {
		k.SaltRespToInit[i] = 0
	}
	for i := range k.ResumptionPSK {
		k.ResumptionPSK[i] = 0
	}
}

// DeriveSession runs §8 over a completed transcript hash and the two
// hybrid shared secrets.
//
//	IKM = u8(len(LblX25519)) ∥ LblX25519 ∥ u8(32) ∥ x25519_shared
//	    ∥ u8(len(LblMLKEM))  ∥ LblMLKEM  ∥ u8(32) ∥ mlkem_shared
//	PRK = HKDF-Extract(salt = H_2, IKM)
//	k_i2r        = HKDF-Expand(PRK, LBL_SESSION_I2R, 32)
//	k_r2i        = HKDF-Expand(PRK, LBL_SESSION_R2I, 32)
//	salt_i2r     = HKDF-Expand(PRK, LBL_SALT_I2R,    4)
//	salt_r2i     = HKDF-Expand(PRK, LBL_SALT_R2I,    4)
//	resumption   = HKDF-Expand(PRK, LBL_RESUMPTION, 32)
//
// HKDF runs over SHA3-256 per §8.4.
func DeriveSession(
	h2 [TranscriptLen]byte,
	x25519Shared [X25519SharedLen]byte,
	mlkemShared [MLKEM768SharedLen]byte,
) SessionKeys {
	ikm := buildIKM(x25519Shared, mlkemShared)
	prk := hkdf.Extract(sha3.New256, ikm, h2[:])

	var k SessionKeys
	expand(prk, LblSessionI2R, k.KInitToResp[:])
	expand(prk, LblSessionR2I, k.KRespToInit[:])
	expand(prk, LblSaltI2R, k.SaltInitToResp[:])
	expand(prk, LblSaltR2I, k.SaltRespToInit[:])
	expand(prk, LblResumption, k.ResumptionPSK[:])

	// IKM and PRK contain the hybrid secret material; zero them once
	// the per-direction keys have been extracted.
	for i := range ikm {
		ikm[i] = 0
	}
	for i := range prk {
		prk[i] = 0
	}
	return k
}

// DeriveResumed is the §12.2 PSK-resumption KDF. It folds the new
// X25519 shared secret with the cached resumption_psk into a fresh
// PRK and re-expands the five session secrets, salted by the resumed
// transcript hash H_2_psk.
func DeriveResumed(
	h2psk [TranscriptLen]byte,
	x25519Shared [X25519SharedLen]byte,
	resumptionPSK [PSKKeyLen]byte,
) SessionKeys {
	// IKM mirrors §8.1 but the second secret is the cached PSK,
	// labelled with LblResumption so a confused-deputy attacker
	// cannot replay a full-handshake mlkem_shared as a PSK.
	ikm := make([]byte, 0, 1+len(LblX25519)+1+X25519SharedLen+1+len(LblResumption)+1+PSKKeyLen)
	ikm = append(ikm, byte(len(LblX25519)))
	ikm = append(ikm, LblX25519...)
	ikm = append(ikm, byte(X25519SharedLen))
	ikm = append(ikm, x25519Shared[:]...)
	ikm = append(ikm, byte(len(LblResumption)))
	ikm = append(ikm, LblResumption...)
	ikm = append(ikm, byte(PSKKeyLen))
	ikm = append(ikm, resumptionPSK[:]...)

	prk := hkdf.Extract(sha3.New256, ikm, h2psk[:])

	var k SessionKeys
	expand(prk, LblSessionI2R, k.KInitToResp[:])
	expand(prk, LblSessionR2I, k.KRespToInit[:])
	expand(prk, LblSaltI2R, k.SaltInitToResp[:])
	expand(prk, LblSaltR2I, k.SaltRespToInit[:])
	expand(prk, LblResumption, k.ResumptionPSK[:])

	for i := range ikm {
		ikm[i] = 0
	}
	for i := range prk {
		prk[i] = 0
	}
	return k
}

// Ratchet implements §13 — derive the next per-direction key and
// nonce salt from the current key.
//
//	info_key  = LBL_REKEY ∥ 0x00 ∥ epoch_n ∥ 0x00
//	info_salt = LBL_REKEY ∥ 0x00 ∥ epoch_n ∥ 0x01
//	k_{n+1}    = HKDF-Expand(k_n, info_key,  32)
//	salt_{n+1} = HKDF-Expand(k_n, info_salt, 4)
//
// Two distinct Expand calls (not a single 36-byte read) — the
// info bytes differ so the output streams are independent.
//
// The caller is responsible for zeroising the old k_n / salt_n.
func Ratchet(kPrev [AEADKeyLen]byte, epoch uint8) (kNext [AEADKeyLen]byte, saltNext [NonceSaltLen]byte) {
	info := make([]byte, 0, len(LblRekey)+3)
	info = append(info, LblRekey...)
	info = append(info, 0x00, epoch, 0x00)
	expand(kPrev[:], info, kNext[:])

	info[len(info)-1] = 0x01
	expand(kPrev[:], info, saltNext[:])
	return kNext, saltNext
}

// PSKID derives the §12.1 psk_id (16-byte truncation of SHA3-256 of
// the resumption_psk). Pinned in code so issuance and lookup agree.
func PSKID(psk [PSKKeyLen]byte) [PSKIDLen]byte {
	h := sha3.Sum256(psk[:])
	var id [PSKIDLen]byte
	copy(id[:], h[:PSKIDLen])
	return id
}

// buildIKM packs §8.1.
func buildIKM(x25519Shared [X25519SharedLen]byte, mlkemShared [MLKEM768SharedLen]byte) []byte {
	out := make([]byte, 0, 1+len(LblX25519)+1+X25519SharedLen+1+len(LblMLKEM)+1+MLKEM768SharedLen)
	out = append(out, byte(len(LblX25519)))
	out = append(out, LblX25519...)
	out = append(out, byte(X25519SharedLen))
	out = append(out, x25519Shared[:]...)
	out = append(out, byte(len(LblMLKEM)))
	out = append(out, LblMLKEM...)
	out = append(out, byte(MLKEM768SharedLen))
	out = append(out, mlkemShared[:]...)
	return out
}

// expand is HKDF-Expand(SHA3-256, prk, info, len(out)) into out.
// Panics on read failure — the stdlib HKDF reader cannot fail
// short of a SHA3 panic, which would already terminate the program.
func expand(prk, info, out []byte) {
	r := hkdf.Expand(sha3.New256, prk, info)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("zap-pq: HKDF-Expand short read: " + err.Error())
	}
}
