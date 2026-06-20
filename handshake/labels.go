// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package handshake implements SPEC-ZAP-PQ-v1: the native post-quantum
// handshake and AEAD framing for ZAP. See docs/SPEC-ZAP-PQ-v1.md for the
// authoritative wire specification.
//
// The package decomposes the protocol along value/behaviour lines:
//
//   - Identity, Profile, SuiteID            : values (data, no behaviour)
//   - Transcript, SessionKeys               : derived values
//   - Frame{Hello, KEMInit, ...}            : wire codecs
//   - Initiator, Responder                  : state machines
//   - Session                               : the post-handshake AEAD stream
//   - ReplayCache, PSKStore                 : independent storage policies
//
// Nothing in this package imports net.Conn — it works against any
// io.ReadWriter so it can be exercised over in-memory pipes in tests.
package handshake

// §3 Constants. Each field is sized per the spec; the literals are the
// only place these numbers appear so a future ciphersuite addition
// can introduce its own constants without touching call sites.
const (
	MagicLen      = 4
	ClientRandLen = 16
	IDLen         = 32 // SHA3-256 output, also the client_id / VM ID length
	TimestampLen  = 8
	PSKIDLen      = 16
	PSKKeyLen     = 32

	X25519PubLen    = 32
	X25519SecLen    = 32
	X25519SharedLen = 32

	MLKEM768PubLen    = 1184
	MLKEM768CTLen     = 1088
	MLKEM768SharedLen = 32

	MLDSA65PubLen = 1952
	MLDSA65SigLen = 3309

	AEADKeyLen   = 32
	AEADNonceLen = 12
	AEADTagLen   = 16
	NonceSaltLen = 4
	NonceCtrLen  = 8

	TranscriptLen = 32 // SHA3-256 digest size

	MaxFrameBody = 1 << 24 // §5 — 16 MiB hard cap

	HandshakeTimeoutSec = 5
	ReplayWindowNS      = 30 * 1_000_000_000 // 30s in nanoseconds
	ReplayCacheTTLSec   = 60
	PSKLifetimeSec      = 3600
	RekeyTimeSec        = 3600
	RekeyFrameCap       = 1 << 31
	RekeyBytesCap       = 100 * (1 << 30)
)

// §3 Magic prefix "ZPQ1".
var Magic = [MagicLen]byte{0x5A, 0x50, 0x51, 0x31}

// §3 / §3.2 ciphersuite registry. Only 0x01 is wire-callable today.
type SuiteID uint8

const (
	SuiteReservedLo  SuiteID = 0x00
	SuiteX25519MLKEM SuiteID = 0x01
	SuiteReservedHi  SuiteID = 0xFF
)

// IsValid reports whether s is a callable ciphersuite. Reserved IDs
// (0x00, 0xFF) and the unallocated mid-range return false.
func (s SuiteID) IsValid() bool {
	return s == SuiteX25519MLKEM
}

// PQMode encodes HELLO.pq_mode (§6.1).
type PQMode uint8

const (
	PQModeClassicalPermitted PQMode = 0x00
	PQModePQRequired         PQMode = 0x01
	PQModePQOnly             PQMode = 0x02
)

// Profile is the chain-security stance applied at the wire boundary
// (§6.0). It is intentionally local — callers map their richer
// notions (lux/pq.Mode, ChainConfig) onto this small enum.
type Profile uint8

const (
	ProfileStrictPQ   Profile = 0x01 // refuse on magic mismatch, no fallback
	ProfilePermissive Profile = 0x02 // fall through to legacy ZAP on mismatch
	ProfileFIPS       Profile = 0x03 // same wire stance as StrictPQ; tagged for audit
)

// FrameType encodes the outer envelope type byte (§5, §6).
type FrameType uint8

const (
	FrameHello    FrameType = 0x01
	FrameKEMInit  FrameType = 0x02
	FrameKEMReply FrameType = 0x03
	FrameAuth     FrameType = 0x04
	FrameData     FrameType = 0x05
	FrameRekey    FrameType = 0x06
	FrameAlert    FrameType = 0x07
	FrameHelloPSK FrameType = 0x08
)

// AuthRole is the §6.4 role byte signed by each side.
type AuthRole uint8

const (
	RoleInitiator AuthRole = 0x49 // 'I'
	RoleResponder AuthRole = 0x52 // 'R'
)

// §3.1 wire labels. ASCII, no NUL terminator. Identical on both sides.
var (
	LblProtocol   = []byte("ZAP-PQ-v1")
	LblX25519     = []byte("X25519")
	LblMLKEM      = []byte("ML-KEM-768")
	LblSessionI2R = []byte("ZAP-PQ-v1 i->r")
	LblSessionR2I = []byte("ZAP-PQ-v1 r->i")
	LblSaltI2R    = []byte("ZAP-PQ-v1 nonce-salt i->r")
	LblSaltR2I    = []byte("ZAP-PQ-v1 nonce-salt r->i")
	LblResumption = []byte("ZAP-PQ-v1 resumption")
	LblRekey      = []byte("ZAP-PQ-v1 rekey")
	LblAuthI      = []byte("ZAP-PQ-v1 auth initiator")
	LblAuthR      = []byte("ZAP-PQ-v1 auth responder")
)

// SignCtx is the ML-DSA-65 context string applied to every AUTH
// signature (§6.4). Pinned in code so a future change forces a
// ciphersuite bump per §18.
var SignCtx = []byte("lux-zap-pq-v1")

// authLabel returns the per-role binding string for §6.4 sign_input.
func (r AuthRole) Label() []byte {
	switch r {
	case RoleInitiator:
		return LblAuthI
	case RoleResponder:
		return LblAuthR
	}
	return nil
}
