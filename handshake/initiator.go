// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/luxfi/crypto/mlkem"
	"golang.org/x/crypto/sha3"
)

// Initiator runs the §4 client side of the handshake.
//
// Required fields:
//
//   - Local: this side's static ML-DSA-65 identity (must have a
//     private key).
//
// Optional fields:
//
//   - Expected: pin the responder's identity. If non-nil, the
//     handshake aborts with ErrVMIdentityMismatch when
//     SHA3-256(responder_static_pk) ≠ Expected.ID().
//   - Profile: chain-security stance. Affects only what the wrapper
//     does on magic-prefix mismatch; once the handshake is engaged
//     the profile is enforced through PQMode + OfferedSchemes.
//   - PQMode: HELLO.pq_mode byte. Defaults to PQModePQOnly under
//     StrictPQ / FIPS, PQModeClassicalPermitted otherwise.
//   - Suite: ciphersuite byte. Defaults to SuiteX25519MLKEM (0x01).
//   - OfferedSchemes: HELLO.offered_schemes. Defaults to [Suite].
//   - Resume: cached PSK to attempt resumption with. If nil or
//     expired, Initiator runs a full handshake.
//   - Rand: entropy source for ephemerals + signing nonces. Defaults
//     to crypto/rand.Reader. KAT tests inject a deterministic reader.
//   - Now: clock for HELLO timestamps. Defaults to time.Now.
type Initiator struct {
	Local          *Identity
	Expected       *Identity
	Profile        Profile
	PQMode         PQMode
	Suite          SuiteID
	OfferedSchemes []SuiteID
	Resume         *ClientPSK

	Rand io.Reader
	Now  func() time.Time
}

// Run executes §4 over conn and returns a keyed Session on success.
// On any failure Run emits the appropriate ALERT (§14) before
// returning and the caller MUST close conn.
func (i *Initiator) Run(conn io.ReadWriter) (*Session, error) {
	if i.Local == nil || i.Local.PrivateKey == nil {
		return nil, errors.New("zap-pq: initiator requires Local with private key")
	}

	suite := i.Suite
	if suite == 0 {
		suite = SuiteX25519MLKEM
	}
	if !suite.IsValid() {
		return nil, fmt.Errorf("%w: suite 0x%02x", ErrUnsupportedSuite, byte(suite))
	}
	schemes := i.OfferedSchemes
	if len(schemes) == 0 {
		schemes = []SuiteID{suite}
	}
	pqMode := i.PQMode
	if pqMode == 0 && (i.Profile == ProfileStrictPQ || i.Profile == ProfileFIPS) {
		pqMode = PQModePQOnly
	}
	r := i.Rand
	if r == nil {
		r = rand.Reader
	}
	nowFn := i.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()

	// §6.0 magic prefix.
	if _, err := conn.Write(Magic[:]); err != nil {
		return nil, err
	}

	if i.Resume != nil && i.Resume.Until.After(now) {
		return i.runResume(conn, suite, pqMode, schemes, r, now)
	}
	return i.runFull(conn, suite, pqMode, schemes, r, now)
}

// ---------- full handshake ----------

func (i *Initiator) runFull(
	conn io.ReadWriter,
	suite SuiteID,
	pqMode PQMode,
	schemes []SuiteID,
	r io.Reader,
	now time.Time,
) (*Session, error) {
	// 1. Compose HELLO.
	var clientRand [ClientRandLen]byte
	if _, err := io.ReadFull(r, clientRand[:]); err != nil {
		return nil, err
	}
	hello := &HelloFrame{
		Suite:             suite,
		PQMode:            pqMode,
		ClientRandom:      clientRand,
		TimestampNS:       uint64(now.UnixNano()),
		ClientID:          i.Local.ID(),
		OfferedSchemes:    schemes,
		StaticPKInitiator: i.Local.PublicBytes(),
	}
	helloBody, err := hello.Encode()
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, FrameHello, helloBody); err != nil {
		return nil, err
	}

	// 2. Generate ephemerals (X25519 + ML-KEM-768).
	x25519Curve := ecdh.X25519()
	xEphSK, err := x25519Curve.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	xEphPK := xEphSK.PublicKey().Bytes()
	var xEphPKArr [X25519PubLen]byte
	copy(xEphPKArr[:], xEphPK)

	mlkemPub, mlkemPriv, err := mlkem.GenerateKeyPair(r, mlkem.MLKEM768)
	if err != nil {
		return nil, err
	}
	mlkemPubBytes := mlkemPub.Bytes()
	var mlkemPubArr [MLKEM768PubLen]byte
	copy(mlkemPubArr[:], mlkemPubBytes)

	kemInit := &KEMInitFrame{
		X25519EphPub: xEphPKArr,
		MLKEMEphPub:  mlkemPubArr,
	}
	kemInitBody := kemInit.Encode()
	if err := writeFrame(conn, FrameKEMInit, kemInitBody); err != nil {
		return nil, err
	}

	// 3. Read KEM_REPLY.
	replyBody, err := expectFrame(conn, FrameKEMReply)
	if err != nil {
		return nil, err
	}
	reply, err := DecodeKEMReply(replyBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}

	// 4. Compute hybrid shared secrets.
	respX25519PK, err := x25519Curve.NewPublicKey(reply.X25519EphPub[:])
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: bad responder X25519 pub: %v", ErrDecodeError, err))
	}
	xSharedBytes, err := xEphSK.ECDH(respX25519PK)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: X25519 ECDH: %v", ErrAuthFailed, err))
	}
	var xShared [X25519SharedLen]byte
	copy(xShared[:], xSharedBytes)
	zeroBytes(xSharedBytes)

	mlkemSharedBytes, err := mlkemPriv.Decapsulate(reply.MLKEMCiphertext[:])
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: ML-KEM decapsulate: %v", ErrAuthFailed, err))
	}
	var mlkemShared [MLKEM768SharedLen]byte
	copy(mlkemShared[:], mlkemSharedBytes)
	zeroBytes(mlkemSharedBytes)

	// 5. Zero ephemeral secrets per §10.4.
	zeroEphemerals(&xEphSK, &mlkemPriv)

	// 6. Verify responder identity against pin (if any).
	respIdentity, err := IdentityFromPublicBytes(reply.StaticPKResponder)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: bad responder static_pk: %v", ErrDecodeError, err))
	}
	if i.Expected != nil {
		want := i.Expected.ID()
		got := sha3.Sum256(reply.StaticPKResponder)
		if want != got {
			return nil, writeAlertFor(conn, ErrVMIdentityMismatch)
		}
	}

	// 7. Build transcript and derive H_2.
	tr := NewTranscript(suite)
	tr.AbsorbHello(helloBody)
	tr.AbsorbKEM(kemInitBody, replyBody)
	h2 := tr.FinishFull(i.Local.PublicBytes(), reply.StaticPKResponder, schemes)

	// 8. Verify responder AUTH before sending our own.
	authRBody, err := expectFrame(conn, FrameAuth)
	if err != nil {
		return nil, err
	}
	authR, err := DecodeAuth(authRBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if authR.Role != RoleResponder {
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: expected responder AUTH, got role 0x%02x", ErrAuthFailed, byte(authR.Role)))
	}
	if err := respIdentity.VerifyAuth(h2, RoleResponder, suite, authR.Signature); err != nil {
		return nil, writeAlertFor(conn, err)
	}

	// 9. Sign and send our AUTH.
	mySig, err := i.Local.Sign(r, h2, RoleInitiator, suite)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: sign: %v", ErrAuthFailed, err))
	}
	myAuth := &AuthFrame{Role: RoleInitiator, Signature: mySig}
	myAuthBody, err := myAuth.Encode()
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if err := writeFrame(conn, FrameAuth, myAuthBody); err != nil {
		return nil, err
	}

	// 10. Derive session keys and return.
	keys := DeriveSession(h2, xShared, mlkemShared)
	zeroBytes(xShared[:])
	zeroBytes(mlkemShared[:])
	runtime.KeepAlive(xShared)
	runtime.KeepAlive(mlkemShared)

	sess, err := newSession(conn, RoleInitiator, respIdentity.ID(), suite, keys, time.Now())
	if err != nil {
		return nil, err
	}
	// Caller will hold the session, but we still hold keys.ResumptionPSK
	// inside the Session.clientPSK; the local var is wiped.
	keys.Zeroize()
	return sess, nil
}

// ---------- resumed handshake (§12.2) ----------

func (i *Initiator) runResume(
	conn io.ReadWriter,
	suite SuiteID,
	pqMode PQMode,
	schemes []SuiteID,
	r io.Reader,
	now time.Time,
) (*Session, error) {
	// 1. Fresh X25519 ephemeral (§12.2 requires this).
	x25519Curve := ecdh.X25519()
	xEphSK, err := x25519Curve.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	xEphPK := xEphSK.PublicKey().Bytes()
	var xEphPKArr [X25519PubLen]byte
	copy(xEphPKArr[:], xEphPK)

	var clientRand [ClientRandLen]byte
	if _, err := io.ReadFull(r, clientRand[:]); err != nil {
		return nil, err
	}

	hello := &HelloPSKFrame{
		Suite:        suite,
		PQMode:       pqMode,
		ClientRandom: clientRand,
		TimestampNS:  uint64(now.UnixNano()),
		PSKID:        i.Resume.ID,
		X25519EphPub: xEphPKArr,
	}
	helloBody := hello.Encode()
	if err := writeFrame(conn, FrameHelloPSK, helloBody); err != nil {
		return nil, err
	}

	// 2. Responder echoes its X25519 ephemeral via KEM_REPLY (but
	// the spec collapses to "directly to AUTH" — we treat the
	// responder's KEM_REPLY in the resumed path as carrying only its
	// fresh X25519 pubkey + zero-length ML-KEM/static fields). To
	// stay strict with the spec wording — which says "skips ML-KEM,
	// derives a new session via §12, and proceeds directly to AUTH" —
	// we expect a small ResumeReply frame carrying only the
	// responder's X25519 ephemeral. We piggyback on KEM_REPLY's
	// frame type with mlkem_ct + static_pk truncated to zero-length
	// sentinels via a distinct frame layout: REKEY/ALERT are too
	// narrow, so we add a dedicated FrameResumeReply allocation in
	// §6.3 — but the spec does not allocate one, so we instead
	// reuse FrameKEMReply with the static_pk replaced by a
	// 1952-byte zero block (acceptable because AUTH is skipped) and
	// a zero ML-KEM ciphertext. That is fragile. The current
	// reference accepts only the bare responder X25519 ephemeral
	// in a 32-byte FrameKEMReply body when handshakeIsResumption is
	// true — kept as an implementation detail until §6.x adds a
	// proper ResumeReply opcode.
	t, body, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	if t == FrameAlert {
		a, derr := DecodeAlert(body)
		if derr != nil {
			return nil, derr
		}
		return nil, errorForAlert(a.Code)
	}
	if t != FrameKEMReply || len(body) != X25519PubLen {
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: resumed reply expected 32 bytes, got type 0x%02x len %d",
				ErrDecodeError, byte(t), len(body)))
	}
	var respEph [X25519PubLen]byte
	copy(respEph[:], body)

	respX25519PK, err := x25519Curve.NewPublicKey(respEph[:])
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrDecodeError, err))
	}
	xSharedBytes, err := xEphSK.ECDH(respX25519PK)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrAuthFailed, err))
	}
	var xShared [X25519SharedLen]byte
	copy(xShared[:], xSharedBytes)
	zeroBytes(xSharedBytes)

	tr := NewTranscript(suite)
	tr.AbsorbHello(helloBody)
	h2psk := tr.FinishPSK(respEph[:])

	keys := DeriveResumed(h2psk, xShared, i.Resume.PSK)
	zeroBytes(xShared[:])
	zeroEphemerals(&xEphSK, nil)

	// AUTH frames are NOT exchanged in resumption — possession of
	// the PSK is the authentication. The peerID carried in the cached
	// PSK is the verified responder identity from the original
	// handshake; Session.PeerID returns it so callers' authorization
	// decisions stay anchored to who the initiator originally pinned.
	sess, err := newSession(conn, RoleInitiator, i.Resume.PeerID, suite, keys, time.Now())
	if err != nil {
		return nil, err
	}
	keys.Zeroize()
	return sess, nil
}

// zeroEphemerals overwrites the in-memory representation of
// the ephemeral secrets per §10.4. Pointers are taken by reference
// so the caller's locals are nil'd out and runtime.KeepAlive forces
// the compiler not to elide the write.
func zeroEphemerals(x **ecdh.PrivateKey, m **mlkem.PrivateKey) {
	if x != nil && *x != nil {
		// crypto/ecdh keeps the secret in an unexported field whose
		// bytes we cannot directly overwrite. Best effort: drop the
		// reference so it becomes GC-reachable, then KeepAlive to
		// defeat compiler dead-store elimination on the local.
		*x = nil
		runtime.KeepAlive(x)
	}
	if m != nil && *m != nil {
		*m = nil
		runtime.KeepAlive(m)
	}
}
