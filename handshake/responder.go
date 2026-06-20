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

// Responder runs the §4 server side of the handshake.
//
// Required fields:
//
//   - Local: server's static ML-DSA-65 identity (must have a
//     private key).
//
// Optional fields:
//
//   - Profile: chain-security stance. Under StrictPQ / FIPS the
//     responder refuses HELLOs that advertise PQModeClassicalPermitted
//     or offered_schemes lists containing non-PQ suites.
//   - AcceptedSuites: server-side ciphersuite allowlist. Empty means
//     {SuiteX25519MLKEM}.
//   - ReplayCache: §11 replay state. nil disables cache lookups
//     (timestamp-only protection — production must supply a cache).
//   - PSKStore: §12 PSK issuer + redeemer. nil disables resumption.
//
// Rand / Now: deterministic overrides for KAT testing.
type Responder struct {
	Local          *Identity
	Profile        Profile
	AcceptedSuites []SuiteID
	ReplayCache    *ReplayCache
	PSKStore       *PSKStore

	Rand io.Reader
	Now  func() time.Time
}

// Run executes §4 over conn and returns a keyed Session on success.
// Mirrors Initiator.Run: on any failure Run emits the appropriate
// ALERT and returns the typed error.
func (rs *Responder) Run(conn io.ReadWriter) (*Session, error) {
	if rs.Local == nil || rs.Local.PrivateKey == nil {
		return nil, errors.New("zap-pq: responder requires Local with private key")
	}
	// Fail-closed under strict profiles: a nil ReplayCache would
	// silently disable §11 protection, turning the responder into a
	// cheap DoS amplifier (no timestamp gate, no (client_id,
	// client_random) dedup). Operators sometimes forget the field;
	// refuse rather than let them ship a broken posture.
	if (rs.Profile == ProfileStrictPQ || rs.Profile == ProfileFIPS) && rs.ReplayCache == nil {
		return nil, errors.New("zap-pq: ReplayCache is required under StrictPQ/FIPS profile")
	}

	r := rs.Rand
	if r == nil {
		r = rand.Reader
	}
	nowFn := rs.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	// §6.0 magic prefix.
	var magic [MagicLen]byte
	if _, err := io.ReadFull(conn, magic[:]); err != nil {
		return nil, err
	}
	if magic != Magic {
		return nil, ErrMagicMismatch
	}

	// First handshake frame: HELLO (full) or HELLO_PSK (resumed).
	t, body, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	switch t {
	case FrameHello:
		return rs.runFull(conn, body, r, nowFn)
	case FrameHelloPSK:
		return rs.runResume(conn, body, r, nowFn)
	case FrameAlert:
		a, derr := DecodeAlert(body)
		if derr != nil {
			return nil, derr
		}
		return nil, errorForAlert(a.Code)
	default:
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: unexpected first frame 0x%02x", ErrDecodeError, byte(t)))
	}
}

// ---------- full handshake ----------

func (rs *Responder) runFull(conn io.ReadWriter, helloBody []byte, r io.Reader, nowFn func() time.Time) (*Session, error) {
	hello, err := DecodeHello(helloBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}

	// Suite admissibility.
	if !rs.acceptsSuite(hello.Suite) {
		return nil, writeAlertFor(conn, ErrUnsupportedSuite)
	}

	// Strict-PQ downgrade defence.
	if rs.Profile == ProfileStrictPQ || rs.Profile == ProfileFIPS {
		if hello.PQMode == PQModeClassicalPermitted {
			return nil, writeAlertFor(conn, ErrDowngradeRefused)
		}
		for _, s := range hello.OfferedSchemes {
			if !s.IsValid() {
				return nil, writeAlertFor(conn, ErrDowngradeRefused)
			}
		}
	}

	// Replay gate (§11).
	if rs.ReplayCache != nil {
		if err := rs.ReplayCache.CheckTimestamp(hello.TimestampNS); err != nil {
			return nil, writeAlertFor(conn, err)
		}
		if rs.ReplayCache.SeenOrAdd(hello.ClientID, hello.ClientRandom) {
			return nil, writeAlertFor(conn, ErrReplayDetected)
		}
	}

	// client_id binding (§6.1 / UKS defence).
	expectedID := sha3.Sum256(hello.StaticPKInitiator)
	if expectedID != hello.ClientID {
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: client_id ≠ SHA3-256(static_pk_initiator)", ErrAuthFailed))
	}
	initIdentity, err := IdentityFromPublicBytes(hello.StaticPKInitiator)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrDecodeError, err))
	}

	// Read KEM_INIT.
	kemInitBody, err := expectFrame(conn, FrameKEMInit)
	if err != nil {
		return nil, err
	}
	kemInit, err := DecodeKEMInit(kemInitBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}

	// Generate responder ephemeral X25519 and ML-KEM encap.
	x25519Curve := ecdh.X25519()
	xEphSK, err := x25519Curve.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	xEphPK := xEphSK.PublicKey().Bytes()
	var xEphPKArr [X25519PubLen]byte
	copy(xEphPKArr[:], xEphPK)

	initX25519PK, err := x25519Curve.NewPublicKey(kemInit.X25519EphPub[:])
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrDecodeError, err))
	}
	xSharedBytes, err := xEphSK.ECDH(initX25519PK)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrAuthFailed, err))
	}
	var xShared [X25519SharedLen]byte
	copy(xShared[:], xSharedBytes)
	zeroBytes(xSharedBytes)

	mlkemPub, err := mlkem.PublicKeyFromBytes(kemInit.MLKEMEphPub[:], mlkem.MLKEM768)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrDecodeError, err))
	}
	mlkemCT, mlkemSharedBytes, err := mlkemPub.Encapsulate(r)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrAuthFailed, err))
	}
	if len(mlkemCT) != MLKEM768CTLen {
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: ML-KEM ciphertext length %d", ErrAuthFailed, len(mlkemCT)))
	}
	var mlkemCTArr [MLKEM768CTLen]byte
	copy(mlkemCTArr[:], mlkemCT)
	var mlkemShared [MLKEM768SharedLen]byte
	copy(mlkemShared[:], mlkemSharedBytes)
	zeroBytes(mlkemSharedBytes)

	// Zero our ephemeral X25519 SK as soon as we have the shared.
	zeroEphemerals(&xEphSK, nil)

	// Build KEM_REPLY and the transcript.
	reply := &KEMReplyFrame{
		X25519EphPub:      xEphPKArr,
		MLKEMCiphertext:   mlkemCTArr,
		StaticPKResponder: rs.Local.PublicBytes(),
	}
	replyBody, err := reply.Encode()
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if err := writeFrame(conn, FrameKEMReply, replyBody); err != nil {
		return nil, err
	}

	tr := NewTranscript(hello.Suite)
	tr.AbsorbHello(helloBody)
	tr.AbsorbKEM(kemInitBody, replyBody)
	h2 := tr.FinishFull(hello.StaticPKInitiator, rs.Local.PublicBytes(), hello.OfferedSchemes)

	// Sign and send responder AUTH first.
	mySig, err := rs.Local.Sign(r, h2, RoleResponder, hello.Suite)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: sign: %v", ErrAuthFailed, err))
	}
	myAuth := &AuthFrame{Role: RoleResponder, Signature: mySig}
	myAuthBody, err := myAuth.Encode()
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if err := writeFrame(conn, FrameAuth, myAuthBody); err != nil {
		return nil, err
	}

	// Read initiator AUTH and verify.
	authIBody, err := expectFrame(conn, FrameAuth)
	if err != nil {
		return nil, err
	}
	authI, err := DecodeAuth(authIBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if authI.Role != RoleInitiator {
		return nil, writeAlertFor(conn,
			fmt.Errorf("%w: expected initiator AUTH, got 0x%02x", ErrAuthFailed, byte(authI.Role)))
	}
	if err := initIdentity.VerifyAuth(h2, RoleInitiator, hello.Suite, authI.Signature); err != nil {
		return nil, writeAlertFor(conn, err)
	}

	// Derive session keys.
	keys := DeriveSession(h2, xShared, mlkemShared)
	zeroBytes(xShared[:])
	zeroBytes(mlkemShared[:])
	runtime.KeepAlive(xShared)
	runtime.KeepAlive(mlkemShared)

	// Optionally issue a resumption PSK for the next handshake.
	if rs.PSKStore != nil {
		rs.PSKStore.Issue(keys.ResumptionPSK, initIdentity.ID())
	}

	sess, err := newSession(conn, RoleResponder, initIdentity.ID(), hello.Suite, keys, nowFn())
	if err != nil {
		return nil, err
	}
	keys.Zeroize()
	return sess, nil
}

// ---------- resumed handshake ----------

func (rs *Responder) runResume(conn io.ReadWriter, helloBody []byte, r io.Reader, nowFn func() time.Time) (*Session, error) {
	hello, err := DecodeHelloPSK(helloBody)
	if err != nil {
		return nil, writeAlertFor(conn, err)
	}
	if !rs.acceptsSuite(hello.Suite) {
		return nil, writeAlertFor(conn, ErrUnsupportedSuite)
	}
	if rs.Profile == ProfileStrictPQ || rs.Profile == ProfileFIPS {
		if hello.PQMode == PQModeClassicalPermitted {
			return nil, writeAlertFor(conn, ErrDowngradeRefused)
		}
	}
	if rs.ReplayCache != nil {
		if err := rs.ReplayCache.CheckTimestamp(hello.TimestampNS); err != nil {
			return nil, writeAlertFor(conn, err)
		}
		// Dedup HELLO_PSK frames on (psk_id, client_random). Without
		// this gate an on-path attacker who captures a HELLO_PSK can
		// race it to the responder ahead of the legitimate peer,
		// burning the PSK and forcing every resumption to fall back
		// to a full handshake (responder loses the ~12× CPU win).
		// The key is namespaced via SHA3-256(psk_id) so it can never
		// collide with a full-handshake (client_id, client_random)
		// tuple in the same cache.
		var pskNS [IDLen]byte
		pskHash := sha3.Sum256(hello.PSKID[:])
		copy(pskNS[:], pskHash[:])
		if rs.ReplayCache.SeenOrAdd(pskNS, hello.ClientRandom) {
			return nil, writeAlertFor(conn, ErrReplayDetected)
		}
	}

	if rs.PSKStore == nil {
		return nil, writeAlertFor(conn, ErrPSKUnknown)
	}
	psk, clientID, ok := rs.PSKStore.Redeem(hello.PSKID)
	if !ok {
		return nil, writeAlertFor(conn, ErrPSKUnknown)
	}

	// Generate fresh X25519 ephemeral.
	x25519Curve := ecdh.X25519()
	xEphSK, err := x25519Curve.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	xEphPK := xEphSK.PublicKey().Bytes()
	var xEphPKArr [X25519PubLen]byte
	copy(xEphPKArr[:], xEphPK)

	initX25519PK, err := x25519Curve.NewPublicKey(hello.X25519EphPub[:])
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrDecodeError, err))
	}
	xSharedBytes, err := xEphSK.ECDH(initX25519PK)
	if err != nil {
		return nil, writeAlertFor(conn, fmt.Errorf("%w: %v", ErrAuthFailed, err))
	}
	var xShared [X25519SharedLen]byte
	copy(xShared[:], xSharedBytes)
	zeroBytes(xSharedBytes)
	zeroEphemerals(&xEphSK, nil)

	// Compact reply: 32-byte responder X25519 ephemeral under
	// FrameKEMReply, no static_pk / no AUTH (the PSK is the auth).
	if err := writeFrame(conn, FrameKEMReply, xEphPKArr[:]); err != nil {
		return nil, err
	}

	tr := NewTranscript(hello.Suite)
	tr.AbsorbHello(helloBody)
	h2psk := tr.FinishPSK(xEphPKArr[:])

	keys := DeriveResumed(h2psk, xShared, psk)
	zeroBytes(xShared[:])
	zeroBytes(psk[:])

	// Optionally issue a fresh PSK for the next resumption.
	if rs.PSKStore != nil {
		rs.PSKStore.Issue(keys.ResumptionPSK, clientID)
	}

	sess, err := newSession(conn, RoleResponder, clientID, hello.Suite, keys, nowFn())
	if err != nil {
		return nil, err
	}
	keys.Zeroize()
	return sess, nil
}

// acceptsSuite reports whether s is in the server's allowlist.
// Empty allowlist accepts only the v1 default suite.
func (rs *Responder) acceptsSuite(s SuiteID) bool {
	if !s.IsValid() {
		return false
	}
	if len(rs.AcceptedSuites) == 0 {
		return s == SuiteX25519MLKEM
	}
	for _, a := range rs.AcceptedSuites {
		if a == s {
			return true
		}
	}
	return false
}
