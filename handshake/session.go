// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Session is the post-handshake AEAD-keyed stream specified by §9, §13.
//
// Send → produces one DATA frame on the wire.
// Recv → consumes one DATA (or REKEY) frame and returns the
//
//	plaintext payload of a DATA frame.
//
// Send and Recv are independently safe to call concurrently against
// the same Session, each under their own mutex.
//
// A Session is NOT net.Conn directly — the package-level conn_pq.go
// adapter wraps it with Read/Write semantics for legacy callers.
type Session struct {
	rw     io.ReadWriter
	closer io.Closer // optional underlying close hook
	role   AuthRole  // 'I' for initiator, 'R' for responder
	peerID [IDLen]byte
	suite  SuiteID

	// Send direction state.
	sendMu        sync.Mutex
	sendKey       [AEADKeyLen]byte
	sendSalt      [NonceSaltLen]byte
	sendCounter   uint64
	sendEpoch     uint8
	sendBytes     uint64
	sendBase      time.Time
	sendBytesCap  uint64
	sendFrameCap  uint64
	sendTimeCap   time.Duration
	sendDir       AuthRole // direction byte for AAD on send
	sendAEAD      cipher.AEAD
	sendAEADStale bool // true when sendKey changed since last AEAD build

	// Receive direction state.
	recvMu      sync.Mutex
	recvKey     [AEADKeyLen]byte
	recvSalt    [NonceSaltLen]byte
	recvCounter uint64 // last accepted (1-based; 0 = nothing yet accepted)
	recvHave    bool
	recvEpoch   uint8
	recvDir     AuthRole
	recvAEAD    cipher.AEAD

	closed atomic.Bool

	// Optional resumption_psk cached for the client to present on
	// subsequent connects (§12.1).
	clientPSK *ClientPSK
}

// newSession constructs a Session from finished SessionKeys. The
// `role` is the LOCAL role (Initiator or Responder).
func newSession(
	rw io.ReadWriter,
	role AuthRole,
	peerID [IDLen]byte,
	suite SuiteID,
	keys SessionKeys,
	now time.Time,
) (*Session, error) {
	s := &Session{
		rw:           rw,
		role:         role,
		peerID:       peerID,
		suite:        suite,
		sendBase:     now,
		sendBytesCap: RekeyBytesCap,
		sendFrameCap: RekeyFrameCap,
		sendTimeCap:  time.Duration(RekeyTimeSec) * time.Second,
	}
	if c, ok := rw.(io.Closer); ok {
		s.closer = c
	}

	switch role {
	case RoleInitiator:
		// initiator sends i->r and receives r->i
		s.sendKey = keys.KInitToResp
		s.sendSalt = keys.SaltInitToResp
		s.sendDir = RoleInitiator
		s.recvKey = keys.KRespToInit
		s.recvSalt = keys.SaltRespToInit
		s.recvDir = RoleResponder
	case RoleResponder:
		s.sendKey = keys.KRespToInit
		s.sendSalt = keys.SaltRespToInit
		s.sendDir = RoleResponder
		s.recvKey = keys.KInitToResp
		s.recvSalt = keys.SaltInitToResp
		s.recvDir = RoleInitiator
	default:
		return nil, fmt.Errorf("zap-pq: invalid session role 0x%02x", byte(role))
	}

	var err error
	s.sendAEAD, err = newAEAD(s.sendKey)
	if err != nil {
		return nil, err
	}
	s.recvAEAD, err = newAEAD(s.recvKey)
	if err != nil {
		return nil, err
	}

	// Cache the resumption_psk for the initiator. The peerID captured
	// here is the verified responder identity — it gets re-presented
	// on the next resumed handshake so Session.PeerID() remains
	// anchored to the identity originally pinned. (Responders rely on
	// PSKStore.Issue called by Responder.Run after the handshake.)
	if role == RoleInitiator {
		psk := MakeClientPSK(keys.ResumptionPSK, peerID, now)
		s.clientPSK = &psk
	}
	// Zero our copy of the resumption key in the local stack frame —
	// for the initiator it now lives in s.clientPSK; for the responder
	// the caller will hand it to PSKStore.Issue.
	// (The caller's keys variable is the master; we don't mutate that.)
	return s, nil
}

// Send encrypts payload and emits one DATA frame. Returns
// ErrSessionClosed on a closed session, ErrEpochExhausted if the
// next REKEY would wrap the epoch byte.
//
// Automatic REKEY: when sending payload would cross any §6.6
// threshold (frame count, time, bytes), Send emits a REKEY frame
// FIRST, ratchets locally, then emits the DATA frame.
func (s *Session) Send(payload []byte) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	// Closed check inside the mutex makes Close a hard barrier: a
	// Close that has won the CAS but is waiting on sendMu cannot let
	// an in-flight Send slip past, because that Send must acquire
	// sendMu first and will see closed=true under the lock.
	if s.closed.Load() {
		return ErrSessionClosed
	}

	if s.needsRekeyLocked(uint64(len(payload))) {
		if err := s.rekeyLocalLocked(); err != nil {
			return err
		}
	}

	// Build outer frame envelope. DATA body length = 8 + 4 + (len + tag).
	ctLen := uint32(len(payload) + AEADTagLen)
	outerLen := uint32(NonceCtrLen + 4 + int(ctLen))
	if outerLen > MaxFrameBody {
		return fmt.Errorf("%w: DATA payload too large %d", ErrDecodeError, len(payload))
	}

	nonce := buildNonce(s.sendSalt, s.sendCounter)
	aad := buildAAD(FrameData, outerLen, s.sendDir, s.sendEpoch)
	ct := s.sendAEAD.Seal(nil, nonce[:], payload, aad[:])
	if len(ct) != int(ctLen) {
		return fmt.Errorf("zap-pq: AEAD seal length unexpected %d != %d", len(ct), ctLen)
	}

	d := &DataFrame{NonceCounter: s.sendCounter, Ciphertext: ct}
	if err := writeFrame(s.rw, FrameData, d.Encode()); err != nil {
		return err
	}

	s.sendCounter++
	s.sendBytes += uint64(len(payload))
	return nil
}

// Recv reads one frame and returns the decrypted payload of a DATA.
//
// REKEY frames are absorbed transparently: Recv ratchets the recv
// state and continues reading until a DATA frame arrives or the
// underlying stream errors. ALERT frames are translated to typed
// errors via errorForAlert.
func (s *Session) Recv() ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	// Closed check inside the mutex makes Close a hard barrier; see
	// the matching comment on Send.
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	for {
		t, body, err := readFrame(s.rw)
		if err != nil {
			return nil, err
		}
		switch t {
		case FrameData:
			return s.handleDataLocked(body)
		case FrameRekey:
			rk, derr := DecodeRekey(body)
			if derr != nil {
				_ = writeAlertFor(s.rw, derr)
				return nil, derr
			}
			_ = rk // reason byte is informational
			if err := s.rekeyRemoteLocked(); err != nil {
				_ = writeAlertFor(s.rw, err)
				return nil, err
			}
			continue
		case FrameAlert:
			a, derr := DecodeAlert(body)
			if derr != nil {
				return nil, derr
			}
			return nil, errorForAlert(a.Code)
		default:
			err := fmt.Errorf("%w: unexpected session frame 0x%02x", ErrDecodeError, byte(t))
			_ = writeAlertFor(s.rw, err)
			return nil, err
		}
	}
}

func (s *Session) handleDataLocked(body []byte) ([]byte, error) {
	d, err := DecodeData(body)
	if err != nil {
		_ = writeAlertFor(s.rw, err)
		return nil, err
	}

	// Strict monotonic counter (§6.5). Reject anything not strictly
	// greater than what we last accepted.
	if s.recvHave && d.NonceCounter <= s.recvCounter {
		err := fmt.Errorf("%w: counter %d ≤ last %d", ErrNonceViolation, d.NonceCounter, s.recvCounter)
		_ = writeAlertFor(s.rw, err)
		return nil, err
	}
	// Counter must be < 2^31 between rekeys (§6.6).
	if d.NonceCounter >= RekeyFrameCap {
		err := fmt.Errorf("%w: counter %d past cap %d without REKEY",
			ErrNonceViolation, d.NonceCounter, uint64(RekeyFrameCap))
		_ = writeAlertFor(s.rw, err)
		return nil, err
	}

	outerLen := uint32(NonceCtrLen + 4 + len(d.Ciphertext))
	aad := buildAAD(FrameData, outerLen, s.recvDir, s.recvEpoch)
	nonce := buildNonce(s.recvSalt, d.NonceCounter)

	plain, err := s.recvAEAD.Open(nil, nonce[:], d.Ciphertext, aad[:])
	if err != nil {
		// AEAD failure → ALERT 0x03 (§9.4).
		_ = writeAlertFor(s.rw, ErrAuthFailed)
		return nil, ErrAuthFailed
	}
	s.recvCounter = d.NonceCounter
	s.recvHave = true
	return plain, nil
}

// Rekey explicitly initiates a local-side rekey. It is safe (and a
// no-op as far as wire correctness goes) to call at any time.
//
// Closed check inside sendMu mirrors Send: Close becomes a hard
// barrier for explicit rekeys too. A Rekey that races a Close
// returns ErrSessionClosed rather than a writeFrame IO error.
func (s *Session) Rekey() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed.Load() {
		return ErrSessionClosed
	}
	return s.rekeyLocalLocked()
}

func (s *Session) needsRekeyLocked(addBytes uint64) bool {
	if s.sendCounter+1 >= s.sendFrameCap {
		return true
	}
	if s.sendBytes+addBytes >= s.sendBytesCap {
		return true
	}
	if time.Since(s.sendBase) >= s.sendTimeCap {
		return true
	}
	return false
}

func (s *Session) rekeyLocalLocked() error {
	if s.sendEpoch == 0xFF {
		return ErrEpochExhausted
	}
	rk := &RekeyFrame{Reason: RekeyReasonExplicit}
	if err := writeFrame(s.rw, FrameRekey, rk.Encode()); err != nil {
		return err
	}
	newKey, newSalt := Ratchet(s.sendKey, s.sendEpoch)
	// Zero old key/salt.
	zeroBytes(s.sendKey[:])
	zeroBytes(s.sendSalt[:])
	s.sendKey = newKey
	s.sendSalt = newSalt
	s.sendEpoch++
	s.sendCounter = 0
	s.sendBytes = 0
	s.sendBase = time.Now()
	aead, err := newAEAD(s.sendKey)
	if err != nil {
		return err
	}
	s.sendAEAD = aead
	return nil
}

func (s *Session) rekeyRemoteLocked() error {
	if s.recvEpoch == 0xFF {
		return ErrEpochExhausted
	}
	newKey, newSalt := Ratchet(s.recvKey, s.recvEpoch)
	zeroBytes(s.recvKey[:])
	zeroBytes(s.recvSalt[:])
	s.recvKey = newKey
	s.recvSalt = newSalt
	s.recvEpoch++
	s.recvCounter = 0
	s.recvHave = false
	aead, err := newAEAD(s.recvKey)
	if err != nil {
		return err
	}
	s.recvAEAD = aead
	return nil
}

// Close marks the session closed, zeros all key material, and (if
// the underlying ReadWriter implements io.Closer) closes it.
//
// Ordering matters: we close the underlying conn BEFORE acquiring
// the per-direction mutexes. A Send / Recv parked inside writeFrame
// or readFrame is holding its mutex while blocked on the wire — if
// Close grabbed the mutex first, it would wait for the parked IO
// while the parked IO waits for somebody (us) to close the conn.
// Closing first unblocks the parked syscall, the parked goroutine
// returns an error and releases its mutex, and we then acquire the
// mutex contention-free to scrub state.
//
// If the underlying rw does NOT implement io.Closer (the in-memory
// io.ReadWriter test path), Close proceeds directly to mutex
// acquisition. Callers using a non-Closer transport must terminate
// any parked Send / Recv via other means (deadlines on the wrapped
// object) before invoking Close, or accept that Close will wait
// for the parked IO to complete naturally.
//
// Best-effort zeroisation: the raw key bytes are wiped, but the
// derived AES round-key schedule inside cipher.AEAD is not directly
// accessible from the Go stdlib. We nil the AEAD references so the
// GC can reclaim them; production with HSM-grade requirements
// should use a key wrapper that scrubs the round-key state.
func (s *Session) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Unblock any parked Send/Recv FIRST. After this, writeFrame /
	// readFrame inside the goroutines that hold sendMu / recvMu
	// return an IO error and release their mutexes naturally.
	var closeErr error
	if s.closer != nil {
		closeErr = s.closer.Close()
	}

	// Now safe to acquire — the parked IO either finished or is on
	// its way out, and any new Send/Recv hits the closed-check
	// inside its mutex acquisition and returns ErrSessionClosed.
	s.sendMu.Lock()
	zeroBytes(s.sendKey[:])
	zeroBytes(s.sendSalt[:])
	s.sendAEAD = nil
	s.sendMu.Unlock()
	s.recvMu.Lock()
	zeroBytes(s.recvKey[:])
	zeroBytes(s.recvSalt[:])
	s.recvAEAD = nil
	s.recvMu.Unlock()

	return closeErr
}

// PeerID returns SHA3-256 of the verified peer's static ML-DSA-65 pk.
func (s *Session) PeerID() [IDLen]byte { return s.peerID }

// Role returns the local role (Initiator or Responder).
func (s *Session) Role() AuthRole { return s.role }

// Epoch returns the current local send epoch. Used by tests; not
// part of the wire-visible state.
func (s *Session) Epoch() uint8 { return s.sendEpoch }

// ResumptionPSK returns the client-side cached resumption_psk for
// future HELLO_PSK use. Returns nil on the responder side (the
// responder's PSK is held in PSKStore instead).
func (s *Session) ResumptionPSK() *ClientPSK { return s.clientPSK }

// ---------- helpers ----------

// newAEAD builds an AES-256-GCM AEAD from a 32-byte key.
func newAEAD(key [AEADKeyLen]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// buildNonce assembles the §9.2 12-byte nonce.
func buildNonce(salt [NonceSaltLen]byte, counter uint64) [AEADNonceLen]byte {
	var n [AEADNonceLen]byte
	copy(n[:NonceSaltLen], salt[:])
	binary.BigEndian.PutUint64(n[NonceSaltLen:], counter)
	return n
}

// buildAAD assembles the §9.3 7-byte AAD:
//
//	frame_type (u8) ∥ length (u32 BE) ∥ direction (u8) ∥ epoch (u8)
func buildAAD(t FrameType, length uint32, dir AuthRole, epoch uint8) [7]byte {
	var a [7]byte
	a[0] = byte(t)
	binary.BigEndian.PutUint32(a[1:5], length)
	a[5] = byte(dir)
	a[6] = epoch
	return a
}

// zeroBytes overwrites slice with zeros. Mostly a self-documentation
// helper — the compiler can elide a naïve clear, so call sites that
// care about realised zeroisation should also keep the slice live
// via runtime.KeepAlive (see pq_zeroize_test.go).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
