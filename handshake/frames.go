// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package handshake

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// All multi-byte integers on the wire are big-endian (§2).
// Encoders return the body bytes (§5 frame envelope = type ∥ length ∥ body).
// writeFrame and readFrame wrap a body with the outer envelope.

// ---------- HELLO (§6.1) ----------

type HelloFrame struct {
	Suite             SuiteID
	PQMode            PQMode
	ClientRandom      [ClientRandLen]byte
	TimestampNS       uint64
	ClientID          [IDLen]byte
	OfferedSchemes    []SuiteID
	StaticPKInitiator []byte // MLDSA65PubLen
}

// Encode returns the wire-encoded HELLO body (no outer type/length).
func (h *HelloFrame) Encode() ([]byte, error) {
	if len(h.StaticPKInitiator) != MLDSA65PubLen {
		return nil, fmt.Errorf("%w: HELLO static_pk_initiator length %d, want %d",
			ErrDecodeError, len(h.StaticPKInitiator), MLDSA65PubLen)
	}
	if len(h.OfferedSchemes) == 0 {
		return nil, fmt.Errorf("%w: HELLO offered_schemes empty", ErrDecodeError)
	}

	bodyLen := 1 + 1 + ClientRandLen + TimestampLen + IDLen +
		4 + len(h.OfferedSchemes) + MLDSA65PubLen
	out := make([]byte, 0, bodyLen)

	out = append(out, byte(h.Suite))
	out = append(out, byte(h.PQMode))
	out = append(out, h.ClientRandom[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], h.TimestampNS)
	out = append(out, ts[:]...)
	out = append(out, h.ClientID[:]...)

	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(h.OfferedSchemes)))
	out = append(out, lp[:]...)
	for _, s := range h.OfferedSchemes {
		out = append(out, byte(s))
	}
	out = append(out, h.StaticPKInitiator...)
	return out, nil
}

// DecodeHello parses a HELLO body. Validates lengths but does not
// check cryptographic facts (those belong to the Responder).
func DecodeHello(body []byte) (*HelloFrame, error) {
	const fixedLen = 1 + 1 + ClientRandLen + TimestampLen + IDLen + 4
	if len(body) < fixedLen+MLDSA65PubLen {
		return nil, fmt.Errorf("%w: HELLO too short %d", ErrDecodeError, len(body))
	}
	h := &HelloFrame{
		Suite:  SuiteID(body[0]),
		PQMode: PQMode(body[1]),
	}
	off := 2
	copy(h.ClientRandom[:], body[off:off+ClientRandLen])
	off += ClientRandLen
	h.TimestampNS = binary.BigEndian.Uint64(body[off : off+TimestampLen])
	off += TimestampLen
	copy(h.ClientID[:], body[off:off+IDLen])
	off += IDLen
	schemesLen := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	// schemesLen counts BYTES of u8 ciphersuite IDs.
	if schemesLen > uint32(MaxFrameBody) || int(schemesLen) > len(body)-off-MLDSA65PubLen {
		return nil, fmt.Errorf("%w: HELLO offered_schemes length %d invalid",
			ErrDecodeError, schemesLen)
	}
	if schemesLen == 0 {
		return nil, fmt.Errorf("%w: HELLO offered_schemes empty", ErrDecodeError)
	}
	h.OfferedSchemes = make([]SuiteID, schemesLen)
	for i := uint32(0); i < schemesLen; i++ {
		h.OfferedSchemes[i] = SuiteID(body[off+int(i)])
	}
	off += int(schemesLen)
	if len(body)-off != MLDSA65PubLen {
		return nil, fmt.Errorf("%w: HELLO trailing %d bytes after static_pk",
			ErrDecodeError, len(body)-off-MLDSA65PubLen)
	}
	h.StaticPKInitiator = append([]byte(nil), body[off:off+MLDSA65PubLen]...)

	// offered_schemes MUST include suite (§6.1).
	included := false
	for _, s := range h.OfferedSchemes {
		if s == h.Suite {
			included = true
			break
		}
	}
	if !included {
		return nil, fmt.Errorf("%w: HELLO suite 0x%02x not in offered_schemes",
			ErrDecodeError, byte(h.Suite))
	}
	return h, nil
}

// ---------- KEM_INIT (§6.2) ----------

type KEMInitFrame struct {
	X25519EphPub [X25519PubLen]byte
	MLKEMEphPub  [MLKEM768PubLen]byte
}

func (k *KEMInitFrame) Encode() []byte {
	out := make([]byte, 0, X25519PubLen+MLKEM768PubLen)
	out = append(out, k.X25519EphPub[:]...)
	out = append(out, k.MLKEMEphPub[:]...)
	return out
}

func DecodeKEMInit(body []byte) (*KEMInitFrame, error) {
	if len(body) != X25519PubLen+MLKEM768PubLen {
		return nil, fmt.Errorf("%w: KEM_INIT length %d, want %d",
			ErrDecodeError, len(body), X25519PubLen+MLKEM768PubLen)
	}
	k := &KEMInitFrame{}
	copy(k.X25519EphPub[:], body[:X25519PubLen])
	copy(k.MLKEMEphPub[:], body[X25519PubLen:])
	return k, nil
}

// ---------- KEM_REPLY (§6.3) ----------

type KEMReplyFrame struct {
	X25519EphPub      [X25519PubLen]byte
	MLKEMCiphertext   [MLKEM768CTLen]byte
	StaticPKResponder []byte // MLDSA65PubLen
}

func (k *KEMReplyFrame) Encode() ([]byte, error) {
	if len(k.StaticPKResponder) != MLDSA65PubLen {
		return nil, fmt.Errorf("%w: KEM_REPLY static_pk_responder length %d, want %d",
			ErrDecodeError, len(k.StaticPKResponder), MLDSA65PubLen)
	}
	out := make([]byte, 0, X25519PubLen+MLKEM768CTLen+MLDSA65PubLen)
	out = append(out, k.X25519EphPub[:]...)
	out = append(out, k.MLKEMCiphertext[:]...)
	out = append(out, k.StaticPKResponder...)
	return out, nil
}

func DecodeKEMReply(body []byte) (*KEMReplyFrame, error) {
	want := X25519PubLen + MLKEM768CTLen + MLDSA65PubLen
	if len(body) != want {
		return nil, fmt.Errorf("%w: KEM_REPLY length %d, want %d",
			ErrDecodeError, len(body), want)
	}
	k := &KEMReplyFrame{}
	off := 0
	copy(k.X25519EphPub[:], body[off:off+X25519PubLen])
	off += X25519PubLen
	copy(k.MLKEMCiphertext[:], body[off:off+MLKEM768CTLen])
	off += MLKEM768CTLen
	k.StaticPKResponder = append([]byte(nil), body[off:off+MLDSA65PubLen]...)
	return k, nil
}

// ---------- AUTH (§6.4) ----------

type AuthFrame struct {
	Role      AuthRole
	Signature []byte // MLDSA65SigLen
}

func (a *AuthFrame) Encode() ([]byte, error) {
	if len(a.Signature) != MLDSA65SigLen {
		return nil, fmt.Errorf("%w: AUTH signature length %d, want %d",
			ErrDecodeError, len(a.Signature), MLDSA65SigLen)
	}
	if a.Role != RoleInitiator && a.Role != RoleResponder {
		return nil, fmt.Errorf("%w: AUTH role 0x%02x invalid",
			ErrDecodeError, byte(a.Role))
	}
	out := make([]byte, 0, 1+MLDSA65SigLen)
	out = append(out, byte(a.Role))
	out = append(out, a.Signature...)
	return out, nil
}

func DecodeAuth(body []byte) (*AuthFrame, error) {
	if len(body) != 1+MLDSA65SigLen {
		return nil, fmt.Errorf("%w: AUTH length %d, want %d",
			ErrDecodeError, len(body), 1+MLDSA65SigLen)
	}
	role := AuthRole(body[0])
	if role != RoleInitiator && role != RoleResponder {
		return nil, fmt.Errorf("%w: AUTH role 0x%02x invalid",
			ErrDecodeError, byte(role))
	}
	return &AuthFrame{
		Role:      role,
		Signature: append([]byte(nil), body[1:]...),
	}, nil
}

// ---------- DATA (§6.5) ----------

type DataFrame struct {
	NonceCounter uint64
	Ciphertext   []byte
}

func (d *DataFrame) Encode() []byte {
	out := make([]byte, 0, NonceCtrLen+4+len(d.Ciphertext))
	var nc [8]byte
	binary.BigEndian.PutUint64(nc[:], d.NonceCounter)
	out = append(out, nc[:]...)
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(d.Ciphertext)))
	out = append(out, lp[:]...)
	out = append(out, d.Ciphertext...)
	return out
}

func DecodeData(body []byte) (*DataFrame, error) {
	if len(body) < NonceCtrLen+4 {
		return nil, fmt.Errorf("%w: DATA too short %d", ErrDecodeError, len(body))
	}
	d := &DataFrame{
		NonceCounter: binary.BigEndian.Uint64(body[:NonceCtrLen]),
	}
	ctLen := binary.BigEndian.Uint32(body[NonceCtrLen : NonceCtrLen+4])
	if int(ctLen) != len(body)-NonceCtrLen-4 {
		return nil, fmt.Errorf("%w: DATA ciphertext length mismatch", ErrDecodeError)
	}
	d.Ciphertext = body[NonceCtrLen+4:]
	return d, nil
}

// ---------- REKEY (§6.6) ----------

type RekeyFrame struct {
	Reason uint8
}

const (
	RekeyReasonCounterLimit uint8 = 0x01
	RekeyReasonTimeLimit    uint8 = 0x02
	RekeyReasonBytesLimit   uint8 = 0x03
	RekeyReasonExplicit     uint8 = 0x04
)

func (r *RekeyFrame) Encode() []byte { return []byte{r.Reason} }

func DecodeRekey(body []byte) (*RekeyFrame, error) {
	if len(body) != 1 {
		return nil, fmt.Errorf("%w: REKEY length %d, want 1", ErrDecodeError, len(body))
	}
	return &RekeyFrame{Reason: body[0]}, nil
}

// ---------- ALERT (§6.7) ----------

type AlertFrame struct {
	Code   AlertCode
	Detail []byte
}

func (a *AlertFrame) Encode() []byte {
	out := make([]byte, 0, 1+4+len(a.Detail))
	out = append(out, byte(a.Code))
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(a.Detail)))
	out = append(out, lp[:]...)
	out = append(out, a.Detail...)
	return out
}

func DecodeAlert(body []byte) (*AlertFrame, error) {
	if len(body) < 1+4 {
		return nil, fmt.Errorf("%w: ALERT too short %d", ErrDecodeError, len(body))
	}
	a := &AlertFrame{Code: AlertCode(body[0])}
	detailLen := binary.BigEndian.Uint32(body[1:5])
	if int(detailLen) != len(body)-5 {
		return nil, fmt.Errorf("%w: ALERT detail length mismatch", ErrDecodeError)
	}
	a.Detail = append([]byte(nil), body[5:]...)
	return a, nil
}

// ---------- HELLO_PSK (§6.8) ----------

type HelloPSKFrame struct {
	Suite        SuiteID
	PQMode       PQMode
	ClientRandom [ClientRandLen]byte
	TimestampNS  uint64
	PSKID        [PSKIDLen]byte
	X25519EphPub [X25519PubLen]byte
}

func (h *HelloPSKFrame) Encode() []byte {
	out := make([]byte, 0, 1+1+ClientRandLen+TimestampLen+PSKIDLen+X25519PubLen)
	out = append(out, byte(h.Suite))
	out = append(out, byte(h.PQMode))
	out = append(out, h.ClientRandom[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], h.TimestampNS)
	out = append(out, ts[:]...)
	out = append(out, h.PSKID[:]...)
	out = append(out, h.X25519EphPub[:]...)
	return out
}

func DecodeHelloPSK(body []byte) (*HelloPSKFrame, error) {
	want := 1 + 1 + ClientRandLen + TimestampLen + PSKIDLen + X25519PubLen
	if len(body) != want {
		return nil, fmt.Errorf("%w: HELLO_PSK length %d, want %d",
			ErrDecodeError, len(body), want)
	}
	h := &HelloPSKFrame{
		Suite:  SuiteID(body[0]),
		PQMode: PQMode(body[1]),
	}
	off := 2
	copy(h.ClientRandom[:], body[off:off+ClientRandLen])
	off += ClientRandLen
	h.TimestampNS = binary.BigEndian.Uint64(body[off : off+TimestampLen])
	off += TimestampLen
	copy(h.PSKID[:], body[off:off+PSKIDLen])
	off += PSKIDLen
	copy(h.X25519EphPub[:], body[off:off+X25519PubLen])
	return h, nil
}

// ---------- Outer envelope (§5) ----------

// writeFrame emits `type ∥ length ∥ body` as a SINGLE w.Write call.
//
// One Write per frame is the only way to guarantee frame atomicity at
// the io.Writer boundary: Session.Send (holding sendMu) and the
// Recv-path's writeAlertFor (holding recvMu) target the same conn but
// hold different mutexes. If writeFrame issued separate header and
// body writes, a concurrent ALERT mid-Send would interleave on the
// wire (DATA header → ALERT header → DATA body → ALERT body) and the
// peer would see a mangled stream. Assembling into one buffer makes
// the atomicity property hold without a cross-direction wire mutex.
//
// The assembly buffer is drawn from a pool to avoid per-call
// allocation on hot Send paths. Buffers are bucketed by power-of-two
// size up to MaxFrameBody so the pool stays bounded.
func writeFrame(w io.Writer, t FrameType, body []byte) error {
	if len(body) > MaxFrameBody {
		return fmt.Errorf("%w: frame body %d exceeds %d", ErrDecodeError, len(body), MaxFrameBody)
	}
	total := 5 + len(body)
	bufP := getFrameBuf(total)
	defer putFrameBuf(bufP, total)
	buf := (*bufP)[:total]
	buf[0] = byte(t)
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(body)))
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}

// frameBufPools holds power-of-two-sized writeFrame buffers.
// Index i covers bodies whose `5+len(body)` fits in 2^(i+5) bytes
// (i.e. starting at 32 bytes for short frames up to MaxFrameBody).
//
// We use *[]byte rather than []byte so the pool's Put avoids the
// allocation noted in https://staticcheck.dev/docs/checks#SA6002.
var frameBufPools [24]sync.Pool

func init() {
	for i := range frameBufPools {
		size := 1 << (i + 5)
		frameBufPools[i].New = func() any {
			b := make([]byte, size)
			return &b
		}
	}
}

// frameBufBucket returns the pool index whose buffer is at least
// `total` bytes. Returns -1 for total > MaxFrameBody+5.
func frameBufBucket(total int) int {
	// Smallest bucket: 32 bytes. Largest: 2^28 (>16 MiB + slop).
	for i := 0; i < len(frameBufPools); i++ {
		if total <= 1<<(i+5) {
			return i
		}
	}
	return -1
}

func getFrameBuf(total int) *[]byte {
	b := frameBufBucket(total)
	if b < 0 {
		// Frame larger than any pooled bucket — allocate fresh.
		x := make([]byte, total)
		return &x
	}
	return frameBufPools[b].Get().(*[]byte)
}

func putFrameBuf(bufP *[]byte, total int) {
	b := frameBufBucket(total)
	if b < 0 {
		return // not from pool
	}
	frameBufPools[b].Put(bufP)
}

// readFrame reads one envelope and returns (type, body).
func readFrame(r io.Reader) (FrameType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := FrameType(hdr[0])
	length := binary.BigEndian.Uint32(hdr[1:])
	if length > MaxFrameBody {
		return 0, nil, fmt.Errorf("%w: frame body %d exceeds %d", ErrDecodeError, length, MaxFrameBody)
	}
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
	}
	return t, body, nil
}

// expectFrame reads one frame and rejects it if its type does not
// match `want`. ALERT frames are translated to the matching sentinel
// error so callers see a typed error rather than the raw type byte.
func expectFrame(r io.Reader, want FrameType) ([]byte, error) {
	t, body, err := readFrame(r)
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
	if t != want {
		return nil, fmt.Errorf("%w: expected frame 0x%02x, got 0x%02x", ErrDecodeError, byte(want), byte(t))
	}
	return body, nil
}

// writeAlert emits an ALERT frame and returns the encoded sentinel
// for the supplied code. Callers typically wrap this in `return`.
func writeAlert(w io.Writer, code AlertCode, detail string) error {
	a := &AlertFrame{Code: code, Detail: []byte(detail)}
	_ = writeFrame(w, FrameAlert, a.Encode())
	return errorForAlert(code)
}

// writeAlertFor emits the appropriate ALERT frame for the supplied
// pipeline error and returns the same error so callers can chain it.
func writeAlertFor(w io.Writer, err error) error {
	if err == nil {
		return nil
	}
	code := alertForError(err)
	a := &AlertFrame{Code: code, Detail: []byte(err.Error())}
	_ = writeFrame(w, FrameAlert, a.Encode())
	return err
}
