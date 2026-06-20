// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// ALPN is the ALPN protocol identifier negotiated for every ZAP-QUIC
// connection. Servers reject TLS handshakes that propose any other ALPN.
const ALPN = "zap/1"

// MaxFrameSize bounds a single ZAP frame on a QUIC stream. Identical to
// the TCP transport's bound — 10 MiB — so the application layer sees the
// same envelope regardless of transport.
const MaxFrameSize = 10 * 1024 * 1024

// handshakeTimeout is how long we wait for the 64-byte node-identity
// handshake on the control stream before tearing down the connection.
const handshakeTimeout = 10 * time.Second

// nodeIDFrameSize is the fixed-length envelope used for the node-ID
// exchange. Mirrors the TCP transport's choice for symmetry with node.go.
const nodeIDFrameSize = 64

// Common errors.
var (
	// ErrConnClosed is returned by Send/Recv/OpenStream after the
	// underlying QUIC connection has been closed (graceful or abrupt).
	ErrConnClosed = errors.New("zap/quic: connection closed")

	// ErrFrameTooLarge is returned when reading a frame whose
	// declared length exceeds MaxFrameSize.
	ErrFrameTooLarge = errors.New("zap/quic: frame too large")

	// ErrBadHandshake is returned when the peer's identity handshake
	// is malformed or empty.
	ErrBadHandshake = errors.New("zap/quic: invalid handshake")

	// ErrBadALPN is returned when the negotiated ALPN is not "zap/1".
	// quic-go enforces ALPN at the TLS layer; this is a belt-and-suspenders
	// post-handshake check.
	ErrBadALPN = errors.New("zap/quic: unexpected ALPN")
)

// Conn is a multiplexed ZAP connection over QUIC.
//
// Conn is the transport-level connection abstraction shared between the
// dialer (client.go) and the listener (server.go). It exposes the same
// shape as ZAP's TCP *Conn (Send, Recv, Close, peer identity) and adds
// stream-level primitives that the underlying TCP transport cannot
// efficiently express.
//
// Conn is safe for concurrent use. Send serializes onto the control
// stream; concurrent callers may instead OpenStream to get independent
// per-RPC streams.
type Conn struct {
	// PeerID is the ZAP node identity asserted by the peer in the
	// identity handshake on the control stream.
	PeerID string

	// LocalAddr / RemoteAddr expose the underlying UDP 5-tuple at the
	// time the connection was created. Because QUIC supports connection
	// migration, RemoteAddr may differ from the address actually
	// observed for the most recent packet — these fields are
	// informational, not authoritative.
	LocalAddr  net.Addr
	RemoteAddr net.Addr

	qc      *quicgo.Conn
	control *quicgo.Stream // bidirectional control stream
	ctrlMu  sync.Mutex     // serializes writes on `control`

	closed atomic.Bool
}

// newConnFromQUIC wraps an already-established *quic.Conn. The dialer
// and the listener share this entry point so that all post-handshake
// state lives in one struct.
func newConnFromQUIC(qc *quicgo.Conn, control *quicgo.Stream, peerID string) *Conn {
	return &Conn{
		PeerID:     peerID,
		LocalAddr:  qc.LocalAddr(),
		RemoteAddr: qc.RemoteAddr(),
		qc:         qc,
		control:    control,
	}
}

// QUIC returns the underlying *quic.Conn. Exposed for advanced callers
// (e.g. tests that need to inspect ConnectionState or trigger a
// migration). Most consumers should not touch this.
func (c *Conn) QUIC() *quicgo.Conn { return c.qc }

// ConnectionState returns the TLS connection state of the underlying
// QUIC handshake. Notably, ConnectionState().CurveID reports the
// negotiated TLS NamedGroup — used by tests to assert that
// X25519MLKEM768 (0x11ec) is the actual negotiated KEM.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.qc.ConnectionState().TLS
}

// IsZeroRTT reports whether the QUIC handshake completed with 0-RTT
// early data accepted by the server. Only meaningful on the client
// side after a resumed connection.
func (c *Conn) IsZeroRTT() bool {
	return c.qc.ConnectionState().Used0RTT
}

// Send writes a ZAP frame on the control stream. This is the
// transport-API parity surface for the TCP Conn.Send: a single,
// serialized stream of frames in arrival order. For independent
// concurrent RPCs, prefer OpenStream.
func (c *Conn) Send(frame []byte) error {
	if c.closed.Load() {
		return ErrConnClosed
	}
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	return writeFrame(c.control, frame)
}

// Recv reads the next ZAP frame from the control stream. Frames are
// read in the same order they were sent.
func (c *Conn) Recv() ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	return readFrame(c.control)
}

// OpenStream opens a new bidirectional QUIC stream for an independent
// request/response exchange. The returned Stream wraps QUIC-level
// flow control so the caller cannot overrun the peer.
//
// The typical RPC pattern is:
//
//	s, err := conn.OpenStream(ctx)
//	if err != nil { return err }
//	defer s.Close()
//	s.WriteFrame(reqBytes)   // sends one ZAP frame
//	respBytes, err := s.ReadFrame()
//
// After Close, the stream ID is freed and may be reused.
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: open stream: %w", err)
	}
	return &Stream{s: s}, nil
}

// AcceptStream blocks until the peer opens a new bidirectional QUIC
// stream. Used by the server to serve per-RPC streams from the client.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{s: s}, nil
}

// OpenUniStream opens a unidirectional send stream, used for
// fire-and-forget subscription deliveries and broadcasts where the
// peer never replies.
func (c *Conn) OpenUniStream(ctx context.Context) (*UniStream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	s, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("zap/quic: open uni stream: %w", err)
	}
	return &UniStream{s: s}, nil
}

// AcceptUniStream blocks until the peer opens a unidirectional QUIC
// stream addressed to this side.
func (c *Conn) AcceptUniStream(ctx context.Context) (*UniReceiveStream, error) {
	if c.closed.Load() {
		return nil, ErrConnClosed
	}
	s, err := c.qc.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return &UniReceiveStream{s: s}, nil
}

// Close initiates a graceful close of the QUIC connection.
//
// Graceful close protocol:
//  1. CloseWrite() on the control stream so the peer's Recv loop
//     observes io.EOF after draining all in-flight frames.
//  2. Wait up to drainTimeout for the peer's control stream to
//     deliver its own EOF (the symmetric DRAIN signal).
//  3. CloseWithError(0, "") on the underlying *quic.Conn, which
//     emits a QUIC CONNECTION_CLOSE frame with error code 0.
//
// This is the ALPN-coordinated DRAIN sequence the mission spec calls
// for: in-flight frames are flushed before connection close.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Step 1: half-close control stream (signal DRAIN).
	_ = c.control.Close()
	// Step 2: best-effort drain wait. We bound it so we don't hang
	// on a misbehaving peer.
	drainTimeout := 200 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, c.control)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
	}
	// Step 3: cleanly tear down the QUIC connection.
	return c.qc.CloseWithError(0, "")
}

// Context returns the underlying connection's context, which is
// canceled when the connection terminates (either side).
func (c *Conn) Context() context.Context {
	return c.qc.Context()
}

// Stream is a bidirectional QUIC stream carrying ZAP frames.
type Stream struct {
	s *quicgo.Stream
}

// WriteFrame writes one length-prefixed ZAP frame to the stream.
func (s *Stream) WriteFrame(frame []byte) error {
	return writeFrame(s.s, frame)
}

// ReadFrame reads one length-prefixed ZAP frame from the stream.
func (s *Stream) ReadFrame() ([]byte, error) {
	return readFrame(s.s)
}

// Close shuts both directions of the stream.
func (s *Stream) Close() error {
	return s.s.Close()
}

// CloseWrite finishes the local write side. The peer will see
// io.EOF on subsequent ReadFrame calls after all queued data is
// delivered.
func (s *Stream) CloseWrite() error {
	return s.s.Close()
}

// UniStream is a unidirectional send-only QUIC stream.
type UniStream struct {
	s *quicgo.SendStream
}

// WriteFrame writes one ZAP frame to the unidirectional stream.
func (u *UniStream) WriteFrame(frame []byte) error {
	return writeFrame(u.s, frame)
}

// Close finishes the stream. The receiver sees io.EOF after the
// last frame is delivered.
func (u *UniStream) Close() error {
	return u.s.Close()
}

// UniReceiveStream is a unidirectional receive-only QUIC stream.
type UniReceiveStream struct {
	s *quicgo.ReceiveStream
}

// ReadFrame reads the next ZAP frame from the stream.
func (u *UniReceiveStream) ReadFrame() ([]byte, error) {
	return readFrame(u.s)
}

// writeFrame writes one length-prefixed ZAP frame.
//
// Wire format: [4-byte little-endian length][frame bytes].
// Identical to ZAP's TCP transport.
func writeFrame(w io.Writer, frame []byte) error {
	if uint64(len(frame)) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(frame) == 0 {
		return nil
	}
	_, err := w.Write(frame)
	return err
}

// readFrame reads the next length-prefixed ZAP frame.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if uint64(n) > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// performServerHandshake reads the client's node-ID then writes the
// server's. Returns the client's asserted node identity.
func performServerHandshake(ctx context.Context, ctrl *quicgo.Stream, localID string) (string, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	_ = ctrl.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_ = ctrl.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	defer func() {
		_ = ctrl.SetReadDeadline(time.Time{})
		_ = ctrl.SetWriteDeadline(time.Time{})
	}()

	type result struct {
		peerID string
		err    error
	}
	out := make(chan result, 1)
	go func() {
		peerID, err := readHandshake(ctrl)
		if err == nil {
			err = writeHandshake(ctrl, localID)
		}
		out <- result{peerID, err}
	}()
	select {
	case r := <-out:
		return r.peerID, r.err
	case <-deadlineCtx.Done():
		return "", deadlineCtx.Err()
	}
}

// performClientHandshake writes our node-ID then reads the server's.
func performClientHandshake(ctx context.Context, ctrl *quicgo.Stream, localID string) (string, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	_ = ctrl.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_ = ctrl.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	defer func() {
		_ = ctrl.SetReadDeadline(time.Time{})
		_ = ctrl.SetWriteDeadline(time.Time{})
	}()

	type result struct {
		peerID string
		err    error
	}
	out := make(chan result, 1)
	go func() {
		if err := writeHandshake(ctrl, localID); err != nil {
			out <- result{"", err}
			return
		}
		peerID, err := readHandshake(ctrl)
		out <- result{peerID, err}
	}()
	select {
	case r := <-out:
		return r.peerID, r.err
	case <-deadlineCtx.Done():
		return "", deadlineCtx.Err()
	}
}

// writeHandshake writes a fixed-size 64-byte identity frame: the first
// N bytes are the node-ID UTF-8, the trailing 4 bytes encode the length.
// This mirrors node.go's TCP handshake exactly.
func writeHandshake(w io.Writer, nodeID string) error {
	var buf [nodeIDFrameSize]byte
	idBytes := []byte(nodeID)
	n := len(idBytes)
	if n > nodeIDFrameSize-4 {
		n = nodeIDFrameSize - 4
	}
	copy(buf[:n], idBytes[:n])
	binary.LittleEndian.PutUint32(buf[nodeIDFrameSize-4:], uint32(n))
	// Wrap in framed write so the receiver can decode without
	// special-casing handshake parsing.
	return writeFrame(w, buf[:])
}

// readHandshake reads and decodes a 64-byte identity frame.
func readHandshake(r io.Reader) (string, error) {
	frame, err := readFrame(r)
	if err != nil {
		return "", err
	}
	if len(frame) != nodeIDFrameSize {
		return "", ErrBadHandshake
	}
	n := binary.LittleEndian.Uint32(frame[nodeIDFrameSize-4:])
	if n == 0 || n > nodeIDFrameSize-4 {
		return "", ErrBadHandshake
	}
	return string(frame[:n]), nil
}
