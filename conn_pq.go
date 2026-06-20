// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/luxfi/zap/handshake"
)

// WrapPQ wraps an established net.Conn with ZAP-PQ-v1 AEAD framing
// after a completed handshake. The returned net.Conn implements
// stream Read/Write on top of the record-oriented Session — one
// Write becomes one DATA frame (chunked at MaxRecord), reads buffer
// across frames so callers see the byte stream they expect.
//
// Close closes the Session (which zeros the keys and closes the
// underlying TCP conn). LocalAddr / RemoteAddr / SetDeadline*
// delegate to the wrapped conn.
//
// Drop-in usage:
//
//	tcp, _ := net.Dial("tcp", "...")
//	sess, _ := (&handshake.Initiator{Local: id}).Run(tcp)
//	pq := zap.WrapPQ(tcp, sess)
//	// use pq as any net.Conn from here on
func WrapPQ(conn net.Conn, sess *handshake.Session) net.Conn {
	return &pqConn{conn: conn, sess: sess}
}

// MaxPQRecord is the largest plaintext payload one Write turns into
// a single DATA frame. Writes larger than this are chunked. Sized
// well below the §5 16-MiB hard cap so the AEAD tag + frame envelope
// always fit.
const MaxPQRecord = 64 * 1024

type pqConn struct {
	conn net.Conn
	sess *handshake.Session

	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex
}

func (c *pqConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		plain, err := c.sess.Recv()
		if err != nil {
			return 0, err
		}
		c.readBuf = plain
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *pqConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPQRecord {
			chunk = chunk[:MaxPQRecord]
		}
		if err := c.sess.Send(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *pqConn) Close() error {
	// Session.Close already closes the underlying conn via the
	// captured io.Closer — calling c.conn.Close again here would
	// return "use of closed network connection" on a perfectly
	// healthy double-close path. Trust the Session.
	return c.sess.Close()
}

func (c *pqConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *pqConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *pqConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *pqConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *pqConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// PeerID exposes the verified peer identity for callers that need to
// route on it (e.g. validator-set membership checks).
func (c *pqConn) PeerID() [32]byte { return c.sess.PeerID() }

// ErrNotPQConn is returned by AsPQConn when the caller passes a
// net.Conn that is not a *pqConn (e.g. a legacy TCP conn).
var ErrNotPQConn = errors.New("zap: not a ZAP-PQ connection")

// AsPQConn type-asserts an interface{} into a ZAP-PQ wrapper so
// callers can fetch PeerID without import cycles.
func AsPQConn(c net.Conn) (*pqConn, error) {
	p, ok := c.(*pqConn)
	if !ok {
		return nil, ErrNotPQConn
	}
	return p, nil
}
