// Package zapweb serves ZAP procedures over WebSocket so browser clients
// — which cannot open a raw TCP/QUIC socket — reach the EXACT same
// zapclient.Server procedure dispatch as native in-cluster peers.
//
// One dispatch path, two transports:
//
//   - native ZAP (TCP/QUIC), via zap.Node, for service-to-service calls
//   - zapweb (WebSocket), via this package, for browser ↔ service calls
//
// There is no REST here. The WebSocket handshake is an HTTP/1.1 Upgrade;
// everything after it is binary ZAP frames, dispatched through
// zapclient.Server.Dispatch (the same opcode routing + PeerVerifier the
// native node uses).
//
// # Wire format (one WebSocket BINARY message per call)
//
//	[ reqID  uint32 LE ]   correlation id — echoed on the reply
//	[ flag   uint32 LE ]   zap.ReqFlagReq on request, zap.ReqFlagResp on
//	                       reply, FlagErr on a dispatch-level failure
//	[ zap.Message bytes ]  the procedure message; its Flags() header
//	                       carries the procedure opcode, identical to the
//	                       native transport. On a FlagErr reply the tail
//	                       is a UTF-8 error string instead.
//
// The JS/TS client builds byte-identical frames (see zapweb/ts), so the
// browser and a Go caller speak the same protocol to the same handlers.
package zapweb

import (
	"encoding/binary"
	"net/http"

	"github.com/coder/websocket"
	zap "github.com/luxfi/zap"
	"github.com/luxfi/zap/zapclient"
)

// corrHeader is the fixed [reqID:4][flag:4] correlation prefix on every
// zapweb frame.
const corrHeader = 8

// FlagErr marks a reply whose tail is a UTF-8 error string rather than a
// ZAP message — used when Dispatch itself fails (unknown procedure,
// rejected peer, handler error). Distinct from zap.ReqFlagReq(1) /
// zap.ReqFlagResp(2).
const FlagErr uint32 = 3

// Options configure Handler.
type Options struct {
	// OriginPatterns is the WebSocket Origin allowlist (coder/websocket
	// AcceptOptions.OriginPatterns). Empty means same-origin only — set
	// the SPA hosts explicitly for cross-origin browser access.
	OriginPatterns []string
	// PeerID is the identity handed to the server's PeerVerifier for
	// browser calls. Default "zapweb". Authentication of the browser
	// principal rides in the procedure payload (bearer/JWT) or a TLS
	// client cert at the ingress, not in this field.
	PeerID string
	// MaxMessage caps a single inbound message in bytes. Default 1 MiB.
	MaxMessage int64
}

// Handler returns an http.Handler that upgrades to WebSocket and bridges
// each binary frame to srv.Dispatch. Mount it on the daemon's listener
// (e.g. at "/zap"); the same zapclient.Server already serves native ZAP
// peers, so browsers and services share one procedure registry.
func Handler(srv *zapclient.Server, opts Options) http.Handler {
	if opts.PeerID == "" {
		opts.PeerID = "zapweb"
	}
	if opts.MaxMessage == 0 {
		opts.MaxMessage = 1 << 20
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: opts.OriginPatterns,
		})
		if err != nil {
			return // Accept already wrote the failure response
		}
		defer c.CloseNow()
		c.SetReadLimit(opts.MaxMessage)

		ctx := r.Context()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return // client closed or read error — end the session
			}
			if typ != websocket.MessageBinary || len(data) < corrHeader {
				continue // ignore text frames / runt frames
			}
			reqID := binary.LittleEndian.Uint32(data[0:4])
			// data[4:8] is the request flag; only ReqFlagReq is acted on.
			msg, perr := zap.Parse(data[corrHeader:])
			if perr != nil {
				if werr := c.Write(ctx, websocket.MessageBinary, encodeErr(reqID, perr)); werr != nil {
					return
				}
				continue
			}
			resp, derr := srv.Dispatch(ctx, opts.PeerID, msg)
			var out []byte
			if derr != nil {
				out = encodeErr(reqID, derr)
			} else {
				out = encodeResp(reqID, resp)
			}
			if werr := c.Write(ctx, websocket.MessageBinary, out); werr != nil {
				return
			}
		}
	})
}

// encodeResp frames a successful reply: [reqID][ReqFlagResp][msg bytes].
// A nil resp (fire-and-forget handler) yields an empty body.
func encodeResp(reqID uint32, resp *zap.Message) []byte {
	var body []byte
	if resp != nil {
		body = resp.Bytes()
	}
	out := make([]byte, corrHeader+len(body))
	binary.LittleEndian.PutUint32(out[0:4], reqID)
	binary.LittleEndian.PutUint32(out[4:8], uint32(zap.ReqFlagResp))
	copy(out[corrHeader:], body)
	return out
}

// encodeErr frames a dispatch-level failure: [reqID][FlagErr][message].
func encodeErr(reqID uint32, err error) []byte {
	es := []byte(err.Error())
	out := make([]byte, corrHeader+len(es))
	binary.LittleEndian.PutUint32(out[0:4], reqID)
	binary.LittleEndian.PutUint32(out[4:8], FlagErr)
	copy(out[corrHeader:], es)
	return out
}
