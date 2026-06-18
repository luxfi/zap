// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/luxfi/mdns"
)

// startQUIC bootstraps the QUIC transport path. It is the
// Transport == TransportQUIC fork of (*Node).Start.
//
// All higher-level APIs (Handle, Send, Call, Broadcast, ConnectDirect)
// continue to work — they look at n.transport to route to either the
// TCP code path (existing in node.go) or the QUIC dispatch below.
func (n *Node) startQUIC() error {
	f, err := lookupTransport(TransportQUIC)
	if err != nil {
		return err
	}
	n.transportFact = f

	addr, closer, err := f.Listen(n.ctx, n.cfg, n.onAcceptedTransportConn)
	if err != nil {
		return fmt.Errorf("zap: start QUIC listener: %w", err)
	}
	n.transClose = closer

	// Discover the kernel-assigned port if cfg.Port was 0, and feed
	// the real port to mDNS.
	port := n.port
	if port == 0 {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			fmt.Sscanf(p, "%d", &port)
			n.port = port
		}
	}

	if !n.noDiscovery {
		n.discovery = mdns.New(n.serviceType, n.nodeID, n.port,
			mdns.WithLogger(n.logger),
		)
		n.discovery.OnPeer(n.handlePeerEvent)
		if err := n.discovery.Start(); err != nil {
			_ = n.transClose()
			return fmt.Errorf("zap: start discovery: %w", err)
		}
	}

	n.logger.Info("ZAP node started (QUIC)",
		"nodeID", n.nodeID,
		"service", n.serviceType,
		"port", n.port,
		"addr", addr,
	)
	return nil
}

// onAcceptedTransportConn is the callback registered with the
// TransportFactory. Each accepted post-handshake QUIC connection
// arrives here.
func (n *Node) onAcceptedTransportConn(peerID string, tc TransportConn) {
	if peerID == "" {
		_ = tc.Close()
		return
	}

	// De-dupe: the lower-NodeID side is meant to initiate, so if we
	// already have a conn for this peer, drop the late arrival.
	n.connsMu.Lock()
	if _, ok := n.transports[peerID]; ok {
		n.connsMu.Unlock()
		_ = tc.Close()
		return
	}
	n.transports[peerID] = tc
	n.connsMu.Unlock()

	n.logger.Info("Peer connected (QUIC)", "peerID", peerID, "addr", tc.RemoteAddr())

	n.wg.Add(1)
	go n.serveTransportConn(peerID, tc)
}

// serveTransportConn drives the read loops on a QUIC peer connection.
//
// Two parallel read loops run on each connection:
//
//  1. Control-stream loop (tc.Recv): handles one-way Sends only.
//  2. Per-Call stream accept loop (AcceptCallStream): handles every
//     Call. Each accepted stream carries exactly one request + one
//     response, so the dispatch goroutine reads, handles, writes,
//     and closes the stream in one shot.
//
// The two loops are independent: each runs in its own goroutine, and
// both terminate when the connection closes or n.ctx is cancelled.
//
// The QUIC transport always implements TransportStreamer; if a
// connection somehow lacks it we close it — the per-stream Call path
// is the only Call path.
func (n *Node) serveTransportConn(peerID string, tc TransportConn) {
	defer n.wg.Done()
	defer func() {
		n.connsMu.Lock()
		if cur, ok := n.transports[peerID]; ok && cur == tc {
			delete(n.transports, peerID)
		}
		n.connsMu.Unlock()
		_ = tc.Close()
		n.logger.Info("Peer disconnected (QUIC)", "peerID", peerID)
	}()

	streamer, ok := tc.(TransportStreamer)
	if !ok {
		n.logger.Error("QUIC TransportConn missing TransportStreamer", "peerID", peerID)
		return
	}
	n.wg.Add(1)
	go n.acceptCallStreams(peerID, streamer)

	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		data, err := tc.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			// Distinguish transient timeouts from terminal errors:
			// the quic.Conn's Recv blocks until a frame arrives, so
			// a non-EOF error here is terminal.
			n.logger.Debug("QUIC Recv error", "peerID", peerID, "error", err)
			return
		}
		// Control stream carries one-way Sends only. Calls ride
		// per-Call streams.
		msg, err := Parse(data)
		if err != nil {
			continue
		}
		n.invokeHandlerOneWay(peerID, msg)
	}
}

// acceptCallStreams runs in its own goroutine for each QUIC peer and
// processes inbound per-Call streams. Each stream gets its own handler
// goroutine so multiple in-flight Calls from the same peer execute
// concurrently — the headline parallelism win.
//
// Termination: AcceptCallStream returns a non-nil err when the
// connection is torn down. The loop exits without logging — the
// peer-disconnected line is already emitted by serveTransportConn's
// deferred close.
func (n *Node) acceptCallStreams(peerID string, s TransportStreamer) {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}
		stream, err := s.AcceptCallStream(n.ctx)
		if err != nil {
			return
		}
		n.wg.Add(1)
		go n.handleCallStream(peerID, stream)
	}
}

// handleCallStream serves exactly one inbound per-Call stream:
// read one frame as the request, run the registered handler, and
// write the response back on the same stream. The stream is closed
// when this function returns.
func (n *Node) handleCallStream(peerID string, stream TransportStream) {
	defer n.wg.Done()
	defer stream.Close()

	reqBytes, err := stream.ReadFrame()
	if err != nil {
		return
	}
	msg, err := Parse(reqBytes)
	if err != nil {
		return
	}

	msgType := msg.Flags() >> 8
	n.handlersMu.RLock()
	handler, ok := n.handlers[msgType]
	n.handlersMu.RUnlock()
	if !ok {
		return
	}

	// Guarded: a handler panic on the QUIC per-Call stream must not crash
	// the node any more than on the TCP path. safeHandle recovers, logs,
	// and converts the panic to an error; the stream is then closed.
	resp, herr := n.safeHandle(handler, peerID, msgType, msg)
	if herr != nil {
		n.logger.Error("Handler error (stream)", "peerID", peerID, "msgType", msgType, "error", herr)
		return
	}
	if resp == nil {
		return
	}
	if err := stream.WriteFrame(resp.Bytes()); err != nil {
		n.logger.Debug("QUIC stream write error", "peerID", peerID, "error", err)
	}
}

// invokeHandlerOneWay runs the registered handler and discards the
// response (matches TCP one-way semantics).
func (n *Node) invokeHandlerOneWay(peerID string, msg *Message) {
	msgType := msg.Flags() >> 8
	n.handlersMu.RLock()
	handler, ok := n.handlers[msgType]
	n.handlersMu.RUnlock()
	if !ok {
		return
	}
	// Guarded: same recover boundary as every other dispatch path so a
	// panicking one-way handler cannot kill the node.
	_, _ = n.safeHandle(handler, peerID, msgType, msg)
}

// quicCall is the QUIC path for Node.Call.
//
// Every Call gets its own fresh bidirectional QUIC stream. The
// request goes out on the new stream, the response comes back on the
// same stream, and the stream is torn down. Concurrent Calls run in
// parallel up to the peer-advertised stream limit (1024 for ZAP's
// QUIC config) — no shared write mutex, no correlation header.
//
// QUIC's TransportConn always implements TransportStreamer; if it
// somehow does not, that is a programmer error and we surface it.
func (n *Node) quicCall(ctx context.Context, peerID string, msg *Message) (*Message, error) {
	tc, err := n.getOrConnectQUIC(ctx, peerID)
	if err != nil {
		return nil, err
	}
	streamer, ok := tc.(TransportStreamer)
	if !ok {
		return nil, fmt.Errorf("zap: QUIC TransportConn for %s missing TransportStreamer", peerID)
	}
	return n.quicCallStream(ctx, streamer, msg)
}

// quicCallStream runs one Call on a fresh per-Call QUIC stream.
//
// The stream lifecycle is:
//  1. OpenCallStream — server peer's AcceptCallStream wakes.
//  2. WriteFrame(req) — single length-prefixed ZAP frame.
//  3. ReadFrame()      — single length-prefixed ZAP frame (response).
//  4. Close            — stream ID returns to the QUIC pool.
//
// No correlation header is needed on the wire: each stream carries
// exactly one request + one response. The response payload is the raw
// ZAP frame; we Parse it directly.
//
// Each stream gets cancelled if ctx fires before the response
// arrives; the QUIC layer will surface ErrStreamCanceled into
// ReadFrame so the goroutine exits cleanly.
func (n *Node) quicCallStream(ctx context.Context, s TransportStreamer, msg *Message) (*Message, error) {
	stream, err := s.OpenCallStream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if err := stream.WriteFrame(msg.Bytes()); err != nil {
		return nil, err
	}

	// Read response on this stream. The QUIC layer respects the
	// stream's own deadline; we set one from ctx so a cancelled
	// context tears the read down.
	type result struct {
		resp []byte
		err  error
	}
	out := make(chan result, 1)
	go func() {
		resp, err := stream.ReadFrame()
		out <- result{resp, err}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			return nil, r.err
		}
		return Parse(r.resp)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// quicSend is the QUIC path for Node.Send (one-way).
func (n *Node) quicSend(ctx context.Context, peerID string, msg *Message) error {
	tc, err := n.getOrConnectQUIC(ctx, peerID)
	if err != nil {
		return err
	}
	return tc.Send(msg.Bytes())
}

// quicConnectDirect opens a QUIC connection to addr (bypassing mDNS),
// performs the identity handshake, and starts the receive loop.
func (n *Node) quicConnectDirect(ctx context.Context, addr string) error {
	if n.transportFact == nil {
		return ErrTransportUnavailable
	}
	peerID, tc, err := n.transportFact.Dial(ctx, n.cfg, addr)
	if err != nil {
		return err
	}
	n.connsMu.Lock()
	if _, ok := n.transports[peerID]; ok {
		n.connsMu.Unlock()
		_ = tc.Close()
		return nil
	}
	n.transports[peerID] = tc
	n.connsMu.Unlock()
	n.logger.Info("Connected to peer (QUIC)", "peerID", peerID, "addr", addr)
	n.wg.Add(1)
	go n.serveTransportConn(peerID, tc)
	return nil
}

// getOrConnectQUIC returns the cached TransportConn for peerID or
// dials a new one via discovery lookup.
func (n *Node) getOrConnectQUIC(ctx context.Context, peerID string) (TransportConn, error) {
	n.connsMu.RLock()
	tc, ok := n.transports[peerID]
	n.connsMu.RUnlock()
	if ok {
		return tc, nil
	}
	if n.discovery == nil {
		return nil, fmt.Errorf("peer not found and discovery disabled: %s", peerID)
	}
	peers := n.discovery.Peers()
	var peer *mdns.Peer
	for _, p := range peers {
		if p.NodeID == peerID {
			peer = p
			break
		}
	}
	if peer == nil {
		return nil, fmt.Errorf("peer not found: %s", peerID)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialedID, newTC, err := n.transportFact.Dial(dialCtx, n.cfg, peer.Address())
	if err != nil {
		return nil, err
	}
	if dialedID != peerID {
		_ = newTC.Close()
		return nil, fmt.Errorf("peer ID mismatch: expected %s, got %s", peerID, dialedID)
	}
	n.connsMu.Lock()
	if existing, ok := n.transports[peerID]; ok {
		n.connsMu.Unlock()
		_ = newTC.Close()
		return existing, nil
	}
	n.transports[peerID] = newTC
	n.connsMu.Unlock()
	n.wg.Add(1)
	go n.serveTransportConn(peerID, newTC)
	return newTC, nil
}
