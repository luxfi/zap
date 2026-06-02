// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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

// serveTransportConn is the QUIC equivalent of handleConn — it
// drives the read loop and dispatches incoming frames to handlers.
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
		n.dispatchFrame(peerID, data, tc)
	}
}

// dispatchFrame routes a single ZAP frame to either the pending-Call
// channel (if it has a response correlation header) or to the
// registered handler. Mirrors the TCP path in node.go's handleConn.
func (n *Node) dispatchFrame(peerID string, data []byte, tc TransportConn) {
	if len(data) >= 8 {
		reqFlag := binary.LittleEndian.Uint32(data[4:8])
		if reqFlag == ReqFlagResp {
			reqID := binary.LittleEndian.Uint32(data[0:4])
			msg, err := Parse(data[8:])
			if err == nil {
				n.routeQUICResponse(peerID, reqID, msg)
			}
			return
		}
		if reqFlag == ReqFlagReq {
			reqID := binary.LittleEndian.Uint32(data[0:4])
			msg, err := Parse(data[8:])
			if err != nil {
				return
			}
			n.handleQUICRequest(peerID, tc, reqID, msg)
			return
		}
	}

	// Regular one-way message.
	msg, err := Parse(data)
	if err != nil {
		return
	}
	n.invokeHandlerOneWay(peerID, msg)
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
	_, _ = handler(n.ctx, peerID, msg)
}

// handleQUICRequest dispatches a Call request and writes back the
// correlation-tagged response on the same transport conn.
func (n *Node) handleQUICRequest(peerID string, tc TransportConn, reqID uint32, msg *Message) {
	msgType := msg.Flags() >> 8
	n.handlersMu.RLock()
	handler, ok := n.handlers[msgType]
	n.handlersMu.RUnlock()
	if !ok {
		return
	}
	resp, err := handler(n.ctx, peerID, msg)
	if err != nil {
		n.logger.Error("Handler error", "peerID", peerID, "msgType", msgType, "error", err)
		return
	}
	if resp == nil {
		return
	}
	respBytes := resp.Bytes()
	wrapped := make([]byte, len(respBytes)+8)
	binary.LittleEndian.PutUint32(wrapped[0:4], reqID)
	binary.LittleEndian.PutUint32(wrapped[4:8], ReqFlagResp)
	copy(wrapped[8:], respBytes)
	if err := tc.Send(wrapped); err != nil {
		n.logger.Debug("QUIC Send error", "peerID", peerID, "error", err)
	}
}

// quicPendingMu / quicPending hold the per-peer pending Call response
// channels for the QUIC transport. We keep them on the Node (not on
// each TransportConn) because TransportConn is an interface and we
// don't want to require implementors to carry the pending map.
var (
	quicPendingMu sync.Mutex
	quicPending   = map[string]map[uint32]chan *Message{}
)

func (n *Node) routeQUICResponse(peerID string, reqID uint32, msg *Message) {
	quicPendingMu.Lock()
	defer quicPendingMu.Unlock()
	if peerMap, ok := quicPending[n.nodeID+":"+peerID]; ok {
		if ch, ok := peerMap[reqID]; ok {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

// quicCall is the QUIC path for Node.Call.
func (n *Node) quicCall(ctx context.Context, peerID string, msg *Message) (*Message, error) {
	tc, err := n.getOrConnectQUIC(ctx, peerID)
	if err != nil {
		return nil, err
	}

	reqID := nextReqID(n)

	respCh := make(chan *Message, 1)
	key := n.nodeID + ":" + peerID
	quicPendingMu.Lock()
	if quicPending[key] == nil {
		quicPending[key] = make(map[uint32]chan *Message)
	}
	quicPending[key][reqID] = respCh
	quicPendingMu.Unlock()

	defer func() {
		quicPendingMu.Lock()
		delete(quicPending[key], reqID)
		quicPendingMu.Unlock()
	}()

	orig := msg.Bytes()
	wrapped := make([]byte, len(orig)+8)
	binary.LittleEndian.PutUint32(wrapped[0:4], reqID)
	binary.LittleEndian.PutUint32(wrapped[4:8], ReqFlagReq)
	copy(wrapped[8:], orig)

	if err := tc.Send(wrapped); err != nil {
		return nil, err
	}

	select {
	case resp := <-respCh:
		return resp, nil
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

// nextReqID returns the next request ID for a QUIC peer. We piggy-
// back on the existing Conn.reqID counter pattern but use a per-node
// global because the TransportConn interface is opaque about its own
// state. Atomicity is provided by the Node struct's reqIDMu.
func nextReqID(n *Node) uint32 {
	n.reqIDQuicMu.Lock()
	defer n.reqIDQuicMu.Unlock()
	n.reqIDQuic++
	return n.reqIDQuic
}
