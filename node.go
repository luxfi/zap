// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/luxfi/mdns"
)

// Node is a ZAP node that combines mDNS discovery with zero-copy RPC.
type Node struct {
	nodeID      string
	serviceType string
	port        int
	noDiscovery bool
	tlsCfg      *tls.Config // nil = plaintext

	// Transport selection (cached from NodeConfig.Transport at
	// construction). Default = TransportTCP for back-compat.
	transport     Transport
	transportFact TransportFactory // resolved only when transport != TCP
	cfg           NodeConfig       // verbatim copy for transport handlers

	// Discovery
	discovery *mdns.Discovery

	// Network
	listener    net.Listener
	transports  map[string]TransportConn // peerID -> transport conn (QUIC path)
	transClose  func() error             // closer for the QUIC listener
	reqIDQuic   uint32                   // QUIC-path request-ID counter
	reqIDQuicMu sync.Mutex
	conns       map[string]*Conn
	connsMu     sync.RWMutex

	// Handlers
	handlers   map[uint16]Handler
	handlersMu sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger
}

// Conn is a ZAP connection to a peer.
type Conn struct {
	NodeID string
	Addr   string
	conn   net.Conn
	mu     sync.Mutex

	// Request/response correlation
	reqID   uint32
	reqIDMu sync.Mutex
	pending map[uint32]chan *Message
	pendMu  sync.Mutex
}

// Handler handles incoming ZAP messages.
type Handler func(ctx context.Context, from string, msg *Message) (*Message, error)

// NodeConfig configures a ZAP node.
type NodeConfig struct {
	NodeID      string
	ServiceType string // e.g., "_luxd._tcp", "_fhed._tcp"
	Port        int
	Metadata    map[string]string
	Logger      *slog.Logger
	NoDiscovery bool        // Disable mDNS discovery (use ConnectDirect only)
	TLS         *tls.Config // optional PQ-TLS 1.3; nil = plaintext

	// Transport selects the network transport: TransportTCP (default,
	// preserves back-compat) or TransportQUIC. TransportQUIC requires
	// `import _ "github.com/luxfi/zap/quic"` somewhere in the binary.
	Transport Transport

	// QUICConfig, if non-nil, is passed to the QUIC transport as a
	// *quic.Config (github.com/quic-go/quic-go). Ignored for
	// TransportTCP. Typed as any here to avoid pulling quic-go into
	// the parent package's import graph.
	QUICConfig any
}

// NewNode creates a new ZAP node.
func NewNode(cfg NodeConfig) *Node {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &Node{
		nodeID:      cfg.NodeID,
		serviceType: cfg.ServiceType,
		port:        cfg.Port,
		noDiscovery: cfg.NoDiscovery,
		tlsCfg:      cfg.TLS,
		transport:   cfg.Transport,
		cfg:         cfg,
		conns:       make(map[string]*Conn),
		transports:  make(map[string]TransportConn),
		handlers:    make(map[uint16]Handler),
		ctx:         ctx,
		cancel:      cancel,
		logger:      cfg.Logger,
	}
}

// Start starts the node (discovery + listener).
func (n *Node) Start() error {
	if n.transport == TransportQUIC {
		return n.startQUIC()
	}
	// Start TCP listener
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", n.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	if n.tlsCfg != nil {
		ln = tls.NewListener(ln, n.tlsCfg)
	}
	n.listener = ln

	// Accept connections
	n.wg.Add(1)
	go n.acceptLoop()

	// Start mDNS discovery (unless disabled)
	if !n.noDiscovery {
		n.discovery = mdns.New(n.serviceType, n.nodeID, n.port,
			mdns.WithLogger(n.logger),
		)

		n.discovery.OnPeer(n.handlePeerEvent)

		if err := n.discovery.Start(); err != nil {
			n.listener.Close()
			return fmt.Errorf("failed to start discovery: %w", err)
		}
	}

	n.logger.Info("ZAP node started",
		"nodeID", n.nodeID,
		"service", n.serviceType,
		"port", n.port,
	)

	return nil
}

// Stop stops the node.
func (n *Node) Stop() {
	n.cancel()

	if n.discovery != nil {
		n.discovery.Stop()
	}

	if n.listener != nil {
		n.listener.Close()
	}
	if n.transClose != nil {
		_ = n.transClose()
	}

	// Close all connections
	n.connsMu.Lock()
	for _, conn := range n.conns {
		conn.conn.Close()
	}
	for _, tc := range n.transports {
		_ = tc.Close()
	}
	n.conns = make(map[string]*Conn)
	n.transports = make(map[string]TransportConn)
	n.connsMu.Unlock()

	n.wg.Wait()
	n.logger.Info("ZAP node stopped", "nodeID", n.nodeID)
}

// Handle registers a handler for a message type.
func (n *Node) Handle(msgType uint16, handler Handler) {
	n.handlersMu.Lock()
	n.handlers[msgType] = handler
	n.handlersMu.Unlock()
}

// Send sends a ZAP message to a peer.
func (n *Node) Send(ctx context.Context, peerID string, msg *Message) error {
	if n.transport == TransportQUIC {
		return n.quicSend(ctx, peerID, msg)
	}
	conn, err := n.getOrConnect(peerID)
	if err != nil {
		return err
	}
	return conn.Send(msg)
}

// Reserved header fields for request/response correlation
// These are the first 8 bytes of every Call message
const (
	FieldReqID   = 0 // uint32 - request ID for correlation
	FieldReqFlag = 4 // uint32 - 1=request, 2=response
	ReqFlagReq   = 1
	ReqFlagResp  = 2
)

// Call sends a request and waits for a response.
func (n *Node) Call(ctx context.Context, peerID string, msg *Message) (*Message, error) {
	if n.transport == TransportQUIC {
		return n.quicCall(ctx, peerID, msg)
	}
	conn, err := n.getOrConnect(peerID)
	if err != nil {
		return nil, err
	}

	// Initialize pending map if needed
	conn.pendMu.Lock()
	if conn.pending == nil {
		conn.pending = make(map[uint32]chan *Message)
	}
	conn.pendMu.Unlock()

	// Get next request ID
	conn.reqIDMu.Lock()
	conn.reqID++
	reqID := conn.reqID
	conn.reqIDMu.Unlock()

	// Create response channel
	respCh := make(chan *Message, 1)
	conn.pendMu.Lock()
	conn.pending[reqID] = respCh
	conn.pendMu.Unlock()

	defer func() {
		conn.pendMu.Lock()
		delete(conn.pending, reqID)
		conn.pendMu.Unlock()
	}()

	// Send wrapped request (one canonical encoder via WrapCorrelated).
	conn.mu.Lock()
	err = writeMessage(conn.conn, WrapCorrelated(reqID, ReqFlagReq, msg.Bytes()))
	conn.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case resp := <-respCh:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Broadcast sends a message to all connected peers.
func (n *Node) Broadcast(ctx context.Context, msg *Message) map[string]error {
	n.connsMu.RLock()
	peers := make([]string, 0, len(n.conns))
	for id := range n.conns {
		peers = append(peers, id)
	}
	n.connsMu.RUnlock()

	results := make(map[string]error)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, peerID := range peers {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			err := n.Send(ctx, id, msg)
			mu.Lock()
			results[id] = err
			mu.Unlock()
		}(peerID)
	}

	wg.Wait()
	return results
}

// Peers returns connected peer IDs.
func (n *Node) Peers() []string {
	n.connsMu.RLock()
	defer n.connsMu.RUnlock()

	peers := make([]string, 0, len(n.conns))
	for id := range n.conns {
		peers = append(peers, id)
	}
	return peers
}

// NodeID returns this node's ID.
func (n *Node) NodeID() string {
	return n.nodeID
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()

	for {
		conn, err := n.listener.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
				n.logger.Error("Accept error", "error", err)
				continue
			}
		}

		n.wg.Add(1)
		go n.handleConn(conn)
	}
}

func (n *Node) handleConn(netConn net.Conn) {
	defer n.wg.Done()
	defer netConn.Close()

	// Set initial read deadline for handshake
	netConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read handshake to get peer ID.
	data, err := readMessageRaw(netConn)
	if err != nil {
		n.logger.Debug("Handshake read error", "error", err)
		return
	}
	peerID, _ := DecodeNodeIDHandshake(data)

	// Check for duplicate BEFORE sending handshake response
	// This way the outgoing side will get EOF and know we rejected
	n.connsMu.Lock()
	if existing, ok := n.conns[peerID]; ok {
		n.connsMu.Unlock()
		n.logger.Debug("Duplicate connection rejected", "peerID", peerID, "existing", existing.Addr)
		return // Don't send handshake - outgoing side will get EOF
	}
	n.connsMu.Unlock()

	// Send our handshake.
	if err := writeMessage(netConn, EncodeNodeIDHandshake(n.nodeID)); err != nil {
		return
	}

	// Re-check after handshake (another connection might have been established while we were sending)
	n.connsMu.Lock()
	if existing, ok := n.conns[peerID]; ok {
		n.connsMu.Unlock()
		n.logger.Debug("Duplicate connection rejected (race)", "peerID", peerID, "existing", existing.Addr)
		return
	}

	conn := &Conn{
		NodeID:  peerID,
		Addr:    netConn.RemoteAddr().String(),
		conn:    netConn,
		pending: make(map[uint32]chan *Message),
	}
	n.conns[peerID] = conn
	n.connsMu.Unlock()

	n.logger.Info("Peer connected", "peerID", peerID, "addr", conn.Addr)

	defer func() {
		n.connsMu.Lock()
		// Only delete if this is still our connection (avoid deleting a newer connection)
		if cur, ok := n.conns[peerID]; ok && cur == conn {
			delete(n.conns, peerID)
		}
		n.connsMu.Unlock()
		n.logger.Info("Peer disconnected", "peerID", peerID)
	}()

	n.dispatchLoop(netConn, conn, peerID)
}

// dispatchLoop is the canonical message-routing loop used by both
// inbound (handleConn) and outbound (ConnectDirect) connections.
// It reads each message, classifies it via UnwrapCorrelated, and
// routes:
//   - Call requests → handler → WrapCorrelated(ReqFlagResp) response
//   - Call responses → conn.pending channel for the awaiting goroutine
//   - Uncorrelated messages → handler → optional response
//
// Returns when the underlying conn errors (non-timeout) or ctx is
// cancelled. The caller is responsible for the per-connection
// cleanup (conns-map delete, log).
func (n *Node) dispatchLoop(netConn net.Conn, conn *Conn, peerID string) {
	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		data, err := readMessageRaw(netConn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			n.logger.Debug("Read error", "peerID", peerID, "error", err)
			return
		}

		if reqID, flag, body, isCall := UnwrapCorrelated(data); isCall {
			switch flag {
			case ReqFlagResp:
				if msg, err := Parse(body); err == nil {
					conn.pendMu.Lock()
					if ch, ok := conn.pending[reqID]; ok {
						select {
						case ch <- msg:
						default:
						}
					}
					conn.pendMu.Unlock()
				}
			case ReqFlagReq:
				msg, err := Parse(body)
				if err != nil {
					continue
				}
				msgType := msg.Flags() >> 8
				n.handlersMu.RLock()
				handler, ok := n.handlers[msgType]
				n.handlersMu.RUnlock()
				if !ok {
					continue
				}
				resp, herr := handler(n.ctx, peerID, msg)
				if herr != nil {
					n.logger.Error("Handler error", "peerID", peerID, "msgType", msgType, "error", herr)
					continue
				}
				if resp != nil {
					conn.mu.Lock()
					writeErr := writeMessage(netConn, WrapCorrelated(reqID, ReqFlagResp, resp.Bytes()))
					conn.mu.Unlock()
					if writeErr != nil {
						n.logger.Debug("Write error", "peerID", peerID, "error", writeErr)
						return
					}
				}
			}
			continue
		}

		// Uncorrelated message — direct handler dispatch.
		msg, err := Parse(data)
		if err != nil {
			continue
		}
		msgType := msg.Flags() >> 8
		n.handlersMu.RLock()
		handler, ok := n.handlers[msgType]
		n.handlersMu.RUnlock()
		if !ok {
			continue
		}
		resp, herr := handler(n.ctx, peerID, msg)
		if herr != nil {
			n.logger.Error("Handler error", "peerID", peerID, "msgType", msgType, "error", herr)
			continue
		}
		if resp != nil {
			conn.mu.Lock()
			writeErr := writeMessage(netConn, resp.Bytes())
			conn.mu.Unlock()
			if writeErr != nil {
				n.logger.Debug("Write error", "peerID", peerID, "error", writeErr)
				return
			}
		}
	}
}

func (n *Node) handlePeerEvent(peer *mdns.Peer, joined bool) {
	if joined {
		n.logger.Info("Peer discovered", "peerID", peer.NodeID, "addr", peer.Address())
		// Deterministic connection rule: LOWER node ID always initiates
		// This prevents races when both sides try to connect simultaneously
		if n.nodeID < peer.NodeID {
			addr := peer.Address()
			go func() {
				// Use ConnectDirect with the discovered address
				if err := n.ConnectDirect(addr); err != nil {
					n.logger.Debug("Failed to connect to discovered peer",
						"peerID", peer.NodeID, "addr", addr, "error", err)
				}
			}()
		}
		// If our ID is higher, we wait for them to connect to us
	} else {
		n.logger.Info("Peer lost", "peerID", peer.NodeID)
		n.connsMu.Lock()
		if conn, ok := n.conns[peer.NodeID]; ok {
			conn.conn.Close()
			delete(n.conns, peer.NodeID)
		}
		n.connsMu.Unlock()
	}
}

func (n *Node) getOrConnect(peerID string) (*Conn, error) {
	n.connsMu.RLock()
	conn, ok := n.conns[peerID]
	n.connsMu.RUnlock()
	if ok {
		return conn, nil
	}

	// Look up peer via discovery. Discovery is nil for noDiscovery
	// nodes and is cleared on Stop(); both cases are races against
	// in-flight Broadcasts and should report a benign "peer not
	// found" rather than panic.
	if n.discovery == nil {
		return nil, fmt.Errorf("peer not found: %s (discovery unavailable)", peerID)
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

	// Connect
	addr := peer.Address()
	netConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	if n.tlsCfg != nil {
		netConn = tls.Client(netConn, n.tlsCfg)
	}

	// Send handshake (canonical encoder).
	if err := writeMessage(netConn, EncodeNodeIDHandshake(n.nodeID)); err != nil {
		netConn.Close()
		return nil, err
	}

	// Read handshake response (canonical decoder).
	respData, err := readMessageRaw(netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	remotePeerID, _ := DecodeNodeIDHandshake(respData)
	if remotePeerID != peerID {
		netConn.Close()
		return nil, fmt.Errorf("peer ID mismatch: expected %s, got %s", peerID, remotePeerID)
	}

	conn = &Conn{
		NodeID:  peerID,
		Addr:    addr,
		conn:    netConn,
		pending: make(map[uint32]chan *Message),
	}

	// Check if we already have a connection (race with incoming connection)
	n.connsMu.Lock()
	if existing, ok := n.conns[peerID]; ok {
		n.connsMu.Unlock()
		netConn.Close()
		return existing, nil // Use existing connection
	}
	n.conns[peerID] = conn
	n.connsMu.Unlock()

	n.logger.Info("Connected to peer", "peerID", peerID, "addr", addr)

	// Start receive loop
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.connsMu.Lock()
			// Only delete if this is still our connection
			if cur, ok := n.conns[peerID]; ok && cur == conn {
				delete(n.conns, peerID)
			}
			n.connsMu.Unlock()
		}()

		for {
			select {
			case <-n.ctx.Done():
				return
			default:
			}

			// Set read deadline so we can check for context cancellation
			netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			data, err := readMessageRaw(netConn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			// Check if this is a Call response (has 8-byte header with response flag)
			if len(data) >= 8 {
				reqFlag := binary.LittleEndian.Uint32(data[4:8])
				if reqFlag == ReqFlagResp {
					// Route response to waiting goroutine
					reqID := binary.LittleEndian.Uint32(data[0:4])
					msg, err := Parse(data[8:])
					if err == nil {
						conn.pendMu.Lock()
						if ch, ok := conn.pending[reqID]; ok {
							select {
							case ch <- msg:
							default:
							}
						}
						conn.pendMu.Unlock()
					}
					continue
				}
			}

			// Regular message - use standard handler
			msg, err := Parse(data)
			if err != nil {
				continue
			}

			msgType := msg.Flags() >> 8
			n.handlersMu.RLock()
			handler, ok := n.handlers[msgType]
			n.handlersMu.RUnlock()

			if ok {
				handler(n.ctx, peerID, msg)
			}
		}
	}()

	return conn, nil
}

// ConnectDirect connects directly to a peer at the given address (bypasses mDNS).
func (n *Node) ConnectDirect(addr string) error {
	if n.transport == TransportQUIC {
		return n.quicConnectDirect(n.ctx, addr)
	}
	netConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	if n.tlsCfg != nil {
		netConn = tls.Client(netConn, n.tlsCfg)
	}

	// Send handshake.
	if err := writeMessage(netConn, EncodeNodeIDHandshake(n.nodeID)); err != nil {
		netConn.Close()
		return err
	}

	// Read handshake response.
	data, err := readMessageRaw(netConn)
	if err != nil {
		netConn.Close()
		return err
	}
	peerID, ok := DecodeNodeIDHandshake(data)
	if !ok {
		netConn.Close()
		return fmt.Errorf("invalid peer handshake")
	}

	conn := &Conn{
		NodeID:  peerID,
		Addr:    addr,
		conn:    netConn,
		pending: make(map[uint32]chan *Message),
	}

	// Check if we already have a connection (race with incoming connection)
	n.connsMu.Lock()
	if _, ok := n.conns[peerID]; ok {
		n.connsMu.Unlock()
		netConn.Close()
		return nil // Already connected, that's fine
	}
	n.conns[peerID] = conn
	n.connsMu.Unlock()

	n.logger.Info("Connected to peer", "peerID", peerID, "addr", addr)

	// Start receive loop — shares the canonical dispatchLoop with
	// the inbound (handleConn) path so message routing has exactly
	// one implementation.
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.connsMu.Lock()
			if cur, ok := n.conns[peerID]; ok && cur == conn {
				delete(n.conns, peerID)
			}
			n.connsMu.Unlock()
			n.logger.Info("Peer disconnected", "peerID", peerID)
		}()
		n.dispatchLoop(netConn, conn, peerID)
	}()

	return nil
}

// Send sends a message over the connection.
func (c *Conn) Send(msg *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeMessage(c.conn, msg.Bytes())
}

// Recv receives a message from the connection.
func (c *Conn) Recv() (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return readMessage(c.conn)
}

// Wire format: [4 bytes length][message bytes]
func writeMessage(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readMessage(r io.Reader) (*Message, error) {
	data, err := readMessageRaw(r)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func readMessageRaw(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(lenBuf[:])
	if length > 10*1024*1024 { // 10MB max
		return nil, errors.New("message too large")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	return data, nil
}
