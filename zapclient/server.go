// server.go — procedure-name handler registration on a ZAP node.

package zapclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	zap "github.com/luxfi/zap"
)

// ProcedureHandler runs server-side for one inbound procedure call.
// Return nil + nil-err to ack a fire-and-forget Send. Return a
// response + nil-err to reply to a Call. Return nil + non-nil err to
// signal failure; the client side observes the err on its Call.
type ProcedureHandler func(ctx context.Context, peer PeerInfo, req *zap.Message) (*zap.Message, error)

// ServerOptions configure NewServer.
type ServerOptions struct {
	NodeID   string
	Port     int
	TLS      *tls.Config
	Verifier PeerVerifier
	Logger   *slog.Logger
	// Metadata is the mDNS TXT-record metadata advertised to peers.
	Metadata map[string]string
	// NoDiscovery disables mDNS advertisement entirely. Use for
	// stdio / unix-socket tests.
	NoDiscovery bool
}

// ServerOption is a functional-option knob.
type ServerOption func(*ServerOptions)

// WithServerNodeID names this server in mDNS announcements.
func WithServerNodeID(id string) ServerOption {
	return func(o *ServerOptions) { o.NodeID = id }
}

// WithServerTLS configures mutual TLS on the listener.
func WithServerTLS(cfg *tls.Config) ServerOption {
	return func(o *ServerOptions) { o.TLS = cfg }
}

// WithVerifier installs the server-side PeerVerifier.
// Default is LocalTrustVerifier, which accepts any authenticated peer.
// Set to AllowListVerifier or a custom impl for stricter policy.
func WithVerifier(v PeerVerifier) ServerOption {
	return func(o *ServerOptions) { o.Verifier = v }
}

// WithServerLogger sets the structured logger.
func WithServerLogger(l *slog.Logger) ServerOption {
	return func(o *ServerOptions) { o.Logger = l }
}

// WithServerMetadata sets the mDNS TXT-record metadata.
func WithServerMetadata(m map[string]string) ServerOption {
	return func(o *ServerOptions) { o.Metadata = m }
}

// WithNoDiscovery disables mDNS advertisement (test-only).
func WithNoDiscovery() ServerOption {
	return func(o *ServerOptions) { o.NoDiscovery = true }
}

// Server is the native ZAP server side: procedure-name dispatch on
// top of *zap.Node. Construct with NewServer, Register procedures,
// Start to begin accepting, Stop to release.
type Server struct {
	node     *zap.Node
	verifier PeerVerifier
	logger   *slog.Logger

	mu         sync.RWMutex
	procedures map[uint16]registration // opcode → handler
	procNames  map[string]uint16       // procedure name → opcode (for collision check + telemetry)
}

type registration struct {
	procedure string
	handler   ProcedureHandler
}

// NewServer constructs a server for the given service type + port.
// The returned Server is not yet listening — call Start.
func NewServer(serviceType string, opts ...ServerOption) (*Server, error) {
	if serviceType == "" {
		return nil, errors.New("zapclient: serviceType is required")
	}
	o := ServerOptions{
		Verifier: LocalTrustVerifier{},
		Logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.NodeID == "" {
		o.NodeID = "zapserver-" + randomSuffix()
	}
	n := zap.NewNode(zap.NodeConfig{
		NodeID:      o.NodeID,
		ServiceType: serviceType,
		Port:        o.Port,
		Metadata:    o.Metadata,
		Logger:      o.Logger,
		NoDiscovery: o.NoDiscovery,
		TLS:         o.TLS,
	})
	s := &Server{
		node:       n,
		verifier:   o.Verifier,
		logger:     o.Logger,
		procedures: make(map[uint16]registration),
		procNames:  make(map[string]uint16),
	}
	return s, nil
}

// Register binds a procedure name to a handler.
//
// Refuses to register if the procedure's opcode collides with an
// already-registered procedure — the caller MUST rename. With the
// 8-bit codespace, occasional collisions are expected; the build
// fails clearly rather than silently routing to the wrong handler.
func (s *Server) Register(procedure string, h ProcedureHandler) error {
	op, err := ProcedureOpcode(procedure)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.procedures[op]; ok {
		return fmt.Errorf("zapclient: opcode 0x%04x collision: %q and %q hash to the same code; rename one",
			op, existing.procedure, procedure)
	}
	s.procedures[op] = registration{procedure: procedure, handler: h}
	s.procNames[procedure] = op
	s.node.Handle(op, s.dispatch)
	return nil
}

// Start binds the listener and begins accepting. Call Stop on shutdown.
func (s *Server) Start() error {
	return s.node.Start()
}

// Stop releases the underlying node + listener. Idempotent.
func (s *Server) Stop() {
	s.node.Stop()
}

// NodeID returns the server's NodeID — useful for tests + ops.
func (s *Server) NodeID() string { return s.node.NodeID() }

// dispatch is the shared Handler for every registered opcode. It
// runs PeerVerifier first; on accept, forwards to the procedure-
// specific handler.
func (s *Server) dispatch(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	op := msg.Flags()
	s.mu.RLock()
	reg, ok := s.procedures[op]
	s.mu.RUnlock()
	if !ok {
		s.logger.Warn("zapclient: unknown opcode", "from", from, "opcode", fmt.Sprintf("0x%04x", op))
		return nil, ErrUnknownProcedure
	}
	peer := PeerInfo{NodeID: from, ServiceType: s.node.NodeID()}
	if err := s.verifier.Verify(ctx, peer, reg.procedure); err != nil {
		s.logger.Warn("zapclient: peer rejected",
			"from", from, "procedure", reg.procedure, "reason", err)
		return nil, err
	}
	return reg.handler(ctx, peer, msg)
}
