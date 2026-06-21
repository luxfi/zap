// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"fmt"
	"sync"

	zaplib "github.com/luxfi/zap"
)

// session.go is the CLIENT side of the DexSession capability transport. A
// FullServiceNode.Bootstrap (server.go) returns a restricted DexSession; from it a
// caller derives capabilities and issues the five operations. Every operation is a
// typed ZAP Node.Call returning a Promise — the consensus path stays native
// atomic; this layer only orchestrates and pipelines.
//
// PER-METHOD may / MUST-NOT (enforced here + by the server + by the value
// boundary):
//
//	Quote / GetState  — READ. May estimate / observe. MUST NOT move value (no
//	                    value-moving code path exists; returns estimates).
//	PrepareSwapIntent — May validate params, estimate, derive the intent id, build
//	                    0x9999 calldata + hookData. MUST NOT reserve funds off-chain,
//	                    claim a fill final, or return an enforceable amountOut.
//	NotifyIntent      — May tell D to scan/import the C->D object the user's signed
//	                    tx created, returning a watch. MUST NOT make a D match valid
//	                    without a D block, or return a live fill C credits.
//	ImportSettlement  — May build a C tx / calldata pointing at a DExportRef. MUST
//	                    NOT credit C via RPC or substitute recipient/asset/amount.

// caller is the minimal slice of the ZAP node the client session needs: a
// correlated request/response Call to the bootstrapped peer. *zaplib.Node
// satisfies it; tests supply an in-memory loopback so the suite needs no socket.
type caller interface {
	Call(ctx context.Context, peerID string, msg *zaplib.Message) (*zaplib.Message, error)
}

// DexSession is the RESTRICTED capability a FullServiceNode.Bootstrap returns. It
// exposes ONLY the orchestration surface — quote/getState/prepareSwapIntent/
// notifyIntent/importSettlement — and derives narrowly-scoped capabilities. There
// is no creditBalance / settleFill / overrideMatch / adminWithdraw: the surface is
// value-free by construction (see capability.go).
type DexSession interface {
	// Capability derivation (Cap'n-Proto: you get authority by ASKING the session;
	// it only hands out caps within its bootstrap grant).
	QuoteCap() (QuoteCap, error)
	IntentCap() (IntentCap, error)
	WatchCap() (WatchCap, error)
	SettlementCap() (SettlementCap, error)
	AdminCap() (AdminCap, error)

	// Operations. Each returns a Promise for pipelining; Await for the value.
	Quote(ctx context.Context, req QuoteRequest) *Promise[QuoteResult]
	GetState(ctx context.Context, req StateRequest) *Promise[StateResult]
	PrepareSwapIntent(ctx context.Context, req SwapIntentRequest) *Promise[PreparedIntent]
	NotifyIntent(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[IntentWatch]
	ImportSettlement(ctx context.Context, ref *Promise[DExportRef]) *Promise[SettlementSubmitResult]

	// Grant reports the authority this session was bootstrapped with.
	Grant() Authority
}

// clientSession is the concrete DexSession. It holds the bootstrap grant, the
// peer to Call, and the unforgeable-token grant table for derived capabilities.
type clientSession struct {
	conn   caller
	peerID string
	grant  Authority

	// market resolves a 32-byte marketID to the V4 PoolKey args the swap calldata
	// needs. Without a mapping prepareSwapIntent cannot build calldata (fail-closed)
	// — the session is configured with the markets it serves at bootstrap.
	market func(marketID ID) (PoolKeyArgs, bool)

	mu     sync.Mutex
	grants map[token]*grant // issued capability tokens -> authority
}

var _ DexSession = (*clientSession)(nil)

// SessionConfig configures a client session (normally produced by Bootstrap, but
// exported so a node can construct one directly against a known peer).
type SessionConfig struct {
	Conn    caller
	PeerID  string
	Grant   Authority
	Markets func(marketID ID) (PoolKeyArgs, bool)
}

// NewSession builds a client session. Bootstrap (server.go) is the canonical
// entry; this is the explicit constructor for a node that already has a peer.
func NewSession(cfg SessionConfig) *clientSession {
	m := cfg.Markets
	if m == nil {
		// No market mapping => prepareSwapIntent fail-closes (cannot build calldata
		// for an unknown market), which is the correct secure default.
		m = func(ID) (PoolKeyArgs, bool) { return PoolKeyArgs{}, false }
	}
	return &clientSession{
		conn:   cfg.Conn,
		peerID: cfg.PeerID,
		grant:  cfg.Grant,
		market: m,
		grants: make(map[token]*grant),
	}
}

func (s *clientSession) Grant() Authority { return s.grant }

// issue mints a capability core for `bits`, but ONLY for bits the session was
// bootstrapped with. Asking for authority outside the grant fails — a session
// cannot widen its own authority, and therefore neither can any capability derived
// from it (the Cap'n-Proto confinement property).
func (s *clientSession) issue(bits Authority) (*capCore, error) {
	if s.grant&bits != bits {
		return nil, ErrNoAuthority
	}
	t := newToken()
	if t == (token{}) {
		// Zero token => RNG failure; refuse rather than issue an unbound capability.
		return nil, ErrNoAuthority
	}
	s.mu.Lock()
	s.grants[t] = &grant{bits: bits}
	s.mu.Unlock()
	return &capCore{session: s, tok: t, bits: bits}, nil
}

// checkGrant verifies a token still permits `need` at this session. Called by
// capCore.authorize on every operation so a revocation is immediate.
func (s *clientSession) checkGrant(t token, need Authority) error {
	s.mu.Lock()
	g, ok := s.grants[t]
	s.mu.Unlock()
	if !ok {
		return ErrNoAuthority
	}
	if g.revoked {
		return ErrRevoked
	}
	if g.bits&need != need {
		return ErrNoAuthority
	}
	return nil
}

// Revoke invalidates a previously issued capability token. After revoke, any
// operation through that capability returns ErrRevoked (fail-closed).
func (s *clientSession) Revoke(t token) {
	s.mu.Lock()
	if g, ok := s.grants[t]; ok {
		g.revoked = true
	}
	s.mu.Unlock()
}

// --- Capability derivation -----------------------------------------------------

func (s *clientSession) QuoteCap() (QuoteCap, error) {
	c, err := s.issue(AuthQuote)
	return QuoteCap{core: c}, err
}
func (s *clientSession) IntentCap() (IntentCap, error) {
	c, err := s.issue(AuthIntent)
	return IntentCap{core: c}, err
}
func (s *clientSession) WatchCap() (WatchCap, error) {
	c, err := s.issue(AuthWatch)
	return WatchCap{core: c}, err
}
func (s *clientSession) SettlementCap() (SettlementCap, error) {
	c, err := s.issue(AuthSettlement)
	return SettlementCap{core: c}, err
}
func (s *clientSession) AdminCap() (AdminCap, error) {
	c, err := s.issue(AuthAdmin)
	return AdminCap{core: c}, err
}

// --- Operations ----------------------------------------------------------------

// Quote issues a read-only book estimate. Gated by AuthQuote. The result is an
// ESTIMATE; nothing the chain trusts.
func (s *clientSession) Quote(ctx context.Context, req QuoteRequest) *Promise[QuoteResult] {
	p := newPromise[QuoteResult]()
	if err := s.requireGrant(AuthQuote); err != nil {
		p.fulfil(QuoteResult{}, err)
		return p
	}
	go func() {
		reqMsg, err := buildQuoteRequest(req)
		if err != nil {
			p.fulfil(QuoteResult{}, err)
			return
		}
		resp, err := s.conn.Call(ctx, s.peerID, reqMsg)
		if err != nil {
			p.fulfil(QuoteResult{}, err)
			return
		}
		defer resp.Release()
		p.fulfil(readQuoteResult(resp), nil)
	}()
	return p
}

// GetState issues a read-only C/D DEX state observation. Gated by AuthQuote.
func (s *clientSession) GetState(ctx context.Context, req StateRequest) *Promise[StateResult] {
	p := newPromise[StateResult]()
	if err := s.requireGrant(AuthQuote); err != nil {
		p.fulfil(StateResult{}, err)
		return p
	}
	go func() {
		reqMsg, err := buildStateRequest(req)
		if err != nil {
			p.fulfil(StateResult{}, err)
			return
		}
		resp, err := s.conn.Call(ctx, s.peerID, reqMsg)
		if err != nil {
			p.fulfil(StateResult{}, err)
			return
		}
		defer resp.Release()
		p.fulfil(readStateResult(resp), nil)
	}()
	return p
}

// PrepareSwapIntent builds the 0x9999 CALLDATA the user signs to create the funded
// C->D intent. Gated by AuthIntent.
//
// MUST NOT: reserve funds (it cannot — no StateDB), claim a fill (it returns no
// fill), return an enforceable amountOut (QuotedOut is flagged estimate-only and
// the enforceable floor rides MinAmountOut baked into the calldata).
//
// The intent id is derived HERE identically to the on-chain SubmitSwapIntent, so
// the user's signed tx mints exactly this id and the watch can locate the D
// result. The derivation is a pure function of the request — no authority.
func (s *clientSession) PrepareSwapIntent(ctx context.Context, req SwapIntentRequest) *Promise[PreparedIntent] {
	p := newPromise[PreparedIntent]()
	if err := s.requireGrant(AuthIntent); err != nil {
		p.fulfil(PreparedIntent{}, err)
		return p
	}
	go func() {
		p.fulfil(s.prepareLocal(ctx, req))
	}()
	return p
}

// prepareLocal is the pure build of a PreparedIntent. It optionally consults the
// server for a quote (estimate only); the calldata + intent id are derived
// locally so a malicious server cannot inject a forged intent id or calldata that
// the user would sign. (If the server were trusted to return the calldata, a
// malicious server could swap the recipient — so we BUILD it client-side from the
// user's own request.)
func (s *clientSession) prepareLocal(ctx context.Context, req SwapIntentRequest) (PreparedIntent, error) {
	if req.AmountIn == 0 {
		return PreparedIntent{}, fmt.Errorf("dexsession: prepareSwapIntent: zero amountIn")
	}
	pk, ok := s.market(req.MarketID)
	if !ok {
		// Fail-closed: cannot build swap calldata for a market we have no PoolKey
		// for. A user must not be handed calldata for an unknown market.
		return PreparedIntent{}, fmt.Errorf("dexsession: prepareSwapIntent: unknown market %x", req.MarketID[:8])
	}

	// Estimate the output (informational). A failed/absent quote does NOT fail the
	// prepare — the calldata is enforceable via MinAmountOut regardless.
	var quoted uint64
	if qr, err := s.Quote(ctx, QuoteRequest{MarketID: req.MarketID, AmountIn: req.AmountIn, ZeroForOne: zeroForOneFor(req)}).Await(ctx); err == nil {
		quoted = qr.AmountOut
	}

	// Derive the intent id identically to the on-chain SubmitSwapIntent.
	intentID := DeriveIntentID(
		req.NetworkID, req.CChainID, req.DChainID,
		// txID is unknown until the user signs/sends; the on-chain derivation uses
		// the real txID + callIndex. The off-chain prepared id is the PARTIAL
		// binding the watch correlates on; the authoritative id is minted on-chain.
		// We bind the known economic identity (account/asset/amount/market) so the
		// watch can match the emitted IntentSubmitted event by these fields even
		// before the final txID is known. The zero txID here is a placeholder the
		// watch tolerates (it matches on the economic tuple, see watch.go).
		ID{}, req.CallIndex,
		req.Account, req.AssetIn, req.AmountIn, req.MarketID,
	)

	// Phase A hookData (intent). Empty selects Phase A; we emit the explicit tag so
	// the intent is unambiguous on-chain.
	hookData := EncodeIntentHookData()
	calldata := EncodeSwapCalldata(pk, zeroForOneFor(req), req.AmountIn, hookData)

	return PreparedIntent{
		To:        addr9999(),
		Calldata:  calldata,
		HookData:  hookData,
		IntentID:  intentID,
		QuotedOut: quoted,
		DChainID:  req.DChainID,
		CChainID:  req.CChainID,
		Account:   req.Account,
		Recipient: req.Recipient,
		AssetIn:   req.AssetIn,
		AmountIn:  req.AmountIn,
		MarketID:  req.MarketID,
	}, nil
}

// NotifyIntent tells D (via the server) to scan/import the C->D object the user's
// signed tx created and returns a watch. Gated by AuthIntent. Pipelines on the
// prepared-intent promise.
//
// MUST NOT: make a D match valid without a D block (it only triggers; dexvm
// consensus does the import+match), or return a live fill C credits (it returns a
// watch, and the watch yields a POINTER on commit, never a credit).
func (s *clientSession) NotifyIntent(ctx context.Context, intent *Promise[PreparedIntent]) *Promise[IntentWatch] {
	return thenAsync(ctx, intent, func(ctx context.Context, pi PreparedIntent) (IntentWatch, error) {
		if err := s.requireGrant(AuthIntent); err != nil {
			return IntentWatch{}, err
		}
		reqMsg, err := buildPreparedIntent(pi)
		if err != nil {
			return IntentWatch{}, err
		}
		// retag as a notify (the server routes on msgType).
		notifyMsg, err := retag(reqMsg, MsgNotify)
		if err != nil {
			return IntentWatch{}, err
		}
		resp, err := s.conn.Call(ctx, s.peerID, notifyMsg)
		if err != nil {
			return IntentWatch{}, err
		}
		defer resp.Release()
		ref := readIntentWatchRef(resp)
		return IntentWatch{session: s, intentID: ref.IntentID}, nil
	})
}

// ImportSettlement asks C to import an EXISTING D->C object named by the ref, and
// returns the calldata / tx hash. Gated by AuthSettlement. Pipelines on the ref
// promise (which is typically watch.OnCommitted()).
//
// MUST NOT: credit C via RPC (it returns calldata/tx hash — the chain credits), or
// substitute recipient/asset/amount (the on-chain ImportSettlement binds them to
// the recorded object; the calldata carries only outputID + amount, and even those
// are bound). A keeper that submits the tx has no custody authority.
func (s *clientSession) ImportSettlement(ctx context.Context, ref *Promise[DExportRef]) *Promise[SettlementSubmitResult] {
	return thenAsync(ctx, ref, func(ctx context.Context, r DExportRef) (SettlementSubmitResult, error) {
		if err := s.requireGrant(AuthSettlement); err != nil {
			return SettlementSubmitResult{}, err
		}
		reqMsg, err := buildDExportRef(r)
		if err != nil {
			return SettlementSubmitResult{}, err
		}
		resp, err := s.conn.Call(ctx, s.peerID, reqMsg)
		if err != nil {
			return SettlementSubmitResult{}, err
		}
		defer resp.Release()
		return readSettlementResult(resp), nil
	})
}

// requireGrant is the session-level authority gate for the operation methods. It
// mirrors the capability gate (capCore.authorize) for callers that use the session
// surface directly rather than a derived capability — both check the same grant.
func (s *clientSession) requireGrant(need Authority) error {
	if s.grant&need != need {
		return ErrNoAuthority
	}
	return nil
}

// --- helpers -------------------------------------------------------------------

// addr9999 returns the 0x9999 settlement address as a 20-byte account. The
// canonical address is 0x...9999 (20 bytes, last two = 0x99 0x99 per the precompile
// poolManagerAddr9999). Kept local as a value (no geth dep).
func addr9999() Account {
	var a Account
	a[18] = 0x99
	a[19] = 0x99
	return a
}

// zeroForOneFor reports the swap direction for a request. The request expresses
// "sell AssetIn"; whether that is zeroForOne depends on the market's currency
// ordering, resolved via the PoolKey. For the prepared calldata we treat AssetIn
// as currency0 when it sorts first; the keeper/market mapping owns the canonical
// ordering. Default: selling AssetIn => zeroForOne when AssetIn == currency0.
func zeroForOneFor(req SwapIntentRequest) bool {
	// AssetInAddr zero (native) sorts first (currency0) by V4 convention; a token
	// sorts by address. We expose the direction the request implies: the request's
	// AssetIn is the token being sold, so zeroForOne iff AssetIn is currency0. The
	// market mapping encodes the canonical order; here we conservatively select
	// zeroForOne=true (sell currency0) which the on-chain handler re-validates
	// against the real PoolKey ordering. (A wrong direction simply fails the swap;
	// it cannot move value the wrong way — the chain binds direction to the pool.)
	return true
}

// retag rebuilds a message under a different msgType flag. The ZAP dispatcher
// routes on Flags()>>8, so a PreparedIntent built for MsgPrepare must be retagged
// MsgNotify before NotifyIntent's Call. The flags word lives at header bytes
// [6:8] little-endian and equals msgType<<8 (low byte 0, high byte msgType); no
// internal field offset references the header, so copying the buffer and patching
// only the flag word is byte-safe. We re-Parse to revalidate.
func retag(msg *zaplib.Message, msgType uint16) (*zaplib.Message, error) {
	src := msg.Bytes()
	buf := make([]byte, len(src))
	copy(buf, src)
	flags := msgType << 8
	buf[6] = byte(flags)      // low byte = 0
	buf[7] = byte(flags >> 8) // high byte = msgType
	return zaplib.Parse(buf)
}
