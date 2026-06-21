// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"fmt"
	"time"
)

// watch.go is the IntentWatch capability: subscribe to a notified intent's D
// result. It NEVER moves value — OnCommitted resolves to a POINTER (DExportRef),
// which the caller then feeds to ImportSettlement, which itself only builds
// calldata the chain consumes against the real object.
//
// A malicious server can drive a watch to PhaseCommitted with a fabricated
// DExportRef. That is HARMLESS: the only thing a caller does with the ref is
// importSettlement -> on-chain ImportSettlement, which reads the real object and
// reverts if it is missing or binds to a different owner/asset/amount. The watch
// surfaces a pointer; the chain is the judge.

// IntentWatch is the subscription handle a NotifyIntent returns. Poll observes the
// current phase; OnCommitted yields a Promise that resolves to the DExportRef when
// (and only when) the watch observes a committed D export.
type IntentWatch struct {
	session  *clientSession
	intentID ID
}

// IntentID is the intent this watch tracks.
func (w IntentWatch) IntentID() ID { return w.intentID }

// Poll observes the current status once. Gated by AuthWatch. Read-only.
func (w IntentWatch) Poll(ctx context.Context) (IntentStatus, error) {
	if w.session == nil {
		return IntentStatus{Phase: PhaseUnknown}, fmt.Errorf("dexsession: nil watch")
	}
	if err := w.session.requireGrant(AuthWatch); err != nil {
		return IntentStatus{Phase: PhaseUnknown}, err
	}
	reqMsg, err := buildWatchPollRequest(w.intentID)
	if err != nil {
		return IntentStatus{Phase: PhaseUnknown}, err
	}
	resp, err := w.session.conn.Call(ctx, w.session.peerID, reqMsg)
	if err != nil {
		return IntentStatus{Phase: PhaseUnknown}, err
	}
	defer resp.Release()
	return readIntentStatus(resp), nil
}

// OnCommitted returns a Promise that resolves to the committed DExportRef. It
// pipelines: the returned promise feeds straight into ImportSettlement. Internally
// it streams the watch — polling the server until PhaseCommitted (a committed D
// block produced the export) or a terminal PhaseRejected, with a bounded backoff.
//
// This is the streaming watch the spec asks for: the caller writes
// watch.OnCommitted().then(ImportSettlement) and the resolution arrives when D has
// actually committed — not a synchronous fiction. (A server that supports push
// resolution sends MsgWatchPush; the client treats a push and a poll identically —
// both deliver an IntentStatus, and only a Committed status with a ref resolves
// the promise.)
//
// CANNOT move value: the promise resolves to a POINTER. The credit happens later,
// on-chain, against the real object.
func (w IntentWatch) OnCommitted(ctx context.Context) *Promise[DExportRef] {
	p := newPromise[DExportRef]()
	if w.session == nil {
		p.fulfil(DExportRef{}, fmt.Errorf("dexsession: nil watch"))
		return p
	}
	if err := w.session.requireGrant(AuthWatch); err != nil {
		p.fulfil(DExportRef{}, err)
		return p
	}
	go w.streamUntilCommitted(ctx, p)
	return p
}

// streamUntilCommitted polls the watch until it commits, is rejected, or ctx ends.
// Backoff starts tight (the happy path is sub-second on a live D-Chain) and caps,
// so a stuck intent does not hot-loop. A PhaseRejected resolves the promise with an
// error (the intent will never settle — e.g. unbacked / expired); a never-
// resolving D block leaves the promise pending until ctx is cancelled, which is
// the correct behaviour (no D block => no committed ref => no settlement — the
// TestZAP_NotifyIntent_CannotValidateMatchWithoutDBlock property).
func (w IntentWatch) streamUntilCommitted(ctx context.Context, p *Promise[DExportRef]) {
	backoff := 25 * time.Millisecond
	const maxBackoff = 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			p.fulfil(DExportRef{}, ctx.Err())
			return
		default:
		}
		st, err := w.Poll(ctx)
		if err != nil {
			p.fulfil(DExportRef{}, err)
			return
		}
		switch st.Phase {
		case PhaseCommitted:
			// Bind the resolved ref's intent id to the watch's intent id (defence
			// against a server returning a ref for a different intent — the caller
			// only ever asked about THIS intent). The ref is still just a pointer;
			// the chain re-verifies on import.
			ref := st.Ref
			ref.IntentID = w.intentID
			p.fulfil(ref, nil)
			return
		case PhaseRejected:
			reason := st.Reason
			if reason == "" {
				reason = "intent rejected by D"
			}
			p.fulfil(DExportRef{}, fmt.Errorf("dexsession: intent %x rejected: %s", w.intentID[:8], reason))
			return
		default:
			// Pending / Matching / Unknown: wait and re-poll.
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				p.fulfil(DExportRef{}, ctx.Err())
				return
			case <-t.C:
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}
