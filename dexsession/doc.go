// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dexsession is the ZAP/Cap'n-Proto orchestration layer for the Lux DEX.
//
// It makes the native C<->D atomic settlement flow FEEL synchronous (capability
// transport + promise pipelining) while keeping the value boundary 100% native.
//
// # The hard invariant (the whole point)
//
// A ZAP response is NEVER sufficient to move money. Money moves ONLY when:
//
//	C  consumes a real D->C atomic shared-memory export object, OR
//	D  consumes a real C->D atomic export object.
//
// Even a fully malicious or stale ZAP layer cannot mint, credit, or substitute
// value: it can only POINT the precompile/keeper at an atomic object that the
// chain independently verifies (asset / owner / amount / one-time bound). This
// package therefore traffics in VALUES — quotes (estimates), calldata (bytes to
// sign), and POINTERS (DExportRef) — never in authority over a balance.
//
// # Why the invariant holds structurally, not just by policy
//
// The C-side value boundary (luxfi/precompile/dex/native_dchain_client.go) and
// the D-side value boundary (luxfi/chains/dexvm/atomic.go) both operate on EVM
// host capabilities (a StateDB and an AtomicState / shared memory). This package
// holds NONE of those: it has no StateDB, no AtomicState, no shared memory, and
// — by deliberate module discipline — no compile-time edge to the precompile or
// the EVM at all. It cannot import the C Verify path, and the C Verify path does
// not import it. The only things crossing the boundary are bytes:
//
//   - prepareSwapIntent returns CALLDATA (hookData for 0x9999) the USER signs;
//     it reserves no funds and returns no amountOut the chain trusts.
//   - notifyIntent tells D to SCAN/import a C->D object the user's signed C tx
//     already created; it cannot make a D match valid without a committed D
//     block.
//   - importSettlement returns finalization CALLDATA / submits a C tx that
//     merely POINTS at a DExportRef; the chain's ImportSettlement re-reads the
//     real D->C object and binds recipient/asset/amount to it.
//
// So "no capability moves money" is provable by EXHAUSTION over the API surface:
// there is no creditBalance / settleFill / overrideMatch / adminWithdraw method
// to call (see capability.go). The capability gate is defence in depth on top of
// a surface that is already value-free by construction.
//
// # Capabilities (Cap'n-Proto style)
//
// FullServiceNode.Bootstrap returns a RESTRICTED DexSession. From the session a
// caller derives narrowly-scoped, unforgeable capabilities — QuoteCap (read),
// IntentCap (request a C->D intent + notify), WatchCap (subscribe to a D
// result), SettlementCap (ask C to import an EXISTING D->C object), AdminCap
// (halt/status only, separately gated). A capability cannot grant authority the
// session was not bootstrapped with, and none of them can mint or credit a C
// balance.
//
// # Promise pipelining (the latency win)
//
// Dependent calls issue before each prior resolves:
//
//	quote  := dex.Quote(req)
//	intent := dex.PrepareSwapIntent(req, quote)   // takes the quote promise
//	watch  := dex.NotifyIntent(intent)            // takes the intent promise
//	settle := watch.OnCommitted().ImportSettlement()
//
// The client overlaps network latency (each call dispatches the instant its
// inputs resolve), and a Pipeline batch collapses a whole dependency chain into
// a single round trip. The consensus path stays native atomic throughout.
package dexsession
