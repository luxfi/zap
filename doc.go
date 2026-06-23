// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zap (v1) is deprecated for new schema authoring.
//
// New schemas MUST be authored via codegen (~/work/lux/zap/v2/codegen)
// which emits v1-equivalent fast paths from a declarative .zap source.
//
// Consumer dispatch for ad-hoc / dynamic schemas goes through the v2
// generic API (github.com/luxfi/zap/v1).
//
// The v1 hand-rolled code in this package remains for in-flight
// migration of legacy callers (luxfi/node/vms/platformvm/txs/zap_native,
// parts of luxfi/consensus/protocol/quasar, etc.); no new v1 schemas
// are accepted.
//
// The wire format is unchanged across v1 and v2 — this is a code-level
// decomplection of the authoring surface only. Existing v1 buffers
// remain parseable by both v1 and v2.
//
// See ~/work/lux/zap/v2/README.md for the canonical authoring path.
package zap
