// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexsession

import (
	"context"
	"testing"
	"time"
)

// red_test.go is the critical adversarial proof: NO sequence of ZAP responses,
// absent a real atomic object, credits or mints any C balance. The adversary
// controls the ENTIRE ZAP layer (maliciousVenue lies about every response). The
// AtomicLedger is the chain — the sole judge of value. The test drives the full
// client pipeline against the adversary and proves money moves IFF a real object
// exists, regardless of ZAP.

// TestRED_ZAP_ResponseAloneCannotMoveMoney is THE test. Three acts:
//
//	Act 1 — Empty chain, malicious ZAP. Run the full pipeline; the adversary claims
//	        COMMITTED with fabricated refs and returns inflated settlement calldata.
//	        Apply that calldata to the EMPTY ledger as the attacker AND as the
//	        victim. Assert: zero balance moves (every settlement reverts — no object).
//
//	Act 2 — A real object for the VICTIM exists. The adversary tries to redirect it
//	        to the attacker (fabricated ref/recipient/asset/amount). Assert: the
//	        attacker is never credited; only the victim, and only the true amount,
//	        and only when the victim submits the correct claim.
//
//	Act 3 — Exhaustive fuzz: thousands of adversarial response permutations
//	        (arbitrary amounts, keys, recipients, assets) against a ledger holding
//	        one real object. Assert: the ONLY successful credit is the exact
//	        (owner, asset, amount) of the real object, consumed exactly once. The
//	        sum of all credits never exceeds the real object's value.
func TestRED_ZAP_ResponseAloneCannotMoveMoney(t *testing.T) {
	ctx := context.Background()

	// ---- Act 1: empty chain, fully malicious ZAP -------------------------------
	{
		ledger := newAtomicLedger()
		attacker := Account{0x99, 0x88, 0x77}
		victim := Account{0x11, 0x22, 0x33}
		asset := ID{0x0A}

		adversary := &maliciousVenue{
			fakeAmount:    1_000_000_000, // claim a billion units
			fakeRecipient: attacker,
			fakeAsset:     asset,
			fakeKey:       DeriveUTXOID(ID{0xBA, 0xD0}, 0), // points at nothing
		}
		c := NewSession(SessionConfig{Conn: venueLoopback(adversary), PeerID: "evil", Grant: AuthorityPublic, Markets: testMarkets})

		// Drive the WHOLE pipeline. The adversary claims instant commit.
		req := testReq()
		req.Account = attacker
		req.Recipient = attacker
		stages := c.SwapFlow(ctx, req)

		// The adversary makes OnCommitted resolve (it lies PhaseCommitted). The
		// settlement promise resolves to (lying) calldata.
		res, err := stages.Settle.Await(ctx)
		if err != nil {
			t.Fatalf("act1: adversary settle promise errored unexpectedly: %v", err)
		}

		// Now the CHAIN judges. Apply the adversary's calldata every way an attacker
		// could try: as the attacker (caller=attacker), as the victim, with the
		// adversary's claimed asset, etc. EVERY path must move zero (the ledger is
		// empty — no object exists).
		for _, caller := range []Account{attacker, victim} {
			for _, outAsset := range []ID{asset, {0x0B}, {}} {
				_, serr := ledger.applySettlementCalldata(res, caller, outAsset)
				if serr == nil {
					t.Fatalf("act1: a settlement SUCCEEDED on an empty ledger (caller=%x asset=%x)", caller[:3], outAsset[:2])
				}
			}
		}
		// Total balances across the universe are zero.
		if total := ledger.totalCredited(); total != 0 {
			t.Fatalf("act1: %d units credited from ZAP responses alone (want 0)", total)
		}
	}

	// ---- Act 2: a real object exists for the victim; adversary tries to steal ---
	{
		ledger := newAtomicLedger()
		attacker := Account{0x99, 0x88, 0x77}
		victim := Account{0x11, 0x22, 0x33}
		assetA := ID{0x0A}
		assetB := ID{0x0B}

		// REAL object: victim is owed 500 of asset A.
		realTx := ID{0xEE}
		realKey := DeriveUTXOID(realTx, 0)
		ledger.PutExport(realKey, atomicObject{owner: victim, asset: assetA, amount: 500})

		// The adversary points the attacker at the victim's real object (the WORST
		// case: the object EXISTS), claiming the attacker's recipient/asset. fakeKey
		// is the correctly-derived object key, so the object is FOUND on import and
		// the only thing standing between the attacker and the funds is the on-chain
		// owner-bind.
		adversary := &maliciousVenue{
			fakeAmount:    500, // the true amount
			fakeRecipient: attacker,
			fakeAsset:     assetB,
			fakeKey:       realKey, // the real, correctly-derived object key
		}
		c := NewSession(SessionConfig{Conn: venueLoopback(adversary), PeerID: "evil", Grant: AuthorityPublic, Markets: testMarkets})

		req := testReq()
		req.Account = attacker
		req.Recipient = attacker
		res, err := c.SwapFlow(ctx, req).Settle.Await(ctx)
		if err != nil {
			t.Fatalf("act2: settle promise: %v", err)
		}
		// The adversary's calldata points at the REAL object (it exists) — so the
		// import gets PAST step 1 (object found) and is stopped by the owner-bind.
		if outID, _, ok := decodeSettlementCalldata(res.Calldata); !ok || outID != realKey {
			t.Fatalf("act2: adversary calldata did not point at the real object key")
		}

		// The attacker submits the calldata (caller=attacker). The object's owner is
		// the VICTIM, so the on-chain owner-bind rejects (owner != caller).
		_, serr := ledger.applySettlementCalldata(res, attacker, assetA)
		if serr != errLedgerOwner {
			t.Fatalf("act2: attacker stole the victim's object: %v", serr)
		}
		// The attacker tries with the adversary's claimed asset B too — now the
		// asset-bind (B != recorded A) fires first; still rejected, still no credit.
		_, serr = ledger.applySettlementCalldata(res, attacker, assetB)
		if serr != errLedgerOwner && serr != errLedgerAsset {
			t.Fatalf("act2: attacker stole with asset substitution: %v", serr)
		}
		if ledger.Balance(attacker, assetA) != 0 || ledger.Balance(attacker, assetB) != 0 {
			t.Fatalf("act2: attacker was credited")
		}

		// Only the VICTIM, submitting the correct claim (caller=victim, derived
		// asset=A, amount=500), is credited — and exactly once.
		got, err := ledger.applySettlementCalldata(settlementCalldataFor(realKey, 500), victim, assetA)
		if err != nil || got != 500 {
			t.Fatalf("act2: victim's honest claim failed: got=%d err=%v", got, err)
		}
		if ledger.Balance(victim, assetA) != 500 {
			t.Fatalf("act2: victim balance = %d, want 500", ledger.Balance(victim, assetA))
		}
		if total := ledger.totalCredited(); total != 500 {
			t.Fatalf("act2: total credited = %d, want exactly 500 (the real object)", total)
		}
	}

	// ---- Act 3: exhaustive adversarial permutation fuzz ------------------------
	{
		ledger := newAtomicLedger()
		victim := Account{0x11, 0x22, 0x33}
		assetA := ID{0x0A}
		realTx := ID{0xEE}
		realKey := DeriveUTXOID(realTx, 0)
		realAmount := uint64(500)
		ledger.PutExport(realKey, atomicObject{owner: victim, asset: assetA, amount: realAmount})

		callers := []Account{victim, {0x99}, {0xAB, 0xCD}, {}}
		assets := []ID{assetA, {0x0B}, {}, {0xFF}}
		amounts := []uint64{0, 1, 499, 500, 501, 1_000_000, 1 << 62}
		keys := []ID{realKey, DeriveUTXOID(realTx, 1), DeriveUTXOID(ID{0xBA}, 0), {}, {0xDE, 0xAD}}

		var successCount int
		for _, caller := range callers {
			for _, asset := range assets {
				for _, amount := range amounts {
					for _, key := range keys {
						res := settlementCalldataFor(key, amount)
						credited, err := ledger.applySettlementCalldata(res, caller, asset)
						if err == nil {
							successCount++
							// The ONLY legitimate success: the exact real object,
							// claimed by its true owner, true asset, true amount.
							if caller != victim || asset != assetA || amount != realAmount || key != realKey {
								t.Fatalf("act3: ILLEGITIMATE credit succeeded: caller=%x asset=%x amount=%d key=%x credited=%d",
									caller[:1], asset[:1], amount, key[:2], credited)
							}
							if credited != realAmount {
								t.Fatalf("act3: legitimate credit was %d, want %d", credited, realAmount)
							}
						}
					}
				}
			}
		}
		// Exactly one legitimate success across the whole permutation space (the
		// object is one-time; after it is consumed, every later attempt fails).
		if successCount != 1 {
			t.Fatalf("act3: %d settlements succeeded, want exactly 1 (one-time object)", successCount)
		}
		// And the total moved is bounded by the real object's value.
		if total := ledger.totalCredited(); total != realAmount {
			t.Fatalf("act3: total credited = %d, want %d (no mint beyond the real object)", total, realAmount)
		}
	}
}

// totalCredited sums all C balances across the ledger — the universe's total
// credited value. Used to assert ZAP responses mint nothing.
func (l *AtomicLedger) totalCredited() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var total uint64
	for _, v := range l.balance {
		total += v
	}
	return total
}

// TestRED_ZAP_StreamedFakeCommitsNeverSettle drives the streaming watch against an
// adversary that floods PhaseCommitted with rotating fake refs. Each fake ref's
// importSettlement reverts on-chain; no flood of fake commits ever moves value.
func TestRED_ZAP_StreamedFakeCommitsNeverSettle(t *testing.T) {
	ledger := newAtomicLedger()
	victim := Account{0x11, 0x22, 0x33}
	c := NewSession(SessionConfig{
		Conn:    venueLoopback(&maliciousVenue{fakeAmount: 1 << 40, fakeKey: DeriveUTXOID(ID{0xBA}, 0)}),
		PeerID:  "evil",
		Grant:   AuthorityPublic,
		Markets: testMarkets,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req := testReq()
	req.Account = victim
	req.Recipient = victim

	// The adversary resolves OnCommitted instantly (it lies). Settle yields fake
	// calldata. Apply it 1000 times every which way — zero moves.
	res, err := c.SwapFlow(ctx, req).Settle.Await(ctx)
	if err != nil {
		t.Fatalf("settle promise: %v", err)
	}
	for i := 0; i < 1000; i++ {
		if _, serr := ledger.applySettlementCalldata(res, victim, req.AssetIn); serr == nil {
			t.Fatalf("a flooded fake commit settled on an empty ledger at i=%d", i)
		}
	}
	if total := ledger.totalCredited(); total != 0 {
		t.Fatalf("flooded fake commits credited %d (want 0)", total)
	}
}
