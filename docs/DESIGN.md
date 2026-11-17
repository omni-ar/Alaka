# Alaka: design and evidence

Alaka sits between an AI agent runtime and a payment rail. It keeps three promises, and every one
of them is machine-checked on each `scripts/verify-all.sh` run:

1. A mandate is never overspent: not in the ledger, and not on the rail.
2. A request is charged at most once, whatever the retries, timeouts or crashes.
3. Ledger and rail never disagree silently. If the rail charged, the intent is `CAPTURED`; if the
   intent is `VOIDED`, the rail did not charge.

This document covers how those promises are kept and the evidence for each claim. All numbers below
were measured on the repository at the time of writing; the run environment is stated where it
matters.

Contents: [1 Invariants](#1-invariants) · [2 Architecture](#2-architecture) ·
[3 Protocol](#3-the-three-phase--two-step-protocol) · [4 Formal model](#4-formal-verification-tla) ·
[5 Ledger kernel](#5-the-ledger-kernel-nidhi) · [6 Concurrency](#6-concurrency) ·
[7 Faults](#7-faults-timeouts-crashes-network-chaos) · [8 Mandates and quotes](#8-capability-mandates-and-quote-drift-mudra) ·
[9 HTTP](#9-http-surface) · [10 Limitations](#10-scope-and-limitations) · [11 Reproduce](#11-reproducing-everything)

---

## 1. Invariants

| Id | Invariant | Enforced by | Checked by |
|----|-----------|-------------|------------|
| I1 | `held + settled <= total_budget` in the ledger; the sum of succeeded rail charges `<= total_budget`; no intent above `max_per_tx` | Deferred conservation trigger (SG003); per-tx check on insert (SG003); the protocol for the rail side | TLC, SQL suite, property suite, storm, chaos |
| I2 | At most one intent and one charge per `(agent_id, idempotency_key)`; a replay with a different payload gets 422; a concurrent duplicate gets 409 | `UNIQUE (agent_id, idempotency_key)`; SHA-256 `request_hash`; deterministic rail idempotency keys `create_<id>` / `confirm_<id>` | TLC (one charge per key), engine tests, property suite, storm |
| I3 | Every ledger transaction balances; postings route only between the three mandate buckets; `available + held + settled = total`, all `>= 0`, at every COMMIT | Deferred constraint triggers (SG005) and composite foreign keys (23503) | TLC, SQL suite (137 + 20 cases), property suite |
| I4 | Revoked, expired or suspended mandates authorise nothing new; terminal mandate states are irreversible; time is judged by PostgreSQL `NOW()` | Intent insert trigger (SG001); mandate FSM trigger (SG004) | TLC (revocation), SQL suite, property suite |
| I5 | Intents move `RESERVED -> CONFIRMING -> AUTHORIZED -> CAPTURED`, or to `VOIDED` / `FAILED`; terminal states never change | Intent FSM trigger (SG004); write-once fields (SG006) | TLC (action property), SQL suite, property suite |
| I6 | No `VOIDED` / `FAILED` intent has a succeeded charge on the rail; a `CAPTURED` intent settled exactly what the rail charged | The recovery protocol: never void without the rail saying `canceled` | TLC, property suite, storm, chaos |

`dev.alaka.property.InvariantChecker` is the single executable form of I1–I6. The property suite,
the storm and the chaos suite all use it, and it reads three independent sources:

- the engine's own view;
- the ledger, through raw JDBC as `alaka_app` in one `REPEATABLE READ` snapshot;
- the rail's ground truth.

## 2. Architecture

```
                   agent runtime
                         |  POST /v1/spends   (X-Mudra-Token, spend + signed quote_token)
                         v
  +-----------------------------------------------------------------------+
  | alaka-core   dev.alaka.core                                           |
  |   AlakaHttpController -> SpendGateway -> SpendEngine (3 runtime modes)|
  +-------+--------------------------+---------------------------+--------+
          | verify token, quote      | Phase 1 / 3 transactions  | Phase 2 calls
          v                          v                           v
  +---------------+   +----------------------------+   +--------------------------+
  | mudra         |   | nidhi                      |   | yaksha                   |
  | Ed25519 token |   | PostgreSQL 16 double-entry |   | Stripe v1 wire adapter   |
  | signer and    |   | ledger, deferred triggers, |   | webhook HMAC + dedup     |
  | verifier;     |   | least-privilege roles,     |   | outbox recovery sweeper  |
  | quote drift   |   | SQLSTATE -> typed errors   |   | simulated rail (tests)   |
  +---------------+   +----------------------------+   +--------------------------+
```

| Package | Responsibility | Main types |
|---------|----------------|-----------|
| `dev.alaka.core` | Execution coordinator, idempotency gate, runtime modes, HTTP | `SpendEngine`, `HardenedSpendEngine`, `NaiveSpendEngine`, `SpendGateway`, `RailCallGuard`, `http.AlakaHttpController` |
| `dev.alaka.nidhi` | Ledger SQL, transactions, retry, error translation | `NidhiLedger`, `TransactionRunner`, `SqlStates`, `NidhiException` (sealed) |
| `dev.alaka.mudra` | Capability tokens, signed quotes and quote-to-settlement drift | `MudraTokenSigner`, `MudraTokenVerifier`, `MudraMandateClaims`, `MudraQuoteSigner`, `MudraQuoteVerifier`, `MudraQuoteClaims`, `MudraCodec`, `QuoteDriftEvaluator` |
| `dev.alaka.yaksha` | Rail port and adapters, webhooks, crash recovery | `PaymentRailPort`, `StripeHttpPaymentRail`, `StripeWebhookVerifier`, `StripeWebhookHandler`, `YakshaRecoverySweeper`, `SimulatedPaymentRail` |

Runtime modes (`--mode=` / `alaka.mode`):

| Mode | Isolation | Concurrency control | Purpose |
|------|-----------|--------------------|---------|
| `naive` | `READ COMMITTED`, autocommit | None. It checks the balance in app code, charges the rail, then appends to an unguarded `naive_spend_log` table | The anti-pattern baseline; it exists to fail measurably |
| `hardened-pessimistic` | `READ COMMITTED` | `spend_mandates FOR SHARE`, then `mandate_balances FOR UPDATE`, then `payment_intents FOR UPDATE` (canonical order) | Writers on one mandate queue; no retries |
| `hardened-ssi` | `SERIALIZABLE` | No explicit balance lock. Conflicts surface as `40001`; whole-transaction retry with exponential backoff and full jitter (≤ 100 attempts, 1 ms base, 64 ms cap) | Optimistic. Taking the lock too would make it the pessimistic mode at a higher isolation level |

The engine opens database work only inside `TransactionRunner.inTransaction` lambdas, which receive a
connection and nothing else. Every rail call goes through `RailCallGuard`, which throws if a
transaction is open on the calling thread. So the rule "never hold a transaction, connection or
lock across network I/O" is checked at run time on every rail call.

## 3. The three-phase / two-step protocol

```
 Phase 1   one DB tx, < 5 ms, no I/O
           idempotency gate -> lock mandate (FOR SHARE) -> lock balance (FOR UPDATE, pessimistic only)
           INSERT intent RESERVED + RESERVE ledger tx (DEBIT AVAILABLE, CREDIT HELD)
           + recovery task in outbox_tasks (due after the grace period)                  COMMIT
 Phase 2A  POST /v1/payment_intents  confirm=false  Idempotency-Key: create_<intent_id>
           (an unconfirmed payment intent never moves money; a late or duplicate packet is harmless)
           short DB tx: record pi_..., RESERVED -> CONFIRMING
 Phase 2B  POST /v1/payment_intents/{pi}/confirm      Idempotency-Key: confirm_<intent_id>
 Phase 3A  one DB tx: CONFIRMING -> CAPTURED + CAPTURE ledger tx
           (DEBIT HELD authorised, CREDIT SETTLED charged, CREDIT AVAILABLE remainder) + task COMPLETED
 Phase 3B  recovery, only from the rail's own answer (GET /v1/payment_intents/{pi}):
             RESERVED, no pi recorded            -> VOID (no confirm was ever sent)
             CONFIRMING, rail succeeded          -> 3A
             CONFIRMING, rail canceled           -> VOID
             CONFIRMING, rail requires_*         -> POST /cancel; on 200 VOID;
                                                    on 400 re-read, capture if it succeeded
             CONFIRMING, rail processing         -> change nothing; the hold stays
```

Why each step is there:

- **The create/confirm split.** A single "charge" call that times out leaves the client unable to
  tell "charged" from "not charged". After an unconfirmed create, only `/confirm` can move money,
  and Alaka sends it only once `CONFIRMING` with the recorded `pi_...` is committed. A late create
  packet therefore cannot charge.
- **`GET`, never a re-sent POST.** Stripe caches a 500 under its `Idempotency-Key`, so resending the
  POST only replays the 500. Its Search API is eventually consistent, and its List API cannot
  filter by idempotency key. A direct `GET` of the recorded `pi_...` is the only reliable read.
- **`/cancel` before voiding.** A successful cancel is what makes the rail reject a delayed
  in-flight confirm. Voiding locally without it is exactly the bug the TLA+ model reproduces
  (section 4).
- **Holding through `processing`.** In that state Stripe rejects `/cancel`
  (`payment_intent_unexpected_state`) and may still charge, so the hold is released only once the
  rail reaches a terminal state.

Races handled, each with a test in `HardenedSpendEngineTest` and the property suite:

| Race | Resolution |
|------|-----------|
| Recovery voids a `RESERVED` intent while its create is in flight | `createOnRail` sees `VOIDED` under the row lock and cancels the late payment intent |
| A confirm lands between recovery's read and its `/cancel` | The cancel is rejected; re-read, then capture |
| The webhook arrives before the `/confirm` HTTP response | Whichever settles first wins under the row lock; the other sees `CAPTURED`; one `CAPTURE` row |
| Concurrent first-time duplicates of one key | One insert wins on `UNIQUE (agent_id, idempotency_key)`. The losers re-run the gate and get 409, 422 or a replay. Under SSI the loser may see `40001` instead and retries |

Webhooks (`payment_intent.*`) are verified over the raw body:

- HMAC-SHA256 of `t.body` with the endpoint secret, compared in constant time (`MessageDigest.isEqual`);
- the signed timestamp must be within ±300 s;
- any of several `v1` values is accepted (secret rotation).

The event id is inserted into `processed_webhooks` (`ON CONFLICT DO NOTHING`) in the same
transaction that applies the event, so a replay is a no-op and an event is never half-applied.

`payment_intent.payment_failed` is deliberately not mapped to a direct void. It leaves the payment
intent cancelable, not canceled, so the handler records the event and then runs the recovery
protocol, which cancels before voiding.

## 4. Formal verification (TLA+)

`spec/AlakaInFlight.tla` models the protocol with explicit network packets and a rail with
`CREATED / PROCESSING / SUCCEEDED / CANCELED` states. It also models `/cancel` as its own step that
the rail rejects while `PROCESSING` or after success, and partial capture that releases the
remainder. Two constants switch on the two known bugs:

- `AllowBlindVoidWithoutCancel`: void locally while a confirm packet may still be in flight;
- `AllowVoidOnCancelFailure`: void although `/cancel` was rejected because the payment intent was
  `PROCESSING`.

The safe configuration checks invariants `TypeOK`, `I1_NoMandateOverspent`,
`ExactCaptureConsistency`, `I3_LedgerConservation`, `LedgerMatchesIntents`, `I6_NoSilentRailDrift`,
`ProcessingKeepsHeldLocked`, `VoidedOnlyAfterRailCanceled`, `RailWorstCaseExposureWithinBudget` and
`OpenIntentCanAlwaysProgress`, plus four action properties: `I5_MonotonicStateMachine`,
`RailMonotonic`, `I2_OneReservationAndOneChargePerKey` and `I4_RevokedMandateReservesNothing`.

TLC 2.19 (`tools/tla2tools.jar` v1.7.4). The unsafe configurations were run with `-workers 1`, which
yields the shortest counterexample deterministically.

| Config | Constants | Result | Generated | Distinct | Depth / trace |
|--------|-----------|--------|-----------|----------|---------------|
| `AlakaInFlight.cfg` (safe) | keys {k1,k2}; amounts {4,6,7}; budget 10; cap 6; partial {2,4} | No error | 25,052 | **6,642** | depth 16 |
| `AlakaInFlightWide.cfg` (safe) | keys {k1,k2,k3}; amounts {3,4,6,7}; otherwise as above | No error | 4,411,811 | **940,994** | depth 23 |
| `AlakaInFlightUnsafeBlindVoid.cfg` | blind void on | `I6_NoSilentRailDrift` violated | 482 | 268 | **6-state** trace |
| `AlakaInFlightUnsafeBlindVoidNoI6.cfg` | same, I6 unchecked | `I1_NoMandateOverspent` violated | 12,298 | 4,275 | **10-state** trace |
| `AlakaInFlightUnsafeCancelFailure.cfg` | void-on-cancel-failure on | `I6_NoSilentRailDrift` violated | 2,313 | 986 | **8-state** trace |
| `AlakaInFlightUnsafeCancelFailureNoI6.cfg` | same, I6 unchecked | `I1_NoMandateOverspent` violated | 19,837 | 6,011 | **12-state** trace |

Counterexamples, as action sequences from TLC's output:

```
Blind void, I6 (6):    Init, Reserve(k1), CreateUnconfirmedPI(k1), SendConfirmPacket(k1),
                       BuggyVoidWhilePacketInFlight(k1), RailReceiveConfirmPacket(k1)
                       -> k1 VOIDED locally, SUCCEEDED on the rail.
Blind void, I1 (10):   ... as above up to the buggy void (5), Reserve(k2, 6),
                       RailReceiveConfirmPacket(k1), CreateUnconfirmedPI(k2), SendConfirmPacket(k2),
                       RailReceiveConfirmPacket(k2)
                       -> rail charged 6 + 6 = 12 against a budget of 10.
Cancel failure, I6 (8):Init, Reserve(k1), CreateUnconfirmedPI(k1), SendConfirmPacket(k1),
                       RailReceiveConfirmPacket(k1) [-> PROCESSING], RailHandleCancelRequest(k1)
                       [REJECTED], BuggyVoidOnCancelFailure(k1), RailResolveProcessing(k1) [SUCCEEDED]
Cancel failure, I1 (12): ... as above up to the buggy void (7), Reserve(k2), RailResolveProcessing(k1),
                       CreateUnconfirmedPI(k2), SendConfirmPacket(k2), RailReceiveConfirmPacket(k2)
                       -> rail charged 12 against 10.
```

`scripts/verify-all.sh` requires the safe config to pass *and* each unsafe config to be rejected
with exactly its expected invariant. An unsafe config that passes is a failure: it would mean the
checker had lost its teeth.

The model was also checked for vacuity and for sensitivity to bugs (Milestone 1):

- **Vacuity:** fourteen probe configs in `spec/probes/` negate reachability facts, and TLC produced
  a witness for every one. The witnessed states include `PROCESSING`, a rejected cancel, a partial
  capture with the remainder released, voids after a rail cancel, and a capture after revocation.
- **Mutations:** seven mutations of the spec were each caught by a named invariant or property.

## 5. The ledger kernel (nidhi)

### Schema shape

- Three accounts per mandate: `MANDATE_AVAILABLE`, `MANDATE_HELD` and `MANDATE_SETTLED`. There is
  no fourth bucket.
- `mandate_balances` is a materialised view of `ledger_postings`. It is kept up to date by an
  `AFTER INSERT` trigger on postings, which is the table's only sanctioned writer.
- Every ledger transaction has a `transition_type`, and its routing is fixed:
  - `RESERVE`: AVAILABLE to HELD;
  - `VOID`: HELD to AVAILABLE;
  - `CAPTURE`: HELD to SETTLED, plus the remainder to AVAILABLE.
- Composite foreign keys `(tx_id, mandate_id, currency)` and `(account_id, mandate_id, currency)`
  make cross-mandate or cross-currency postings unrepresentable (23503).
- `migrations/003_index_postings_mandate.sql` indexes `ledger_postings (mandate_id)`. The per-commit
  balance cross-check filters on that column; without the index it is a full-table scan, which
  under SSI made unrelated mandates conflict (section 6.2).

### Why conservation cannot be a `CHECK` constraint

A reservation inserts two postings, one row at a time. After the first (`DEBIT AVAILABLE`) the
materialised balance is `available - x, held, settled`, which sums to `total - x`. An immediate
`CHECK (available + held + settled = total)` therefore rejects every valid transaction at its first
row.

Conservation, non-negativity, transaction balance, bucket routing and "materialised balance equals
the sum of postings" are therefore checked by `DEFERRABLE INITIALLY DEFERRED` constraint triggers,
which run at `COMMIT`. They are attached `AFTER INSERT` on both `ledger_transactions` and
`ledger_postings`. A lone posting appended later to an already-committed transaction re-triggers the
check on that transaction and is rejected.

### Least privilege

| Role | Can | Cannot |
|------|-----|--------|
| `alaka_migrator` | Own every object; apply migrations 001+ | Create databases or roles |
| `alaka_app` (runtime) | `SELECT` / `INSERT` on the ledger tables; `SELECT` / `INSERT` / `UPDATE` on intents, mandates and outbox; `UPDATE (version)` on `mandate_balances` (needed only for `SELECT ... FOR UPDATE`) | `TRUNCATE`, `DELETE`, `ALTER`, `DROP`, disable triggers, `SET session_replication_role`, create tables / temp tables / functions, `SET ROLE`, write any balance column |

The two trigger functions that must write tables the app may not touch are `SECURITY DEFINER`,
owned by the migrator: `trg_init_mandate_ledger` and `trg_apply_posting_to_mandate_balance`. All
nine trigger functions pin `search_path = public, pg_temp`. The Java service connects only as
`alaka_app`, and `AlakaConfiguration` refuses to start with any other database user.

### Vulnerabilities found by the adversarial suite

The 137-case suite (`tests/sql/verify_nidhi_attacks.sql`, run as `alaka_app`) found four real holes
in the baseline schema. The 20-case owner suite (`verify_nidhi_owner_guards.sql`) proves the guards
that privileges hide from the app. Each hole was reproduced against the verbatim baseline before it
was fixed, and each has regression cases.

| Tag | Hole in the baseline | Fix |
|-----|---------------------|-----|
| NIDHI-D9 | A balanced "CAPTURE" (DEBIT HELD, CREDIT AVAILABLE) could be committed against an intent left `RESERVED`. The hold was released while the intent stayed chargeable on the rail, and the freed budget could be reserved again: **140 committed on a budget of 100** | A `CAPTURE` / `VOID` ledger transaction is valid only if, at COMMIT, its intent is in the matching terminal state (SG005) |
| NIDHI-D8 | Same-status updates skipped all checks. `captured_amount_minor` could be rewritten on a captured intent, `stripe_payment_intent` nulled on a `CONFIRMING` one (breaking recovery), and the rail idempotency keys swapped | Rail keys immutable; `stripe_payment_intent` write-once; captured amount changes only on the transition into `CAPTURED` (SG006) |
| NIDHI-D7 | Only some mandate terms were frozen. A plain `UPDATE` could widen `allowed_merchants` or push `expires_at` forward on a lapsed mandate, defeating SG008 and I4 | Every signed term immutable: allowlist, `not_before`, `expires_at`, `token_kid` (SG006) |
| NIDHI-D5 | The `pg_trigger_depth() > 1` guard on `mandate_balances` was forgeable: a trigger on any table the attacker owns (a temp table suffices) set `available_minor` to 1,000,000 | The guard also requires `current_user` to own the table; `alaka_app` lost `TEMP` / `CREATE`, so it owns nothing |

Every custom SQLSTATE `SG001`–`SG008`, plus `23503`, is asserted at least once. The `P0001`–`P0004`
class is never used, because `P0002` is PL/pgSQL's `no_data_found`. `dev.alaka.nidhi.SqlStates`
translates each code into a sealed `NidhiException` subtype, including errors raised by `COMMIT`.

## 6. Concurrency

### 6.1 Twenty sessions against one mandate (SQL probe)

`tests/sql/verify_nidhi_concurrency.sh` runs each scenario as one wave:

- a fresh mandate with `total_budget_minor = 3000`;
- 20 `psql` sessions as `alaka_app`, each reserving 600 in one Phase 1 transaction, so at most 5 fit;
- sessions released together by an advisory-lock barrier, and held at a second barrier inside their
  transactions until all 20 are open at once (verified via `pg_locks`);
- `pg_sleep` widening the race window.

It asserts the exact final outcome of every session and the exact end state. Numbers are from 3
waves per scenario; outcomes were identical in every wave.

| Scenario | Outcome per wave | Where losers learn they failed | Mechanism |
|----------|------------------|-------------------------------|-----------|
| `rc_lock`: READ COMMITTED + upfront `FOR UPDATE` | 5 COMMITTED, 15 `SG003` | At COMMIT (the deferred check) | At most 1 writing transaction at any instant (peak 1); the others wait on the row lock (median 841 ms, max 1,713 ms). 0 `40001`, 0 `40P01` |
| `rc_nolock`: READ COMMITTED, no upfront lock (sleep between postings, or before COMMIT) | 5 COMMITTED, 15 `SG003` | At COMMIT | All 20 insert their intent and ledger rows first (20 concurrent writers). The first posting's `UPDATE mandate_balances` then serialises them (median wait 516–553 ms), and the lock is held until COMMIT, so the deferred `balance == SUM(postings)` check always reads a consistent state. No deadlock, no false `SG005`, no lost update |
| `ssi_noretry`: SERIALIZABLE, no lock | 1 COMMITTED, 19 `40001` | At the first posting (the balance-row update) | All 20 snapshots predate any write; once the first writer commits, every waiter fails |
| `ssi_retry`: SERIALIZABLE + retry with backoff and jitter | 5 COMMITTED, 15 `SG003` | `SG003` at COMMIT, after retries | 105 attempts, 85 `40001`. Attempts per session: one session each took 1, 2, 3, 4 and 5 attempts; 15 sessions took 6 |

The answer to "is the upfront lock needed for correctness?" is no: the database alone holds the
invariant under READ COMMITTED. The lock changes where contention is paid. Without it, losers do all
their writes and learn of the failure at COMMIT; with it, they queue before writing anything.

### 6.2 Fifty virtual threads: one hot mandate vs ten (`ConcurrencyStormTest`)

**Single mandate.** One mandate with a budget of 10,000 and a per-transaction cap of 2,000. 40
distinct spends of 1,000 each (demand is 4× the budget), plus 10 retries re-sending keys already in
use, half of them with a tampered payload. All 50 threads are released by one latch, and rail
latency is 5–15 ms so that check-then-act windows overlap.

Counts are ranges across twelve full runs. Latencies are from one run with migration `003`
applied, the same run the README quotes.

| Mode | Rail charged / budget | Invariant violations | `40001` retries | p50 / p95 / p99 (ms) |
|------|----------------------|----------------------|-----------------|---------------------:|
| `naive` | **34,996 – 49,995** / 10,000 | 14–24 per run (I1 ×3, I2 ×10–20, I3 ×1) | 0 | 171 / 193 / 197 |
| `hardened-pessimistic` | **10,000** / 10,000 every run | 0 | 0 | 1,816 / 3,067 / 3,196 |
| `hardened-ssi` | **9,997 – 10,000** / 10,000 | 0 | **637 – 865**, never exhausting the budget | 1,890 / 2,438 / 2,462 |

- **Why below 10,000:** tampered 999 requests won the race for their keys and became the stored
  requests, so the original 1,000s were rejected with 422. The ledger and the rail agree.
- **The worst `naive` run (49,995)** charged every duplicate retry as well.

**Ten mandates.** Ten engines, each with its own simulated rail and mandate (budget 10,000, cap
3,000), share one connection pool. Five threads per mandate spend 3,000 each, all 50 released by
one latch, so each mandate fits three spends and rejects two with `SG003`. Every run charged exactly
90,000 of 100,000, with 0 invariant violations and 0 `40P01` (asserted through `EngineMetrics`,
since the pessimistic mode retries deadlocks silently). Two runs before and three after migration
`003` (the third "after" run is the final `verify-all.sh --wide` run):

| Mode, schema | `40001` | p50 / p95 / p99 (ms) | `ledger_postings` seq / index scans |
|--------------|--------:|---------------------:|------------------------------------:|
| pessimistic, 001–002 | 0, 0 | 329 / 422 / 437; 313 / 382 / 386 | 79 / 78; 70 / 65 |
| pessimistic, with 003 | 0, 0, 0 | 341 / 455 / 492; 288 / 360 / 390; 301 / 382 / 408 | 11 / 117; 11 / 110; 11 / 154 |
| SSI, 001–002 | **1,121, 1,093** | 2,286 / 2,874 / 2,967; 1,991 / 2,646 / 2,716 | 613 / 664; 677 / 721 |
| SSI, with 003 | **521, 586, 438** | 1,014 / 1,242 / 1,295; 1,149 / 1,475 / 1,517; 1,007 / 1,228 / 1,269 | 10 / 536; 10 / 566; 10 / 524 |

The scan counters are `pg_stat_user_tables` deltas over the storm and its invariant check; the
check itself accounts for about 10 scans.

What the two tables show:

- **Pessimistic scales with independent mandates.** p50 drops from about 1.8 s on one hot row to
  about 0.3 s across ten.
- **SSI did not scale before `003`.** Ten mandates sharing no rows produced more serialization
  failures than fifty threads on one mandate.

The cause is the deferred integrity trigger's per-commit `SUM` over `ledger_postings WHERE
mandate_id = …`. Migration 001 has no index leading on `mandate_id`, so the query is a sequential
scan. Under SSI a sequential scan takes a relation-level SIREAD predicate lock, so every writer
of any posting conflicts with every other.

`003` adds `ledger_postings (mandate_id)`. Sequential scans fall to about 10 (the invariant check's
own reads), and cross-mandate `40001` and p50 roughly halve. The residual conflicts come from
page-granular predicate locks on a still-small index.

**What the latencies are.** They come from a laptop through Docker Desktop's network, and are not a
throughput benchmark; see section 10. Single-mandate pessimistic p50 varied between about 1.5 s and
2.0 s across runs, with and without `003`, because fifty writers queue on one balance row.

## 7. Faults: timeouts, crashes, network chaos

### Crash recovery

Every intent gets a recovery task in its Phase 1 transaction, and the transaction that settles the
intent completes it. `YakshaRecoverySweeper.sweepOnce()` works in three steps:

1. **Claim.** It claims due `PENDING` tasks, and `PROCESSING` tasks whose lease expired, with
   `FOR UPDATE SKIP LOCKED`, so concurrent sweepers never collide.
2. **Recover.** It runs Phase 3B outside any transaction.
3. **Record.** A task whose intent is now terminal becomes `COMPLETED`. Otherwise it is rescheduled
   with exponential backoff and jitter, or moved to `DEAD_LETTER` after `maxAttempts`, with the hold
   kept. The result is written only if the sweeper still holds the claim (same status and attempt
   number).

`StripeWireIntegrationTest` crashes requests after each step and recovers them:

| Crash point | Recovered to |
|-------------|--------------|
| After Phase 1 | `VOIDED` |
| After Step 2A | `VOIDED`, payment intent canceled |
| After Step 2B, rail charged | `CAPTURED` |
| Rail still `processing` | Stays held; dead-lettered after the attempt limit |

It also tests that the grace period is respected and that an expired lease is reclaimed.

### Network chaos (`ToxiproxyChaosTest`)

A real Toxiproxy 2.12 container sits between the Stripe HTTP adapter and the mock Stripe server.
"The rail applied the call but its response never arrived" is modelled as a `limit_data = 0` toxic
on the downstream direction. The mock answers `Connection: close`, so probabilistic toxics are
decided per call. Each scenario runs for both hardened modes in its own database, and each ends with
`InvariantChecker.assertHolds`.

| Scenario | Fault | Asserted |
|----------|-------|----------|
| (a) Cut after `/confirm` applied | Downstream `limit_data 0` during `/confirm` | The intent stays `CONFIRMING`, still holding its amount, while Stripe has charged. One `sweepOnce()` does one `GET`, never re-POSTs, and lands on `CAPTURED` with exact balances |
| (b) Cut after `/create` applied | The same toxic during `/create` | The intent stays `RESERVED` with no `pi` recorded. The sweeper voids it; the orphan stays `requires_confirmation` and is never charged (rail total 0, no `/confirm` ever sent) |
| (c) Degraded-network storm | 150–300 ms downstream latency; a 20 % per-connection TCP reset before delivery; a 10 % per-connection cut after apply. 20 virtual threads, 16 spends + 4 duplicates | Every recovery task completes while the network is still degraded; 0 violations; `settled == rail charged`; no key charged twice; the fault counter is positive (the chaos actually bit) |

One storm run, as printed:

```
hardened-pessimistic: CAPTURED=5 VOIDED=3 SG003=8 409=1 422=1 rail-unreachable=2,
                      8 rail calls failed, 2 sweep rounds, settled=5000 rail=5000 budget=10000
hardened-ssi:         CAPTURED=6 VOIDED=7 SG003=3 409=1 422=2 rail-unreachable=1,
                      9 rail calls failed, 1 sweep round,  settled=5998 rail=5998 budget=10000
```

Under faults the engine under-spends; it never overspends. A request whose confirm never reached
Stripe holds its budget until recovery voids it, and requests rejected with `SG003` during that
window are not retried by the test.

## 8. Capability mandates and quote drift (mudra)

A mandate is granted by an Ed25519 token signed with the JDK's built-in provider:

```
mudra1.<base64url(canonical claims)>.<base64url(signature)>
```

The claims are `mandate_id`, `agent_id`, `currency`, `total_budget_minor`, `max_per_tx_minor`,
`allowed_merchants`, `not_before`, `expires_at` and `token_kid`. Each field is encoded with a length
prefix under a domain tag, so the encoding is unambiguous. The allowlist is sorted and deduplicated,
and non-canonical encodings are rejected, so each grant has exactly one byte form. The key id is
inside the signed bytes.

A purchase is approved by a second Ed25519 token, signed by the approving party (the user, or an
approval service), never by the agent:

```
mudraq1.<base64url(canonical quote claims)>.<base64url(signature)>
```

The quote claims are `mandate_id`, `agent_id`, `idempotency_key`, `merchant_id`, `currency`,
`quoted_amount_minor`, `max_slippage_bps`, `expires_at` and `quote_kid`.

- **Shared encoding.** Both token types use `MudraCodec`: the same length-prefixed encoding and the
  same signature envelope, under different domain tags (`alaka-mudra-mandate-v1`,
  `alaka-mudra-quote-v1`). A mandate token relabelled as a quote does not verify.
- **Separate trust.** Quote keys form their own trust set (`alaka.mudra.trusted-quote-keys`), so a
  mandate issuer's key cannot approve purchases.
- **One approval, one purchase.** The quote is bound to `idempotency_key`, and
  `UNIQUE (agent_id, idempotency_key)` admits one intent per key. An approval can therefore
  authorise at most one intent, with no schema change.

`SpendGateway` runs, before any database statement:

- **Mandate token verification.** The signature must verify under a trusted issuer key, and the
  token must grant this mandate to this agent. Anything else raises `BadSignature`, `UnknownKey`,
  `MandateMismatch` or `MalformedToken`.
- **Quote token verification.** The signature must verify under a trusted approver key, and the
  quote must name this request's mandate, agent and idempotency key. Anything else raises
  `InvalidQuote` with a reason: `MALFORMED`, `UNKNOWN_KEY`, `BAD_SIGNATURE` or `MISMATCH`. An agent
  that raises `quoted_amount_minor` or `max_slippage_bps` breaks the signature; one that replays an
  approval under a new key gets `MISMATCH`.
- **Quote drift**, against the signed values. The merchant and currency must equal the quote's, the
  quote must be unexpired, and the amount must satisfy
  `amount × 10000 ≤ quoted × (10000 + max_slippage_bps)`. That is compared exactly, so there is no
  rounding: quote 10,000 with 50 bps accepts 10,050 and rejects 10,051; quote 999 with 50 bps
  accepts 1,003 and rejects 1,004.

A test with an engine that throws on any call proves that forged mandate tokens, tampered,
replayed or untrusted quotes, and drifted amounts never reach Postgres. The HTTP test also checks
the database afterwards and finds no intent.

The mandate verifier deliberately does not judge the validity window on the application clock.
Postgres checks it with `NOW()` on every reservation (I4), and issuers backdate `not_before` to
absorb clock skew between their clock and the database's.

## 9. HTTP surface

`dev.alaka.core.http.AlakaHttpController` is a thin translation layer that contains no business
rules. JSON is snake_case.

| Endpoint | Success | Errors |
|----------|---------|--------|
| `POST /v1/mandates` `{"token"}` | 201 | 422 invalid token; 409 already registered |
| `POST /v1/mandates/{id}/revoke` | 200 | 409 already terminal (SG004); 404 unknown |
| `POST /v1/spends` (header `X-Mudra-Token`; spend + `quote_token`) | 200 terminal; 202 still settling (rail `processing`, or recovery could not reach the rail) | 409 + `Retry-After` while in flight; 422 payload mismatch / mandate token / `InvalidQuote.<reason>` / `QuoteDrift.<reason>` / SG002; 402 SG003; 403 SG001 / SG008; 400 missing header or an unsigned `quote` object; 503 + `Retry-After` if serialization retries run out |
| `POST /v1/webhooks/stripe` | 200 `{"disposition": APPLIED / DUPLICATE / IGNORED}` | 400 missing, malformed, stale or wrong signature |

`AlakaHttpControllerTest` starts the real Spring Boot application against Postgres and the mock
Stripe server, and drives these flows over HTTP.

## 10. Scope and limitations

What the evidence covers, and what it does not:

- **TLC proofs are for finite instances:** two keys (three in the wide config), a budget of 10, and
  the amounts listed in section 4. The model does not cover:
  - the 422/409 responses;
  - expiry or suspension (only revocation);
  - the local `AUTHORIZED` / `FAILED` states;
  - a late Step 2A packet;
  - liveness.

  It also assumes two Stripe behaviours: that `/cancel` of a canceled payment intent fails, and that
  a failed `processing` ends cancelable.
- **Quotes are only as trustworthy as the approver's key.** The agent can no longer fabricate, edit
  or reuse an approval (section 8), but whoever holds a key in `alaka.mudra.trusted-quote-keys` can
  approve any purchase within the mandate. Key storage, rotation and revocation are not
  implemented.
- **Quote expiry is judged on the application clock**, before Phase 1. A retry of a completed
  request after its quote expired gets `422 QuoteDrift.QUOTE_EXPIRED` instead of the stored result.
- **Partial capture is verified but not reachable on Stripe.** The TLA+ model and the ledger kernel
  support `captured_amount_minor < authorized_amount_minor`, with the remainder returning to
  AVAILABLE, and the property suite drives it through `SimulatedPaymentRail`.
  `StripeHttpPaymentRail` sends `capture_method=automatic`, under which Stripe captures a card
  payment in full; the mock Stripe server refuses anything else. Reaching partial capture on Stripe
  needs three things, none implemented:
  - `capture_method=manual` and `/capture`;
  - an `AUTHORIZED` state in the protocol and the model, so recovery does not cancel an
    authorisation meant to be captured;
  - a persisted capture amount.
- **SSI keeps some false conflicts across mandates** even with the `003` index (438–586 `40001` in
  the ten-mandate storm), because predicate locks are page-granular. The pessimistic mode has none.
- **Bounded loss, not zero loss.** The guarantees bound what can go wrong; they do not make a
  compromised agent harmless:
  - A compromised agent with a valid mandate token and approvals from a trusted approver can still
    spend up to the mandate's budget at allowlisted merchants. I1 caps the damage at
    `total_budget_minor`.
  - A dead-lettered `processing` intent keeps its hold, so budget stays locked until a human or a
    later webhook resolves it. Locked, not lost.
  - Orphaned unconfirmed payment intents can accumulate on the rail. They can never charge, but
    nothing cancels them.
- **The rail is a mock in every automated test.** `StripeTestModeLiveTest` exercises the real Stripe
  test-mode API, but runs only when `STRIPE_TEST_KEY` is set. It was not run for the numbers in this
  document.
- **Faults are injected on the rail path only.** No Toxiproxy sits between the service and Postgres,
  and there is no `kill -9` of a running JVM. "Crash" means a request abandoned between phases, then
  resumed by the sweeper.
- **The latencies in section 6.2** come from a Windows 11 laptop running Docker Desktop (WSL2), at
  50 requests per run. They show relative behaviour, not capacity. No open-workload (k6) benchmark
  has been run.
- **Database backends can disagree about the time.** On the development host (Hyper-V / WSL2,
  clocksource `tsc`), backends of one PostgreSQL instance were caught reading clocks up to 278 ms
  apart. The evidence: a `clock_timestamp()` read *after* a mandate was committed came out earlier
  than that mandate's `not_before = NOW()`. The skew is intermittent; 300 back-to-back backends
  later showed none.

  Its effect was that a mandate created on one backend was occasionally "not yet valid" (SG001) for
  a reservation on another. It also made zero-grace recovery tasks not yet due for a sweeper on a
  lagging backend. The fixes:
  - immediately-valid mandates are stamped `not_before = NOW() - 5 s`
    (`NidhiLedger.CLOCK_SKEW_ALLOWANCE`), which grants nothing because the row did not exist before;
  - signed tokens backdate `not_before` themselves;
  - tests sweep until a task is due, and assert on `outbox_tasks.attempts`.

  A residual effect remains: mandate expiry and quote expiry are only as precise as the clocks
  involved. On such a host an expired mandate may be accepted for up to the skew (hundreds of
  milliseconds). The Milestone 1 attack suite still creates mandates with the column default
  `not_before = NOW()`, so it could in principle trip on this host.
- **The in-process sweeper** (`alaka.recovery.sweep-interval`) is a simple loop. Several instances
  are safe (`SKIP LOCKED`, leases), but there is no leader election and no metrics export.

## 11. Reproducing everything

Requirements: bash, Java 21+, and Docker with the compose plugin. `psql`, `mvn` and `make` are not
needed on the host.

```bash
bash scripts/verify-all.sh            # tla, sql, concurrency, java; summary in target-verify/summary.txt
bash scripts/verify-all.sh --wide     # also the 940,994-state TLC configuration
bash scripts/verify-all.sh sql concurrency   # selected steps
./mvnw -B clean verify                # Java only (Testcontainers starts its own Postgres and Toxiproxy)
make verify-all                       # same as the script, where make exists
```

The SQL steps use scratch databases named `alaka_verify_*` in the compose Postgres and never touch
the `alaka` development database. Benchmark output is in `target/storm-report.txt`, and CI
(`.github/workflows/verify.yml`) runs `verify-all.sh --wide` on every push and pull request to
`main`, uploading both as artifacts.
