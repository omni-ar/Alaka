--------------------------- MODULE AlakaInFlight ---------------------------
(***************************************************************************)
(* Alaka spend-reservation kernel: in-flight packet race, PROCESSING, and  *)
(* partial capture.                                                        *)
(*                                                                         *)
(* This module extends the verified baseline SpendGatewayInFlight          *)
(* (CLAUDE.md section 6, Artifact A).  Every baseline variable, action and *)
(* invariant is kept; the differences are listed here so a reviewer can    *)
(* diff the two by eye.                                                    *)
(*                                                                         *)
(* ADDED                                                                   *)
(*  - rail_pi_state gains "PROCESSING".  A confirm packet landing on a     *)
(*    CREATED PaymentIntent may move it to PROCESSING or straight to       *)
(*    SUCCEEDED.  PROCESSING later resolves to SUCCEEDED or to CANCELED.   *)
(*  - rail_charged[k]: the amount the rail actually charged for k (Stripe  *)
(*    amount_received).  It is chosen by the rail at the moment the PI     *)
(*    becomes SUCCEEDED and is either the full authorized amount or a      *)
(*    strictly smaller value from PartialCaptureAmounts.  It is 0 in every *)
(*    other rail state.  The rail-side total in I1 sums rail_charged, not  *)
(*    the authorized amount.                                               *)
(*  - intents[k].captured: the local captured_amount_minor column.         *)
(*    CommitCapture copies rail_charged[k] into it, settles exactly that   *)
(*    much, and releases (authorized - captured) back to bal_available in  *)
(*    the same step.                                                       *)
(*  - cancel_resp[k]: the rail's answer to the most recent explicit        *)
(*    POST /cancel for k ("OK" = 200, "REJECTED" = 400                     *)
(*    payment_intent_unexpected_state).                                    *)
(*  - RailHandleCancelRequest: the /cancel network call as its own step,   *)
(*    separate from the local void, so the rejection is an observable      *)
(*    event and the window between "rail canceled" and "locally voided"    *)
(*    is explored.                                                         *)
(*  - RailResolveProcessing: PROCESSING -> SUCCEEDED | CANCELED.           *)
(*  - BuggyVoidOnCancelFailure, gated by AllowVoidOnCancelFailure.         *)
(*  - MaxPerTx and the per-transaction cap guard in ReserveSpend (I1's     *)
(*    second clause).                                                      *)
(*  - Terminating: a stuttering step enabled only when no intent is open,  *)
(*    so that resting states are not reported as deadlocks (see the note   *)
(*    above Next).                                                         *)
(*                                                                         *)
(* CHANGED RELATIVE TO THE BASELINE                                        *)
(*  - The baseline invariant I2_ExactCaptureConsistency is kept but named  *)
(*    ExactCaptureConsistency: in CLAUDE.md, I2 is idempotency, which that *)
(*    predicate does not check.                                            *)
(*  - SumSucceededOnRail sums rail_charged instead of intents[k].amount.   *)
(*  - SafeCancelOnRailAndVoid is the baseline action verbatim (same guard, *)
(*    same effects); it additionally records cancel_resp = "OK" when it    *)
(*    cancels a CREATED PI.                                                *)
(*                                                                         *)
(* NOT MODELLED (so nothing here should be read as proving it)             *)
(*  - Request-hash mismatch (422) and concurrent-duplicate (409) handling  *)
(*    of I2.  One idempotency key is one index k; see I2 below for the     *)
(*    part that is checked.                                                *)
(*  - Mandate expiry, suspension, CONSUMED and the NOW() rule of I4.  Only *)
(*    revocation is modelled.                                              *)
(*  - The local AUTHORIZED and FAILED intent states.  "Rail SUCCEEDED,     *)
(*    intent still CONFIRMING" plays the role of AUTHORIZED.  FAILED has   *)
(*    the same ledger effect as VOIDED (HELD -> AVAILABLE) and is folded   *)
(*    into VOIDED.                                                         *)
(*  - Refunds.  I6 therefore reads "unrefunded succeeded charge" as "any   *)
(*    succeeded charge".                                                   *)
(*  - Individual ledger postings.  I3 is checked on the three bucket       *)
(*    totals, not on DEBIT/CREDIT rows.                                    *)
(*  - A non-atomic Phase 2A.  As in the baseline, CreateUnconfirmedPI      *)
(*    creates the PI on the rail and records pi_id locally in one step, so *)
(*    a late create packet is not explored.                                *)
(*  - Duplicate delivery of the confirm packet, and a second confirm with  *)
(*    a new payment method after a failed attempt.  A failed PROCESSING    *)
(*    attempt is modelled as ending directly in CANCELED (Stripe returns   *)
(*    card PIs to requires_payment_method, which is cancelable and which   *)
(*    nothing else in this protocol can move).                             *)
(*  - Liveness.  No fairness is assumed and no temporal "eventually"       *)
(*    property is checked; only safety.                                    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    IdempKeys,                   \* e.g., {"k1", "k2"}
    Amounts,                     \* amounts an agent may request, e.g., {4, 6, 7}
    MandateBudget,               \* e.g., 10
    MaxPerTx,                    \* per-transaction cap (max_per_tx_minor), e.g., 6
    PartialCaptureAmounts,       \* amounts the rail may charge instead of the full
                                 \* authorized amount (only values strictly between
                                 \* 0 and the authorized amount are ever used)
    AllowBlindVoidWithoutCancel, \* BOOLEAN: TRUE reproduces the in-flight overspend
    AllowVoidOnCancelFailure     \* BOOLEAN: TRUE lets recovery void although /cancel
                                 \* was rejected and the PI is PROCESSING

ASSUME
    /\ IdempKeys # {}
    /\ IsFiniteSet(IdempKeys)
    /\ \A a \in Amounts : a \in Nat /\ a > 0
    /\ \A c \in PartialCaptureAmounts : c \in Nat
    /\ MandateBudget \in Nat
    /\ MaxPerTx \in Nat
    /\ AllowBlindVoidWithoutCancel \in BOOLEAN
    /\ AllowVoidOnCancelFailure \in BOOLEAN

VARIABLES
    mandate_status,     \* "ACTIVE" | "REVOKED"
    bal_available,      \* Integer
    bal_held,           \* Integer
    bal_settled,        \* Integer
    intents,            \* [k -> [state: {"NONE","RESERVED","CONFIRMING","CAPTURED","VOIDED"},
                        \*        amount: Int, captured: Int]]
    wire_confirm,       \* [k -> "NONE" | "IN_FLIGHT" | "DELIVERED"]
    rail_pi_state,      \* [k -> "NONE" | "CREATED" | "PROCESSING" | "SUCCEEDED" | "CANCELED"]
    rail_charged,       \* [k -> Int]  amount the rail actually charged (0 unless SUCCEEDED)
    cancel_resp         \* [k -> "NONE" | "OK" | "REJECTED"]  last /cancel response

vars == <<mandate_status, bal_available, bal_held, bal_settled, intents,
          wire_confirm, rail_pi_state, rail_charged, cancel_resp>>

IntentStates == {"NONE", "RESERVED", "CONFIRMING", "CAPTURED", "VOIDED"}
RailStates   == {"NONE", "CREATED", "PROCESSING", "SUCCEEDED", "CANCELED"}

\* What the rail may charge for a PI authorized for amt: all of it, or a
\* strictly partial amount.
RailChargeChoices(amt) ==
    {amt} \cup {c \in PartialCaptureAmounts : c > 0 /\ c < amt}

Init ==
    /\ mandate_status = "ACTIVE"
    /\ bal_available = MandateBudget
    /\ bal_held = 0
    /\ bal_settled = 0
    /\ intents = [k \in IdempKeys |-> [state |-> "NONE", amount |-> 0, captured |-> 0]]
    /\ wire_confirm = [k \in IdempKeys |-> "NONE"]
    /\ rail_pi_state = [k \in IdempKeys |-> "NONE"]
    /\ rail_charged = [k \in IdempKeys |-> 0]
    /\ cancel_resp = [k \in IdempKeys |-> "NONE"]

-----------------------------------------------------------------------------
(* Phase 1: local reservation.                                             *)

ReserveSpend(k, amt) ==
    /\ amt \in Amounts
    /\ amt <= MaxPerTx
    /\ intents[k].state = "NONE"
    /\ mandate_status = "ACTIVE"
    /\ bal_available >= amt
    /\ bal_available' = bal_available - amt
    /\ bal_held' = bal_held + amt
    /\ intents' = [intents EXCEPT ![k] = [state |-> "RESERVED", amount |-> amt, captured |-> 0]]
    /\ UNCHANGED <<mandate_status, bal_settled, wire_confirm, rail_pi_state,
                   rail_charged, cancel_resp>>

(* Phase 2A: create the unconfirmed PI and record pi_id.                   *)

CreateUnconfirmedPI(k) ==
    /\ intents[k].state = "RESERVED"
    /\ rail_pi_state[k] = "NONE"
    /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "CREATED"]
    /\ intents' = [intents EXCEPT ![k].state = "CONFIRMING"]
    /\ UNCHANGED <<mandate_status, bal_available, bal_held, bal_settled, wire_confirm,
                   rail_charged, cancel_resp>>

(* Phase 2B: the confirm packet leaves the gateway.  From here on it may   *)
(* land at the rail at any later time, whatever the gateway does meanwhile.*)

SendConfirmPacket(k) ==
    /\ intents[k].state = "CONFIRMING"
    /\ wire_confirm[k] = "NONE"
    /\ wire_confirm' = [wire_confirm EXCEPT ![k] = "IN_FLIGHT"]
    /\ UNCHANGED <<mandate_status, bal_available, bal_held, bal_settled, intents,
                   rail_pi_state, rail_charged, cancel_resp>>

(* The confirm packet lands.  On a CREATED PI the rail either starts       *)
(* PROCESSING or succeeds at once, charging an amount of its choosing.  On *)
(* any other PI state (in particular CANCELED) the packet has no effect.   *)

RailReceiveConfirmPacket(k) ==
    /\ wire_confirm[k] = "IN_FLIGHT"
    /\ wire_confirm' = [wire_confirm EXCEPT ![k] = "DELIVERED"]
    /\ IF rail_pi_state[k] = "CREATED"
       THEN \/ /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "PROCESSING"]
               /\ UNCHANGED rail_charged
            \/ \E c \in RailChargeChoices(intents[k].amount) :
                  /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "SUCCEEDED"]
                  /\ rail_charged' = [rail_charged EXCEPT ![k] = c]
       ELSE UNCHANGED <<rail_pi_state, rail_charged>>
    /\ UNCHANGED <<mandate_status, bal_available, bal_held, bal_settled, intents,
                   cancel_resp>>

(* The rail finishes PROCESSING: it either charges (full or partial) or    *)
(* the attempt ends without moving money.                                  *)

RailResolveProcessing(k) ==
    /\ rail_pi_state[k] = "PROCESSING"
    /\ \/ \E c \in RailChargeChoices(intents[k].amount) :
             /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "SUCCEEDED"]
             /\ rail_charged' = [rail_charged EXCEPT ![k] = c]
       \/ /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "CANCELED"]
          /\ UNCHANGED rail_charged
    /\ UNCHANGED <<mandate_status, bal_available, bal_held, bal_settled, intents,
                   wire_confirm, cancel_resp>>

(* Phase 3A: local capture.  The guard reads the rail state (GET, the      *)
(* Phase 2B response, or a verified webhook).  Reading it in the same step *)
(* is sound because SUCCEEDED is terminal on the rail and rail_charged is  *)
(* fixed once set (checked by RailMonotonic and I2 below).                 *)
(* Settles exactly what the rail charged and releases the remainder.       *)

CommitCapture(k) ==
    /\ intents[k].state \in {"RESERVED", "CONFIRMING"}
    /\ rail_pi_state[k] = "SUCCEEDED"
    /\ LET amt == intents[k].amount
           cap == rail_charged[k]
       IN
        /\ bal_held' = bal_held - amt
        /\ bal_settled' = bal_settled + cap
        /\ bal_available' = bal_available + (amt - cap)
        /\ intents' = [intents EXCEPT ![k].state = "CAPTURED", ![k].captured = cap]
        /\ UNCHANGED <<mandate_status, wire_confirm, rail_pi_state, rail_charged,
                       cancel_resp>>

(* Phase 3B step 4: POST /cancel reaches the rail.  The recovery worker    *)
(* may send it at any time for an intent that has a pi_id and is not yet   *)
(* terminal; its earlier GET may be stale, so the rail decides.  Only a PI *)
(* that has not started confirming is cancelable.  PROCESSING, SUCCEEDED   *)
(* and already-CANCELED PIs answer 400 and are left untouched.             *)
(* A lost response needs no separate action: no safe action reads          *)
(* cancel_resp, they read the rail state.                                  *)

RailHandleCancelRequest(k) ==
    /\ intents[k].state = "CONFIRMING"
    /\ IF rail_pi_state[k] = "CREATED"
       THEN /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "CANCELED"]
            /\ cancel_resp' = [cancel_resp EXCEPT ![k] = "OK"]
       ELSE /\ cancel_resp' = [cancel_resp EXCEPT ![k] = "REJECTED"]
            /\ UNCHANGED rail_pi_state
    /\ UNCHANGED <<mandate_status, bal_available, bal_held, bal_settled, intents,
                   wire_confirm, rail_charged>>

(* Baseline action, guard unchanged.  It covers three safe voids:          *)
(*   rail NONE     - intent stuck in RESERVED, no confirm was ever sent;   *)
(*   rail CREATED  - cancel succeeds and the void commits (the two-step    *)
(*                   version of this is RailHandleCancelRequest followed   *)
(*                   by this action from rail CANCELED);                   *)
(*   rail CANCELED - GET shows canceled, including after PROCESSING ended  *)
(*                   in CANCELED.                                          *)
(* It is NOT enabled while the rail is PROCESSING or SUCCEEDED: that is    *)
(* the "keep CONFIRMING with bal_held locked" rule.                        *)

SafeCancelOnRailAndVoid(k) ==
    /\ intents[k].state \in {"RESERVED", "CONFIRMING"}
    /\ rail_pi_state[k] \in {"NONE", "CREATED", "CANCELED"}
    /\ rail_pi_state' = [rail_pi_state EXCEPT ![k] = "CANCELED"]
    /\ cancel_resp' = IF rail_pi_state[k] = "CREATED"
                      THEN [cancel_resp EXCEPT ![k] = "OK"]
                      ELSE cancel_resp
    /\ bal_held' = bal_held - intents[k].amount
    /\ bal_available' = bal_available + intents[k].amount
    /\ intents' = [intents EXCEPT ![k].state = "VOIDED"]
    /\ UNCHANGED <<mandate_status, bal_settled, wire_confirm, rail_charged>>

(* BUG 1 (baseline): void locally on a stale "not charged yet" reading,    *)
(* without cancelling on the rail, while the confirm packet may still land.*)

BuggyVoidWhilePacketInFlight(k) ==
    /\ AllowBlindVoidWithoutCancel = TRUE
    /\ intents[k].state = "CONFIRMING"
    /\ rail_pi_state[k] = "CREATED"
    /\ bal_held' = bal_held - intents[k].amount
    /\ bal_available' = bal_available + intents[k].amount
    /\ intents' = [intents EXCEPT ![k].state = "VOIDED"]
    /\ UNCHANGED <<mandate_status, bal_settled, wire_confirm, rail_pi_state,
                   rail_charged, cancel_resp>>

(* BUG 2: /cancel was rejected, the PI is PROCESSING, and the recovery     *)
(* worker voids locally anyway instead of keeping bal_held locked.  The    *)
(* guard requires the rail to be PROCESSING at the moment of the void, so  *)
(* the bug is shown even when the worker's view of the rail is fresh.      *)

BuggyVoidOnCancelFailure(k) ==
    /\ AllowVoidOnCancelFailure = TRUE
    /\ intents[k].state = "CONFIRMING"
    /\ cancel_resp[k] = "REJECTED"
    /\ rail_pi_state[k] = "PROCESSING"
    /\ bal_held' = bal_held - intents[k].amount
    /\ bal_available' = bal_available + intents[k].amount
    /\ intents' = [intents EXCEPT ![k].state = "VOIDED"]
    /\ UNCHANGED <<mandate_status, bal_settled, wire_confirm, rail_pi_state,
                   rail_charged, cancel_resp>>

RevokeMandate ==
    /\ mandate_status = "ACTIVE"
    /\ mandate_status' = "REVOKED"
    /\ UNCHANGED <<bal_available, bal_held, bal_settled, intents, wire_confirm,
                   rail_pi_state, rail_charged, cancel_resp>>

(* Deadlock handling.  A state with no open intent (every intent NONE,     *)
(* CAPTURED or VOIDED) is a legitimate resting point, so it may stutter;   *)
(* without this step TLC reports a deadlock as soon as the mandate is      *)
(* revoked with nothing in flight.  TLC's deadlock check stays ON in every *)
(* cfg, but it is NOT what detects a stuck in-flight intent: a CONFIRMING  *)
(* intent can always repeat a /cancel request, which TLC counts as a       *)
(* successor.  That check is the invariant OpenIntentCanAlwaysProgress.    *)

Terminating ==
    /\ \A k \in IdempKeys : intents[k].state \in {"NONE", "CAPTURED", "VOIDED"}
    /\ UNCHANGED vars

Next ==
    \/ RevokeMandate
    \/ \E k \in IdempKeys, a \in Amounts : ReserveSpend(k, a)
    \/ \E k \in IdempKeys :
        \/ CreateUnconfirmedPI(k)
        \/ SendConfirmPacket(k)
        \/ RailReceiveConfirmPacket(k)
        \/ RailResolveProcessing(k)
        \/ CommitCapture(k)
        \/ RailHandleCancelRequest(k)
        \/ SafeCancelOnRailAndVoid(k)
        \/ BuggyVoidWhilePacketInFlight(k)
        \/ BuggyVoidOnCancelFailure(k)
    \/ Terminating

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Helpers.                                                                *)

RECURSIVE SumFn(_, _)
SumFn(f, S) == IF S = {} THEN 0
               ELSE LET x == CHOOSE v \in S : TRUE
                    IN f[x] + SumFn(f, S \ {x})

AuthorizedAmt == [k \in IdempKeys |-> intents[k].amount]
CapturedAmt   == [k \in IdempKeys |-> intents[k].captured]

\* Total actually charged on the rail across all succeeded PIs.
SumSucceededOnRail ==
    SumFn(rail_charged, {k \in IdempKeys : rail_pi_state[k] = "SUCCEEDED"})

-----------------------------------------------------------------------------
(* State invariants.                                                       *)

TypeOK ==
    /\ mandate_status \in {"ACTIVE", "REVOKED"}
    /\ bal_available \in 0..MandateBudget
    /\ bal_held \in 0..MandateBudget
    /\ bal_settled \in 0..MandateBudget
    /\ intents \in [IdempKeys -> [state : IntentStates,
                                  amount : Amounts \cup {0},
                                  captured : 0..MaxPerTx]]
    /\ wire_confirm \in [IdempKeys -> {"NONE", "IN_FLIGHT", "DELIVERED"}]
    /\ rail_pi_state \in [IdempKeys -> RailStates]
    /\ rail_charged \in [IdempKeys -> 0..MaxPerTx]
    /\ cancel_resp \in [IdempKeys -> {"NONE", "OK", "REJECTED"}]
    \* Well-formedness tying the amount fields to the state fields.
    /\ \A k \in IdempKeys :
        /\ (intents[k].state = "NONE") <=> (intents[k].amount = 0)
        /\ (intents[k].state = "CAPTURED") <=> (intents[k].captured > 0)
        /\ (rail_pi_state[k] = "SUCCEEDED") <=> (rail_charged[k] > 0)

\* I1: neither the local ledger nor the rail exceeds the budget, and no
\* intent exceeds the per-transaction cap.
I1_NoMandateOverspent ==
    /\ bal_available >= 0
    /\ bal_held >= 0
    /\ (bal_held + bal_settled) <= MandateBudget
    /\ SumSucceededOnRail <= MandateBudget
    /\ \A k \in IdempKeys : intents[k].amount <= MaxPerTx

\* Baseline I2_ExactCaptureConsistency, renamed (see header) and extended:
\* a CAPTURED intent has a SUCCEEDED PI, and the locally settled amount is
\* exactly what the rail charged, which is positive and at most the
\* authorized amount.
ExactCaptureConsistency ==
    \A k \in IdempKeys :
        (intents[k].state = "CAPTURED") =>
            /\ rail_pi_state[k] = "SUCCEEDED"
            /\ intents[k].captured = rail_charged[k]
            /\ intents[k].captured > 0
            /\ intents[k].captured <= intents[k].amount

\* I3 on the three bucket totals: conservation and non-negativity.
I3_LedgerConservation ==
    /\ bal_available + bal_held + bal_settled = MandateBudget
    /\ bal_available >= 0
    /\ bal_held >= 0
    /\ bal_settled >= 0

\* Stronger than I3: the buckets agree with the intents, so no budget is
\* stranded.  bal_held is exactly the authorized amounts of open intents and
\* bal_settled is exactly the captured amounts.  A partial capture that kept
\* its remainder in HELD, or dropped it, violates this.
LedgerMatchesIntents ==
    /\ bal_held = SumFn(AuthorizedAmt,
                        {k \in IdempKeys : intents[k].state \in {"RESERVED", "CONFIRMING"}})
    /\ bal_settled = SumFn(CapturedAmt,
                           {k \in IdempKeys : intents[k].state = "CAPTURED"})

\* I6 (baseline): no VOIDED intent has a succeeded charge on the rail.
I6_NoSilentRailDrift ==
    \A k \in IdempKeys :
        (intents[k].state = "VOIDED") => (rail_pi_state[k] # "SUCCEEDED")

(* The four invariants below are listed in the safe cfg only.  The first   *)
(* three are stronger than I1 and I6: they state the reason the safe       *)
(* protocol works.  Each unsafe behaviour violates them: the first two at  *)
(* the buggy void step itself, the third before the rail total exceeds the *)
(* budget.  They are left out of the unsafe cfgs so that those             *)
(* counterexamples are reported against the CLAUDE.md invariants, as in    *)
(* the baseline.                                                           *)

\* While the rail is PROCESSING the intent is still CONFIRMING, hence (by
\* LedgerMatchesIntents) its amount is still locked in bal_held.
ProcessingKeepsHeldLocked ==
    \A k \in IdempKeys :
        (rail_pi_state[k] = "PROCESSING") => (intents[k].state = "CONFIRMING")

\* A VOIDED intent's PI is CANCELED on the rail, so it can never succeed
\* later.  I6 only says it has not succeeded yet.
VoidedOnlyAfterRailCanceled ==
    \A k \in IdempKeys :
        (intents[k].state = "VOIDED") => (rail_pi_state[k] = "CANCELED")

\* Look-ahead form of I1: even if every PI that can still succeed (CREATED
\* or PROCESSING) were charged in full, the rail total stays within budget.
RailWorstCaseExposureWithinBudget ==
    LET Exposure == [k \in IdempKeys |->
                        IF rail_pi_state[k] = "SUCCEEDED"
                        THEN rail_charged[k]
                        ELSE intents[k].amount]
    IN SumFn(Exposure,
             {k \in IdempKeys : rail_pi_state[k] \in {"CREATED", "PROCESSING", "SUCCEEDED"}})
       <= MandateBudget

\* No stuck in-flight intent: every open intent has an enabled step that
\* moves it, its packet or its PI forward.  Repeating a /cancel request does
\* not count.  This is a possibility check in each reachable state, not a
\* liveness proof (no fairness is assumed).
AdvanceStep(k) ==
    \/ CreateUnconfirmedPI(k)
    \/ SendConfirmPacket(k)
    \/ RailReceiveConfirmPacket(k)
    \/ RailResolveProcessing(k)
    \/ CommitCapture(k)
    \/ SafeCancelOnRailAndVoid(k)

OpenIntentCanAlwaysProgress ==
    \A k \in IdempKeys :
        (intents[k].state \in {"RESERVED", "CONFIRMING"}) => ENABLED AdvanceStep(k)

-----------------------------------------------------------------------------
(* Transition properties.  These are [][A]_vars formulas and must be       *)
(* listed under PROPERTIES in the cfg, not INVARIANTS.                     *)

\* I5: intents only move forward and terminal intents are frozen.
\* RESERVED -> CAPTURED is deliberately absent although CommitCapture's
\* baseline guard would permit it: TLC confirms it never happens.
IntentTransitions ==
    { <<"NONE", "RESERVED">>,
      <<"RESERVED", "CONFIRMING">>,
      <<"RESERVED", "VOIDED">>,
      <<"CONFIRMING", "CAPTURED">>,
      <<"CONFIRMING", "VOIDED">> }

I5_MonotonicStateMachine ==
    [][\A k \in IdempKeys :
          /\ \/ intents'[k].state = intents[k].state
             \/ <<intents[k].state, intents'[k].state>> \in IntentTransitions
          /\ (intents[k].state \in {"CAPTURED", "VOIDED"}) => (intents'[k] = intents[k])
      ]_vars

\* The rail's own state machine: SUCCEEDED and CANCELED are terminal.  This
\* is what justifies the local actions reading those two states atomically.
RailTransitions ==
    { <<"NONE", "CREATED">>,
      <<"NONE", "CANCELED">>,
      <<"CREATED", "PROCESSING">>,
      <<"CREATED", "SUCCEEDED">>,
      <<"CREATED", "CANCELED">>,
      <<"PROCESSING", "SUCCEEDED">>,
      <<"PROCESSING", "CANCELED">> }

RailMonotonic ==
    [][\A k \in IdempKeys :
          \/ rail_pi_state'[k] = rail_pi_state[k]
          \/ <<rail_pi_state[k], rail_pi_state'[k]>> \in RailTransitions
      ]_vars

\* I2, the part this model can express: per idempotency key there is at
\* most one reservation, at most one confirm packet, and at most one charge.
\*  - once a key has an intent, it never returns to NONE and its authorized
\*    amount never changes (a replay cannot reserve again or alter it);
\*  - the confirm packet for a key is sent at most once (wire_confirm never
\*    moves backwards);
\*  - the charged amount is set at most once and never changes afterwards.
\* The 422 payload-mismatch and 409 in-flight-duplicate responses are not
\* modelled.
I2_OneReservationAndOneChargePerKey ==
    [][\A k \in IdempKeys :
          /\ (intents[k].state # "NONE") =>
                /\ intents'[k].state # "NONE"
                /\ intents'[k].amount = intents[k].amount
          /\ (wire_confirm[k] = "IN_FLIGHT") => (wire_confirm'[k] \in {"IN_FLIGHT", "DELIVERED"})
          /\ (wire_confirm[k] = "DELIVERED") => (wire_confirm'[k] = "DELIVERED")
          /\ (rail_charged'[k] # rail_charged[k]) => (rail_charged[k] = 0)
      ]_vars

\* I4, the part this model can express: revocation is irreversible, and a
\* REVOKED mandate never authorizes a new reservation (no intent leaves
\* NONE and bal_held never grows).  Intents reserved before the revocation
\* may still be captured or voided; that is intended.  Expiry, suspension
\* and database-time checks are not modelled.
I4_RevokedMandateReservesNothing ==
    [][(mandate_status = "REVOKED") =>
          /\ mandate_status' = "REVOKED"
          /\ bal_held' <= bal_held
          /\ \A k \in IdempKeys :
                (intents[k].state = "NONE") => (intents'[k].state = "NONE")
      ]_vars

-----------------------------------------------------------------------------
(* REACHABILITY PROBES.  Each one claims that something interesting NEVER  *)
(* happens, and each is EXPECTED TO BE VIOLATED in the safe model: the     *)
(* counterexample TLC prints is a witness that the behaviour is reachable, *)
(* so the invariants above are not holding vacuously.  They are used only  *)
(* by the cfgs in spec/probes/ and must never appear in a real cfg.        *)

Probe_NeverProcessing ==
    \A k \in IdempKeys : rail_pi_state[k] # "PROCESSING"

\* /cancel rejected while the PI is PROCESSING and the intent stays CONFIRMING.
Probe_NeverCancelRejectedWhileProcessing ==
    \A k \in IdempKeys :
        ~ ( /\ cancel_resp[k] = "REJECTED"
            /\ rail_pi_state[k] = "PROCESSING"
            /\ intents[k].state = "CONFIRMING" )

\* Captured after a rejected cancel (the "re-fetch, succeeded, capture" path).
Probe_NeverCapturedAfterCancelRejected ==
    \A k \in IdempKeys :
        ~ (cancel_resp[k] = "REJECTED" /\ intents[k].state = "CAPTURED")

\* Voided after some /cancel for k was rejected.  The rejection may have been
\* for a PROCESSING PI or for one that was already CANCELED; this state
\* predicate cannot tell which.
Probe_NeverVoidedAfterCancelRejected ==
    \A k \in IdempKeys :
        ~ (cancel_resp[k] = "REJECTED" /\ intents[k].state = "VOIDED")

\* PROCESSING ended in CANCELED with no cancel request ever made for k.
Probe_NeverProcessingEndsCanceled ==
    \A k \in IdempKeys :
        ~ ( /\ rail_pi_state[k] = "CANCELED"
            /\ wire_confirm[k] = "DELIVERED"
            /\ cancel_resp[k] = "NONE"
            /\ intents[k].state = "CONFIRMING" )

\* ... and the intent is then voided.  With the packet DELIVERED and no
\* cancel request ever made for k, the only way the PI can be CANCELED is
\* PROCESSING -> CANCELED, so this witnesses "held through PROCESSING, voided
\* only after the rail reached CANCELED".
Probe_NeverVoidedAfterProcessingEndsCanceled ==
    \A k \in IdempKeys :
        ~ ( /\ intents[k].state = "VOIDED"
            /\ wire_confirm[k] = "DELIVERED"
            /\ cancel_resp[k] = "NONE" )

Probe_NeverPartialCapture ==
    \A k \in IdempKeys :
        ~ (intents[k].state = "CAPTURED" /\ intents[k].captured < intents[k].amount)

Probe_NeverFullCapture ==
    \A k \in IdempKeys :
        ~ (intents[k].state = "CAPTURED" /\ intents[k].captured = intents[k].amount)

Probe_NeverVoided ==
    \A k \in IdempKeys : intents[k].state # "VOIDED"

\* The central race, safe side: voided while the confirm packet is still in
\* flight (it will land on a CANCELED PI).
Probe_NeverVoidedWithPacketInFlight ==
    \A k \in IdempKeys :
        ~ (intents[k].state = "VOIDED" /\ wire_confirm[k] = "IN_FLIGHT")

\* A released partial-capture remainder is actually re-spendable: every key
\* captured although their authorized amounts sum to more than the budget.
Probe_NeverAllCapturedBeyondAuthorizedBudget ==
    ~ ( /\ \A k \in IdempKeys : intents[k].state = "CAPTURED"
        /\ SumFn(AuthorizedAmt, IdempKeys) > MandateBudget )

\* Two intents open at the same time.
Probe_NeverTwoOpenIntents ==
    Cardinality({k \in IdempKeys : intents[k].state \in {"RESERVED", "CONFIRMING"}}) < 2

\* An intent reserved before revocation is captured after it.
Probe_NeverCapturedAfterRevocation ==
    ~ (mandate_status = "REVOKED" /\ \E k \in IdempKeys : intents[k].state = "CAPTURED")

\* Transition probe (list under PROPERTIES): shows TLC really evaluates
\* [][A]_vars properties on this spec.
Probe_NoConfirmingToVoidedStep ==
    [][\A k \in IdempKeys :
          ~ (intents[k].state = "CONFIRMING" /\ intents'[k].state = "VOIDED")
      ]_vars
=============================================================================
