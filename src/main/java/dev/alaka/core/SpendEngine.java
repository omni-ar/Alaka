package dev.alaka.core;

import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.nidhi.SignedMandateTerms;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPaymentIntent;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The execution coordinator: turns a {@link SpendRequest} into a reservation, a rail charge and a
 * settlement, in one of the three {@link RuntimeMode}s. Obtain instances from
 * {@link SpendEngines#create}.
 *
 * <p>Engines are thread-safe and hold no database transaction or row lock across a rail call.
 * Database rejections surface as {@link NidhiException} subtypes, idempotency rejections as
 * {@link IdempotencyException} subtypes.
 *
 * <p>The phase methods ({@link #reserve}, {@link #createOnRail}, {@link #confirmOnRail},
 * {@link #capture}, {@link #recoverOrVoid}) expose the three-phase protocol one step at a time so
 * that tests can interleave them and inject faults between them. They are implemented by the two
 * hardened modes; {@link RuntimeMode#NAIVE} implements only {@link #execute} and the read and
 * mandate methods, and throws {@link UnsupportedOperationException} from the phase methods.
 */
public interface SpendEngine {

    /**
     * Returns the mode this engine runs in.
     *
     * @return the runtime mode
     */
    RuntimeMode mode();

    /**
     * Creates an {@code ACTIVE} mandate with its three ledger accounts and full available budget.
     *
     * @param terms the mandate terms
     * @return the new mandate id
     */
    UUID createMandate(NewMandate terms);

    /**
     * Creates an {@code ACTIVE} mandate whose id and validity window were fixed by a verified
     * capability token. Validity is still judged by the database's {@code NOW()} on every
     * reservation (I4).
     *
     * @param terms the signed terms
     * @return the mandate id, {@code terms.mandateId()}
     * @throws NidhiException.UniqueViolation if a mandate with that id already exists
     */
    UUID createMandate(SignedMandateTerms terms);

    /**
     * Revokes a mandate. Irreversible (I4); reservations already made are unaffected and can
     * still be captured or voided.
     *
     * @param mandateId mandate to revoke
     * @param reason human-readable reason, stored with the mandate
     * @throws NidhiException.IllegalStateTransition if the mandate is already in a terminal state
     */
    void revokeMandate(UUID mandateId, String reason);

    /**
     * Phase 1: one local database transaction, no network I/O. Passes the idempotency gate, then
     * inserts the intent in {@code RESERVED} together with its {@code RESERVE} ledger transaction
     * and postings ({@code DEBIT MANDATE_AVAILABLE}, {@code CREDIT MANDATE_HELD}) and its recovery
     * task in {@code outbox_tasks}, and commits. The task falls due once the request has had the
     * engine's recovery grace period to finish; the transaction that settles the intent completes
     * it.
     *
     * <p>Idempotency gate, for an {@code (agentId, idempotencyKey)} that already exists, including
     * when the existing row was inserted by a concurrent request that won the race:
     * <ul>
     *   <li>different {@link SpendRequest#requestHash()}: {@link IdempotencyException.PayloadMismatch};
     *   <li>same hash, intent not terminal: {@link IdempotencyException.InFlight};
     *   <li>same hash, intent terminal: the stored intent with {@code replayed = true}.
     * </ul>
     *
     * @param request the spend request
     * @return the reserved intent, or the stored terminal intent of a replay
     * @throws IdempotencyException if the idempotency gate rejects the request
     * @throws NidhiException.MandateInactive if the mandate is revoked, suspended, expired, not
     *     yet valid or issued to another agent
     * @throws NidhiException.CurrencyMismatch if the currency differs from the mandate's
     * @throws NidhiException.MerchantNotAllowed if the merchant is not in the allowlist
     * @throws NidhiException.BudgetExceeded if the per-transaction cap or the available budget is
     *     exceeded
     */
    SpendResult reserve(SpendRequest request);

    /**
     * Phase 2A: outside any database transaction, creates the unconfirmed payment intent on the
     * rail with idempotency key {@code "create_" + intentId}, then records its id and advances
     * the intent {@code RESERVED -> CONFIRMING} in one short transaction. Idempotent: an intent
     * that is already {@code CONFIRMING} or beyond is returned unchanged.
     *
     * @param intentId gateway intent id
     * @return the intent after the call
     * @throws RailException.Timeout if the rail call's outcome is unknown; the intent is left
     *     {@code RESERVED} for {@link #recoverOrVoid}
     */
    IntentView createOnRail(UUID intentId);

    /**
     * Phase 2B: outside any database transaction, confirms the payment intent on the rail with
     * idempotency key {@code "confirm_" + intentId}. Does not touch the database; the caller
     * follows up with {@link #capture} or {@link #recoverOrVoid}.
     *
     * @param intentId gateway intent id, which must be {@code CONFIRMING}
     * @return the rail's view of the payment intent after the confirm
     * @throws IllegalStateException if the intent is not {@code CONFIRMING}
     * @throws RailException.Timeout if the rail call's outcome is unknown
     * @throws RailException.ConfirmRejected if the payment intent was already canceled
     */
    RailPaymentIntent confirmOnRail(UUID intentId);

    /**
     * Phase 3A: reads the payment intent from the rail and, if it {@code SUCCEEDED}, settles
     * exactly the amount the rail charged in one transaction: intent to {@code CAPTURED}, a
     * {@code CAPTURE} ledger transaction with {@code DEBIT MANDATE_HELD} for the authorised
     * amount, {@code CREDIT MANDATE_SETTLED} for the charged amount and, for a partial capture,
     * {@code CREDIT MANDATE_AVAILABLE} for the remainder. Idempotent: an intent that is already
     * {@code CAPTURED} is returned unchanged.
     *
     * @param intentId gateway intent id
     * @return the captured intent
     * @throws IllegalStateException if the rail has not charged the payment intent, or the intent
     *     is {@code VOIDED} or {@code FAILED}
     */
    IntentView capture(UUID intentId);

    /**
     * Phase 3B: resolves an intent whose outcome is unknown, never by blind-voiding.
     * <ul>
     *   <li>{@code RESERVED} with no rail payment intent recorded: void locally.
     *   <li>{@code CONFIRMING}: read the rail. {@code SUCCEEDED}: capture. {@code CANCELED}: void.
     *       {@code REQUIRES_CONFIRMATION}: cancel on the rail first and void only if the cancel
     *       succeeded; if it was rejected, read the rail again and capture if it succeeded.
     *       {@code PROCESSING}: change nothing, the hold stays locked.
     *   <li>terminal: returned unchanged.
     * </ul>
     * A void is one transaction: intent to {@code VOIDED} with a {@code VOID} ledger transaction
     * ({@code DEBIT MANDATE_HELD}, {@code CREDIT MANDATE_AVAILABLE}).
     *
     * @param intentId gateway intent id
     * @return the intent after recovery: {@code CAPTURED}, {@code VOIDED}, or still
     *     {@code CONFIRMING} while the rail is processing
     */
    IntentView recoverOrVoid(UUID intentId);

    /**
     * Applies a rail event whose authenticity the caller has verified (for Stripe, a webhook whose
     * {@code Stripe-Signature} checked out). The event id is recorded in
     * {@code processed_webhooks} in the same transaction that applies the event, so a replayed
     * event is a no-op and an event is never half-applied.
     * <ul>
     *   <li>{@code payment_intent.succeeded}: capture exactly the charged amount the event reports.
     *   <li>{@code payment_intent.canceled}: void.
     *   <li>{@code payment_intent.payment_failed}: the payment intent returns to a cancelable state,
     *       not to {@code canceled}, so voiding now would release a hold on a payment intent that
     *       could still be confirmed. The event is recorded, then {@link #recoverOrVoid} runs, which
     *       cancels on the rail before it voids.
     *   <li>any other type, or a payment intent no intent has recorded: recorded and ignored.
     * </ul>
     *
     * @param providerEventId the provider's event id ({@code evt_...})
     * @param eventType the event type
     * @param paymentIntent the payment intent as the event reports it
     * @return what was done
     */
    RailEventOutcome applyRailEvent(String providerEventId, String eventType, RailPaymentIntent paymentIntent);

    /**
     * Runs a request end to end. In the hardened modes: {@link #reserve}, {@link #createOnRail},
     * {@link #confirmOnRail}, then {@link #capture} if the rail succeeded; if a rail call fails or
     * its outcome is unknown, {@link #recoverOrVoid} is run once and its result returned; if the
     * rail is processing, the intent is returned still {@code CONFIRMING}.
     *
     * <p>In {@link RuntimeMode#NAIVE} this is the anti-pattern baseline: read the amount spent,
     * check the budget in application code, charge the rail, then record the spend, with no lock
     * held and no database-enforced conservation.
     *
     * @param request the spend request
     * @return the intent after the run, or the stored terminal intent of a replay
     * @throws IdempotencyException as for {@link #reserve}
     * @throws NidhiException as for {@link #reserve}
     */
    SpendResult execute(SpendRequest request);

    /**
     * Finds an intent by id.
     *
     * @param intentId gateway intent id
     * @return the intent, or empty if it does not exist
     */
    Optional<IntentView> findIntent(UUID intentId);

    /**
     * Finds an intent by its idempotency identity.
     *
     * @param agentId agent id
     * @param idempotencyKey idempotency key
     * @return the intent, or empty if the key has not been used by that agent
     */
    Optional<IntentView> findIntent(String agentId, String idempotencyKey);

    /**
     * Lists every intent of a mandate.
     *
     * @param mandateId mandate id
     * @return the mandate's intents, oldest first
     */
    List<IntentView> intentsOf(UUID mandateId);

    /**
     * Reads a mandate's budget buckets as this engine's mode accounts for them.
     *
     * @param mandateId mandate id
     * @return the current balances
     */
    MandateBalances balances(UUID mandateId);

    /**
     * Returns the counters accumulated since this engine was created.
     *
     * @return a snapshot of the engine's metrics
     */
    EngineMetrics metrics();
}
