package dev.alaka.core;

import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.nidhi.NidhiLedger;
import dev.alaka.nidhi.SignedMandateTerms;
import dev.alaka.nidhi.TransactionRunner;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The two hardened modes, which share the three-phase protocol and differ only in concurrency
 * control.
 *
 * <ul>
 *   <li>{@link RuntimeMode#HARDENED_PESSIMISTIC}: {@code READ COMMITTED}; every money-moving
 *       transaction first locks the mandate's balance row {@code FOR UPDATE} (after the mandate
 *       {@code FOR SHARE} in Phase 1), so writers on one mandate queue up and never conflict.
 *   <li>{@link RuntimeMode#HARDENED_SSI}: {@code SERIALIZABLE}, and deliberately no explicit
 *       balance lock: the point of the mode is optimistic concurrency, where conflicting writers
 *       are detected by the database ({@code 40001}) and the whole transaction is retried with
 *       backoff and jitter. Taking the lock as well would make it the pessimistic mode at a higher
 *       isolation level. The intent row is still locked {@code FOR UPDATE} in Phases 2A, 3A and
 *       3B; that lock is per intent and only orders the steps of one request.
 * </ul>
 *
 * <p>Structure of every public operation: database work happens only inside
 * {@link TransactionRunner#inTransaction} lambdas, which receive a connection and nothing else;
 * rail calls happen only between them, through {@link RailCallGuard}, which fails if a
 * transaction is open on the thread.
 */
final class HardenedSpendEngine implements SpendEngine {

    private static final Duration IN_FLIGHT_RETRY_AFTER = Duration.ofSeconds(1);
    private static final int IDEMPOTENCY_RACE_ATTEMPTS = 3;

    private final RuntimeMode mode;
    private final TransactionRunner tx;
    private final NidhiLedger ledger = new NidhiLedger();
    private final PaymentRailPort rail;
    private final boolean lockBalances;
    private final long recoveryGraceMillis;

    HardenedSpendEngine(RuntimeMode mode, TransactionRunner tx, PaymentRailPort rail, EngineOptions options) {
        if (mode == RuntimeMode.NAIVE) {
            throw new IllegalArgumentException("HardenedSpendEngine does not implement " + mode);
        }
        this.mode = mode;
        this.tx = Objects.requireNonNull(tx, "tx");
        this.rail = new RailCallGuard(rail);
        this.lockBalances = mode == RuntimeMode.HARDENED_PESSIMISTIC;
        this.recoveryGraceMillis = options.recoveryGrace().toMillis();
    }

    @Override
    public RuntimeMode mode() {
        return mode;
    }

    @Override
    public UUID createMandate(NewMandate terms) {
        return tx.inTransaction(c -> ledger.insertMandate(c, terms));
    }

    @Override
    public UUID createMandate(SignedMandateTerms terms) {
        tx.inTransaction(c -> {
            ledger.insertSignedMandate(c, terms);
            return null;
        });
        return terms.mandateId();
    }

    @Override
    public void revokeMandate(UUID mandateId, String reason) {
        String before = tx.inTransaction(c -> ledger.revokeMandate(c, mandateId, reason))
                .orElseThrow(() -> new IllegalArgumentException("Unknown mandate " + mandateId));
        if (!before.equals("ACTIVE") && !before.equals("SUSPENDED")) {
            throw new NidhiException.IllegalStateTransition(
                    "Mandate " + mandateId + " is already " + before + "; terminal mandate states are irreversible",
                    null);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Phase 1
    // ---------------------------------------------------------------------------------------

    @Override
    public SpendResult reserve(SpendRequest request) {
        Objects.requireNonNull(request, "request");
        String requestHash = request.requestHash();
        for (int attempt = 1; ; attempt++) {
            try {
                return tx.inTransaction(c -> reserveOnce(c, request, requestHash));
            } catch (NidhiException.UniqueViolation e) {
                // A concurrent first-time request with the same (agent_id, idempotency_key) committed
                // between our gate read and our insert. Run the transaction again: the gate now
                // sees the winner's row and answers 409 / 422 / replay.
                if (attempt >= IDEMPOTENCY_RACE_ATTEMPTS) {
                    throw e;
                }
            }
        }
    }

    private SpendResult reserveOnce(Connection c, SpendRequest request, String requestHash) throws SQLException {
        Optional<IntentView> existing = ledger.findIntent(c, request.agentId(), request.idempotencyKey());
        if (existing.isPresent()) {
            return idempotencyGate(existing.get(), requestHash);
        }
        if (ledger.findMandate(c, request.mandateId(), true).isEmpty()) {
            throw new IllegalArgumentException("Unknown mandate " + request.mandateId());
        }
        if (lockBalances) {
            ledger.lockBalances(c, request.mandateId());
        }
        IntentView intent = new IntentView(
                UUID.randomUUID(),
                request.mandateId(),
                request.agentId(),
                request.idempotencyKey(),
                requestHash,
                request.merchantId(),
                request.currency(),
                request.amountMinor(),
                0,
                IntentStatus.RESERVED,
                null);
        ledger.insertReservation(c, intent);
        ledger.enqueueRecovery(c, intent.intentId(), recoveryGraceMillis);
        return new SpendResult(intent, false);
    }

    private static SpendResult idempotencyGate(IntentView existing, String requestHash) {
        if (!existing.requestHash().equals(requestHash)) {
            throw new IdempotencyException.PayloadMismatch(
                    "Idempotency key '" + existing.idempotencyKey() + "' of agent " + existing.agentId()
                            + " was already used with a different payload");
        }
        if (!existing.status().isTerminal()) {
            throw new IdempotencyException.InFlight(
                    "Request with idempotency key '" + existing.idempotencyKey() + "' is still in flight (intent "
                            + existing.intentId() + " is " + existing.status() + ")",
                    IN_FLIGHT_RETRY_AFTER);
        }
        return new SpendResult(existing, true);
    }

    // ---------------------------------------------------------------------------------------
    // Phase 2A / 2B
    // ---------------------------------------------------------------------------------------

    @Override
    public IntentView createOnRail(UUID intentId) {
        IntentView intent = requireIntent(intentId);
        if (intent.status() != IntentStatus.RESERVED) {
            return intent;
        }
        // Network step, no transaction open. An unconfirmed payment intent never moves money, so
        // a delayed or duplicated create is harmless.
        RailPaymentIntent pi = rail.createUnconfirmed(
                NidhiLedger.railCreateKey(intentId),
                intentId,
                intent.merchantId(),
                intent.currency(),
                intent.authorizedAmountMinor());
        IntentView after = tx.inTransaction(c -> {
            IntentView locked = ledger.findIntent(c, intentId, true).orElseThrow();
            if (locked.status() == IntentStatus.RESERVED) {
                ledger.markConfirming(c, intentId, pi.piId());
                return ledger.findIntent(c, intentId, false).orElseThrow();
            }
            return locked;
        });
        if (after.status() == IntentStatus.VOIDED) {
            // Recovery voided the reservation while this create was in flight. The payment intent
            // we just created is unconfirmed; cancel it so it can never be confirmed later.
            cancelOrphan(pi.piId());
        }
        return after;
    }

    private void cancelOrphan(String piId) {
        try {
            rail.cancel(piId);
        } catch (RailException.CancelRejected e) {
            // Already canceled by someone else; nothing can be charged on it.
            if (e.statusAtRejection() != RailPiStatus.CANCELED) {
                throw new IllegalStateException(
                        "Orphaned payment intent " + piId + " of a voided intent is " + e.statusAtRejection(), e);
            }
        }
    }

    @Override
    public RailPaymentIntent confirmOnRail(UUID intentId) {
        IntentView intent = requireIntent(intentId);
        if (intent.status() != IntentStatus.CONFIRMING) {
            throw new IllegalStateException("Intent " + intentId + " is " + intent.status() + ", not CONFIRMING");
        }
        return rail.confirm(intent.railPaymentIntentId(), NidhiLedger.railConfirmKey(intentId));
    }

    // ---------------------------------------------------------------------------------------
    // Phase 3A
    // ---------------------------------------------------------------------------------------

    @Override
    public IntentView capture(UUID intentId) {
        IntentView intent = requireIntent(intentId);
        if (intent.status() == IntentStatus.CAPTURED) {
            return intent;
        }
        if (intent.status().isTerminal()) {
            throw new IllegalStateException("Intent " + intentId + " is " + intent.status() + "; cannot capture");
        }
        if (intent.railPaymentIntentId() == null) {
            throw new IllegalStateException("Intent " + intentId + " has no rail payment intent; cannot capture");
        }
        RailPaymentIntent pi = rail.retrieve(intent.railPaymentIntentId());
        if (pi.status() != RailPiStatus.SUCCEEDED) {
            throw new IllegalStateException(
                    "Rail payment intent " + pi.piId() + " is " + pi.status() + "; nothing was charged to capture");
        }
        return settleCapture(intentId, pi);
    }

    private IntentView settleCapture(UUID intentId, RailPaymentIntent succeeded) {
        return tx.inTransaction(c -> {
            IntentView locked = lockForTransition(c, intentId);
            if (locked.status() == IntentStatus.CAPTURED) {
                return locked;
            }
            if (locked.status().isTerminal()) {
                throw new IllegalStateException(
                        "Intent " + intentId + " is " + locked.status() + " but the rail charged " + succeeded.piId());
            }
            ledger.recordCapture(c, locked, succeeded.chargedMinor());
            return ledger.findIntent(c, intentId, false).orElseThrow();
        });
    }

    // ---------------------------------------------------------------------------------------
    // Phase 3B
    // ---------------------------------------------------------------------------------------

    @Override
    public IntentView recoverOrVoid(UUID intentId) {
        IntentView intent = requireIntent(intentId);
        if (intent.status().isTerminal()) {
            return intent;
        }
        if (intent.status() == IntentStatus.RESERVED) {
            // No rail payment intent recorded, so no confirm was ever sent: voiding is safe. If a
            // create is still in flight, createOnRail sees VOIDED under the row lock and cancels it.
            IntentView afterVoid = tx.inTransaction(c -> {
                IntentView locked = lockForTransition(c, intentId);
                if (locked.status() == IntentStatus.RESERVED) {
                    ledger.recordVoid(c, locked);
                    return ledger.findIntent(c, intentId, false).orElseThrow();
                }
                return locked;
            });
            if (afterVoid.status() != IntentStatus.CONFIRMING) {
                return afterVoid;
            }
            intent = afterVoid;
        }
        return recoverConfirming(intent);
    }

    private IntentView recoverConfirming(IntentView intent) {
        String piId = intent.railPaymentIntentId();
        RailPaymentIntent pi = rail.retrieve(piId);
        if (pi.status() == RailPiStatus.REQUIRES_CONFIRMATION) {
            try {
                pi = rail.cancel(piId);
            } catch (RailException.CancelRejected e) {
                // A confirm landed between our read and our cancel (or another recoverer won).
                // Never void on the strength of a failed cancel: read the rail again.
                pi = rail.retrieve(piId);
            }
        }
        return switch (pi.status()) {
            case SUCCEEDED -> settleCapture(intent.intentId(), pi);
            case CANCELED -> settleVoid(intent.intentId());
            // PROCESSING: the rail rejects /cancel and may still charge. Keep the hold locked.
            case PROCESSING, REQUIRES_CONFIRMATION -> requireIntent(intent.intentId());
        };
    }

    private IntentView settleVoid(UUID intentId) {
        return tx.inTransaction(c -> {
            IntentView locked = lockForTransition(c, intentId);
            if (locked.status().isTerminal()) {
                if (locked.status() == IntentStatus.CAPTURED) {
                    throw new IllegalStateException("Intent " + intentId + " is CAPTURED but its payment intent is canceled");
                }
                return locked;
            }
            ledger.recordVoid(c, locked);
            return ledger.findIntent(c, intentId, false).orElseThrow();
        });
    }

    // ---------------------------------------------------------------------------------------
    // Verified rail events (webhooks)

    static final String EVENT_SUCCEEDED = "payment_intent.succeeded";
    static final String EVENT_CANCELED = "payment_intent.canceled";
    static final String EVENT_PAYMENT_FAILED = "payment_intent.payment_failed";

    @Override
    public RailEventOutcome applyRailEvent(String providerEventId, String eventType, RailPaymentIntent pi) {
        Objects.requireNonNull(providerEventId, "providerEventId");
        Objects.requireNonNull(eventType, "eventType");
        Objects.requireNonNull(pi, "pi");
        RailEventOutcome outcome = tx.inTransaction(c -> {
            Optional<IntentView> known = ledger.findIntentByRailId(c, pi.piId());
            UUID intentId = known.map(IntentView::intentId).orElse(null);
            if (!ledger.recordWebhook(c, providerEventId, intentId, eventType)) {
                return new RailEventOutcome(RailEventOutcome.Disposition.DUPLICATE, known);
            }
            if (known.isEmpty()) {
                // A payment intent no intent recorded: e.g. a late Step 2A packet whose intent was
                // voided. It is unconfirmed and can never charge; nothing to settle.
                return new RailEventOutcome(RailEventOutcome.Disposition.IGNORED, known);
            }
            boolean succeeded = eventType.equals(EVENT_SUCCEEDED) && pi.status() == RailPiStatus.SUCCEEDED;
            boolean canceled = eventType.equals(EVENT_CANCELED) && pi.status() == RailPiStatus.CANCELED;
            if (!succeeded && !canceled) {
                return new RailEventOutcome(RailEventOutcome.Disposition.IGNORED, known);
            }
            IntentView locked = lockForTransition(c, intentId);
            if (!locked.status().isTerminal()) {
                if (succeeded) {
                    ledger.recordCapture(c, locked, pi.chargedMinor());
                } else {
                    ledger.recordVoid(c, locked);
                }
            } else if (locked.status() != (succeeded ? IntentStatus.CAPTURED : IntentStatus.VOIDED)) {
                throw new IllegalStateException("Event " + providerEventId + " (" + eventType + ") contradicts intent "
                        + intentId + " in " + locked.status());
            }
            return new RailEventOutcome(
                    RailEventOutcome.Disposition.APPLIED, ledger.findIntent(c, intentId, false));
        });
        if (outcome.disposition() == RailEventOutcome.Disposition.IGNORED
                && eventType.equals(EVENT_PAYMENT_FAILED) && outcome.intent().isPresent()) {
            // Recorded; now resolve it the only safe way: cancel on the rail, then void.
            IntentView recovered = recoverOrVoid(outcome.intent().get().intentId());
            return new RailEventOutcome(RailEventOutcome.Disposition.APPLIED, Optional.of(recovered));
        }
        return outcome;
    }

    // ---------------------------------------------------------------------------------------
    // End to end
    // ---------------------------------------------------------------------------------------

    @Override
    public SpendResult execute(SpendRequest request) {
        SpendResult reserved = reserve(request);
        if (reserved.replayed()) {
            return reserved;
        }
        UUID intentId = reserved.intent().intentId();
        try {
            IntentView created = createOnRail(intentId);
            if (created.status() != IntentStatus.CONFIRMING) {
                return new SpendResult(created, false);
            }
            RailPaymentIntent confirmed = confirmOnRail(intentId);
            if (confirmed.status() == RailPiStatus.SUCCEEDED) {
                return new SpendResult(settleCapture(intentId, confirmed), false);
            }
            return new SpendResult(requireIntent(intentId), false);
        } catch (RailException e) {
            // Outcome unknown or rejected: resolve through the recovery protocol, never by guessing.
            return new SpendResult(recoverOrVoid(intentId), false);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------------------------

    @Override
    public Optional<IntentView> findIntent(UUID intentId) {
        return tx.read(c -> ledger.findIntent(c, intentId, false));
    }

    @Override
    public Optional<IntentView> findIntent(String agentId, String idempotencyKey) {
        return tx.read(c -> ledger.findIntent(c, agentId, idempotencyKey));
    }

    @Override
    public List<IntentView> intentsOf(UUID mandateId) {
        return tx.read(c -> ledger.intentsOf(c, mandateId));
    }

    @Override
    public MandateBalances balances(UUID mandateId) {
        return tx.read(c -> ledger.balances(c, mandateId))
                .orElseThrow(() -> new IllegalArgumentException("Unknown mandate " + mandateId));
    }

    @Override
    public EngineMetrics metrics() {
        return new EngineMetrics(tx.serializationFailures(), tx.deadlocks(), tx.retriesExhausted());
    }

    private IntentView requireIntent(UUID intentId) {
        return findIntent(intentId).orElseThrow(() -> new IllegalArgumentException("Unknown intent " + intentId));
    }

    /** Takes the locks of a capture or void in canonical order and returns the locked intent. */
    private IntentView lockForTransition(Connection c, UUID intentId) throws SQLException {
        IntentView unlocked = ledger.findIntent(c, intentId, false).orElseThrow();
        if (lockBalances) {
            ledger.lockBalances(c, unlocked.mandateId());
        }
        return ledger.findIntent(c, intentId, true).orElseThrow();
    }
}
