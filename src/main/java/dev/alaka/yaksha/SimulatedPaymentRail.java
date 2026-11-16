package dev.alaka.yaksha;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.locks.ReentrantLock;

/**
 * In-memory, thread-safe {@link PaymentRailPort} that behaves like the rail the protocol was
 * designed against: unconfirmed intents never move money, a confirm can leave an intent
 * {@code PROCESSING}, {@code /cancel} is rejected while processing or after success, a canceled
 * intent rejects a late confirm, and every charge that happened is recorded so tests can compare
 * the rail's truth with the ledger's.
 *
 * <p>All state sits behind one {@link ReentrantLock} (not {@code synchronized}, which would pin a
 * virtual thread's carrier). Latency is slept before the lock is taken, so a call is "in flight"
 * for its whole latency and is applied atomically when it lands; that is what lets a delayed
 * confirm genuinely race a cancel.
 */
public final class SimulatedPaymentRail implements PaymentRailPort {

    private static final class Pi {
        final String piId;
        final UUID intentId;
        final String merchantId;
        final String currency;
        final long amountMinor;
        RailPiStatus status = RailPiStatus.REQUIRES_CONFIRMATION;
        long chargedMinor;

        Pi(String piId, UUID intentId, String merchantId, String currency, long amountMinor) {
            this.piId = piId;
            this.intentId = intentId;
            this.merchantId = merchantId;
            this.currency = currency;
            this.amountMinor = amountMinor;
        }

        RailPaymentIntent view() {
            return new RailPaymentIntent(piId, intentId, status, merchantId, currency, amountMinor, chargedMinor);
        }
    }

    /**
     * Prefix unique to this rail instance. Real rail ids are globally unique, and the ledger
     * enforces that ({@code UNIQUE (stripe_payment_intent)}), so two simulated rails sharing one
     * database must never hand out the same id.
     */
    private final String idPrefix = "pi_sim_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "_";
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Pi> byPiId = new LinkedHashMap<>();
    private final Map<String, String> piIdByCreateKey = new HashMap<>();
    private final Map<UUID, ConfirmBehavior> confirmBehaviors = new HashMap<>();
    private final Map<UUID, ConfirmBehavior.RailFault> createFaults = new HashMap<>();
    private ConfirmBehavior defaultConfirmBehavior = ConfirmBehavior.succeedFull();
    private long minLatencyNanos;
    private long maxLatencyNanos;
    private long nextPiNumber = 1;

    /** Creates a rail with no latency that confirms every intent in full. */
    public SimulatedPaymentRail() {
    }

    @Override
    public RailPaymentIntent createUnconfirmed(
            String idempotencyKey, UUID intentId, String merchantId, String currency, long amountMinor) {
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(intentId, "intentId");
        if (amountMinor <= 0) {
            throw new IllegalArgumentException("amountMinor must be positive: " + amountMinor);
        }
        simulateLatency();
        ConfirmBehavior.RailFault fault;
        RailPaymentIntent created;
        lock.lock();
        try {
            fault = createFaults.remove(intentId);
            if (fault == ConfirmBehavior.RailFault.TIMEOUT_BEFORE_APPLY) {
                throw new RailException.Timeout("create for intent " + intentId + " lost before reaching the rail");
            }
            String existing = piIdByCreateKey.get(idempotencyKey);
            if (existing != null) {
                created = byPiId.get(existing).view();
            } else {
                Pi pi = new Pi(idPrefix + nextPiNumber++, intentId, merchantId, currency, amountMinor);
                byPiId.put(pi.piId, pi);
                piIdByCreateKey.put(idempotencyKey, pi.piId);
                created = pi.view();
            }
        } finally {
            lock.unlock();
        }
        if (fault == ConfirmBehavior.RailFault.TIMEOUT_AFTER_APPLY) {
            throw new RailException.Timeout("create for intent " + intentId + " applied, response lost");
        }
        return created;
    }

    @Override
    public RailPaymentIntent confirm(String piId, String idempotencyKey) {
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        simulateLatency();
        ConfirmBehavior.RailFault fault;
        RailPaymentIntent result;
        lock.lock();
        try {
            Pi pi = require(piId);
            ConfirmBehavior behavior = confirmBehaviors.getOrDefault(pi.intentId, defaultConfirmBehavior);
            fault = behavior.fault();
            if (fault == ConfirmBehavior.RailFault.TIMEOUT_BEFORE_APPLY) {
                // The fault is one-shot; the outcome still applies to the confirm that does land.
                confirmBehaviors.put(pi.intentId, behavior.withFault(ConfirmBehavior.RailFault.NONE));
                throw new RailException.Timeout("confirm of " + piId + " lost before reaching the rail");
            }
            switch (pi.status) {
                case CANCELED -> throw new RailException.ConfirmRejected(piId + " is canceled");
                case REQUIRES_CONFIRMATION -> {
                    confirmBehaviors.remove(pi.intentId);
                    if (behavior.outcome() == ConfirmBehavior.Outcome.SUCCEED) {
                        succeed(pi, behavior.chargedMinor());
                    } else {
                        pi.status = RailPiStatus.PROCESSING;
                    }
                }
                case PROCESSING, SUCCEEDED -> {
                    // Replayed confirm: idempotent, never charges twice.
                }
            }
            result = pi.view();
        } finally {
            lock.unlock();
        }
        if (fault == ConfirmBehavior.RailFault.TIMEOUT_AFTER_APPLY) {
            throw new RailException.Timeout("confirm of " + piId + " applied, response lost");
        }
        return result;
    }

    @Override
    public RailPaymentIntent retrieve(String piId) {
        simulateLatency();
        lock.lock();
        try {
            return require(piId).view();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public RailPaymentIntent cancel(String piId) {
        simulateLatency();
        lock.lock();
        try {
            Pi pi = require(piId);
            if (pi.status != RailPiStatus.REQUIRES_CONFIRMATION) {
                throw new RailException.CancelRejected(
                        pi.status, "cannot cancel " + piId + " in state " + pi.status + " (payment_intent_unexpected_state)");
            }
            pi.status = RailPiStatus.CANCELED;
            return pi.view();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the latency of every rail call: each call sleeps for a uniformly random duration in
     * {@code [min, max]} before it is applied. Sleeping must not pin a carrier thread.
     *
     * @param min shortest latency, not negative
     * @param max longest latency, at least {@code min}
     */
    public void setLatency(Duration min, Duration max) {
        if (min.isNegative() || max.compareTo(min) < 0) {
            throw new IllegalArgumentException("Need 0 <= min <= max, got " + min + " and " + max);
        }
        lock.lock();
        try {
            minLatencyNanos = min.toNanos();
            maxLatencyNanos = max.toNanos();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets how confirms behave when no per-intent behaviour is set. Initially
     * {@link ConfirmBehavior#succeedFull()}.
     *
     * @param behavior the default confirm behaviour
     */
    public void setDefaultConfirmBehavior(ConfirmBehavior behavior) {
        Objects.requireNonNull(behavior, "behavior");
        lock.lock();
        try {
            defaultConfirmBehavior = behavior;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets how the first confirm that is applied for one gateway intent behaves, overriding the
     * default. May be called before the payment intent exists.
     *
     * @param intentId gateway intent id
     * @param behavior the confirm behaviour for that intent
     */
    public void setConfirmBehavior(UUID intentId, ConfirmBehavior behavior) {
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(behavior, "behavior");
        lock.lock();
        try {
            confirmBehaviors.put(intentId, behavior);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Makes the next {@code createUnconfirmed} for one gateway intent observe a fault. With
     * {@link ConfirmBehavior.RailFault#TIMEOUT_AFTER_APPLY} the payment intent exists on the rail
     * although the caller never learns its id.
     *
     * @param intentId gateway intent id
     * @param fault the fault the caller should observe once
     */
    public void setCreateFault(UUID intentId, ConfirmBehavior.RailFault fault) {
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(fault, "fault");
        lock.lock();
        try {
            if (fault == ConfirmBehavior.RailFault.NONE) {
                createFaults.remove(intentId);
            } else {
                createFaults.put(intentId, fault);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Resolves a {@code PROCESSING} payment intent to {@code SUCCEEDED}.
     *
     * @param piId rail payment intent id
     * @param chargedMinor amount to charge; {@code 0} means the full authorised amount
     * @return the payment intent after resolution
     * @throws IllegalStateException if the payment intent is not {@code PROCESSING}
     */
    public RailPaymentIntent resolveProcessingAsSucceeded(String piId, long chargedMinor) {
        lock.lock();
        try {
            Pi pi = requireProcessing(piId);
            succeed(pi, chargedMinor);
            return pi.view();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Resolves a {@code PROCESSING} payment intent to {@code CANCELED} (the charge failed).
     *
     * @param piId rail payment intent id
     * @return the payment intent after resolution
     * @throws IllegalStateException if the payment intent is not {@code PROCESSING}
     */
    public RailPaymentIntent resolveProcessingAsCanceled(String piId) {
        lock.lock();
        try {
            Pi pi = requireProcessing(piId);
            pi.status = RailPiStatus.CANCELED;
            return pi.view();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the rail's ground truth for invariant I1: the sum of {@code chargedMinor} over all
     * {@code SUCCEEDED} payment intents.
     *
     * @return total amount charged, in minor units
     */
    public long totalChargedMinor() {
        lock.lock();
        try {
            long total = 0;
            for (Pi pi : byPiId.values()) {
                if (pi.status == RailPiStatus.SUCCEEDED) {
                    total += pi.chargedMinor;
                }
            }
            return total;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns a consistent snapshot of every payment intent the rail has created.
     *
     * @return all payment intents, in creation order
     */
    public List<RailPaymentIntent> paymentIntents() {
        lock.lock();
        try {
            List<RailPaymentIntent> all = new ArrayList<>(byPiId.size());
            for (Pi pi : byPiId.values()) {
                all.add(pi.view());
            }
            return all;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Finds the payment intent created for a gateway intent.
     *
     * @param intentId gateway intent id
     * @return the payment intent, or empty if none was created
     */
    public Optional<RailPaymentIntent> findByIntentId(UUID intentId) {
        lock.lock();
        try {
            for (Pi pi : byPiId.values()) {
                if (pi.intentId.equals(intentId)) {
                    return Optional.of(pi.view());
                }
            }
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    private static void succeed(Pi pi, long requestedChargeMinor) {
        long charged = requestedChargeMinor == 0 ? pi.amountMinor : requestedChargeMinor;
        if (charged <= 0 || charged > pi.amountMinor) {
            throw new IllegalStateException(
                    "Charge " + charged + " outside 1.." + pi.amountMinor + " for " + pi.piId);
        }
        pi.status = RailPiStatus.SUCCEEDED;
        pi.chargedMinor = charged;
    }

    private Pi require(String piId) {
        Pi pi = byPiId.get(piId);
        if (pi == null) {
            throw new RailException.UnknownPaymentIntent("no payment intent " + piId);
        }
        return pi;
    }

    private Pi requireProcessing(String piId) {
        Pi pi = require(piId);
        if (pi.status != RailPiStatus.PROCESSING) {
            throw new IllegalStateException(piId + " is " + pi.status + ", not PROCESSING");
        }
        return pi;
    }

    private void simulateLatency() {
        long min;
        long max;
        lock.lock();
        try {
            min = minLatencyNanos;
            max = maxLatencyNanos;
        } finally {
            lock.unlock();
        }
        long nanos = max <= min ? min : ThreadLocalRandom.current().nextLong(min, max + 1);
        if (nanos <= 0) {
            return;
        }
        try {
            Thread.sleep(Duration.ofNanos(nanos));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RailException.Timeout("interrupted while the call was in flight");
        }
    }
}
