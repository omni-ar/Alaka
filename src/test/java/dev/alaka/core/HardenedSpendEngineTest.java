package dev.alaka.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.ConfirmBehavior;
import dev.alaka.yaksha.ConfirmBehavior.RailFault;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** End-to-end behaviour of both hardened modes against PostgreSQL 16 and the simulated rail. */
class HardenedSpendEngineTest {

    private static final String MERCHANT = "merchant-a";

    private static HikariDataSource dataSource;

    @BeforeAll
    static void startPool() {
        dataSource = NidhiPostgres.shared().newAppDataSource(20);
    }

    @AfterAll
    static void closePool() {
        dataSource.close();
    }

    /** One engine, one rail and one fresh mandate (budget 10000, per-tx cap 6000). */
    private static final class Fixture {
        final SimulatedPaymentRail rail = new SimulatedPaymentRail();
        final SpendEngine engine;
        final String agent = "agent-" + UUID.randomUUID();
        final UUID mandate;
        int keys;

        Fixture(RuntimeMode mode) {
            this(mode, null);
        }

        Fixture(RuntimeMode mode, PaymentRailPort railOverride) {
            engine = SpendEngines.create(mode, dataSource, railOverride == null ? rail : railOverride);
            mandate = engine.createMandate(new NewMandate(
                    agent, "USD", 10_000, 6_000, List.of(MERCHANT), Duration.ofHours(1), "kid-test"));
        }

        SpendRequest request(long amount) {
            return new SpendRequest(mandate, agent, "key-" + keys++, MERCHANT, "USD", amount);
        }

        MandateBalances balances() {
            return engine.balances(mandate);
        }

        void assertBalances(long available, long held, long settled) {
            assertThat(balances()).isEqualTo(new MandateBalances(mandate, 10_000, available, held, settled));
        }

        RailPaymentIntent railOf(UUID intentId) {
            return rail.findByIntentId(intentId).orElseThrow();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Happy paths

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void executeCapturesInFull(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        SpendResult result = f.engine.execute(f.request(4_000));

        assertThat(result.replayed()).isFalse();
        assertThat(result.intent().status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(result.intent().capturedAmountMinor()).isEqualTo(4_000);
        assertThat(f.railOf(result.intent().intentId()).chargedMinor()).isEqualTo(4_000);
        f.assertBalances(6_000, 0, 4_000);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void phasesStepByStepWithPartialCaptureReleaseRemainder(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        IntentView reserved = f.engine.reserve(f.request(4_000)).intent();
        UUID id = reserved.intentId();
        assertThat(reserved.status()).isEqualTo(IntentStatus.RESERVED);
        f.assertBalances(6_000, 4_000, 0);

        f.rail.setConfirmBehavior(id, ConfirmBehavior.succeedPartial(2_500));
        IntentView confirming = f.engine.createOnRail(id);
        assertThat(confirming.status()).isEqualTo(IntentStatus.CONFIRMING);
        assertThat(confirming.railPaymentIntentId()).isEqualTo(f.railOf(id).piId());
        assertThat(f.engine.createOnRail(id)).isEqualTo(confirming);
        f.assertBalances(6_000, 4_000, 0);

        assertThat(f.engine.confirmOnRail(id).status()).isEqualTo(RailPiStatus.SUCCEEDED);
        IntentView captured = f.engine.capture(id);
        assertThat(captured.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(captured.capturedAmountMinor()).isEqualTo(2_500);
        f.assertBalances(7_500, 0, 2_500);

        assertThat(f.engine.capture(id)).isEqualTo(captured);
        assertThat(f.engine.recoverOrVoid(id)).isEqualTo(captured);
        f.assertBalances(7_500, 0, 2_500);
    }

    // ------------------------------------------------------------------------------------------
    // Idempotency gate (I2)

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void idempotencyGateAnswersReplayInFlightAndMismatch(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        SpendRequest request = f.request(1_000);
        IntentView reserved = f.engine.reserve(request).intent();

        assertThatThrownBy(() -> f.engine.execute(request))
                .isInstanceOfSatisfying(IdempotencyException.InFlight.class, e -> {
                    assertThat(e.httpStatus()).isEqualTo(409);
                    assertThat(e.retryAfter()).isPositive();
                });
        SpendRequest tampered = new SpendRequest(
                request.mandateId(), request.agentId(), request.idempotencyKey(), MERCHANT, "USD", 1_001);
        assertThatThrownBy(() -> f.engine.execute(tampered))
                .isInstanceOfSatisfying(IdempotencyException.PayloadMismatch.class,
                        e -> assertThat(e.httpStatus()).isEqualTo(422));

        f.engine.createOnRail(reserved.intentId());
        f.engine.confirmOnRail(reserved.intentId());
        IntentView captured = f.engine.capture(reserved.intentId());

        SpendResult replay = f.engine.execute(request);
        assertThat(replay.replayed()).isTrue();
        assertThat(replay.intent()).isEqualTo(captured);
        assertThatThrownBy(() -> f.engine.execute(tampered)).isInstanceOf(IdempotencyException.PayloadMismatch.class);
        assertThat(f.rail.paymentIntents()).hasSize(1);
        f.assertBalances(9_000, 0, 1_000);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void concurrentFirstTimeDuplicatesProduceOneIntentAndOneCharge(RuntimeMode mode) throws Exception {
        Fixture f = new Fixture(mode);
        f.rail.setLatency(Duration.ofMillis(5), Duration.ofMillis(20));
        SpendRequest request = f.request(1_000);
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Object>> outcomes = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < threads; i++) {
                outcomes.add(pool.submit(() -> {
                    start.await();
                    try {
                        return f.engine.execute(request);
                    } catch (IdempotencyException e) {
                        return e;
                    }
                }));
            }
            start.countDown();
        }
        int executed = 0;
        for (Future<Object> outcome : outcomes) {
            Object value = outcome.get();
            if (value instanceof SpendResult result && !result.replayed()) {
                executed++;
            } else {
                assertThat(value).isInstanceOfAny(SpendResult.class, IdempotencyException.InFlight.class);
            }
        }
        assertThat(executed).isEqualTo(1);
        assertThat(f.engine.intentsOf(f.mandate)).hasSize(1);
        assertThat(f.rail.paymentIntents()).hasSize(1);
        assertThat(f.rail.totalChargedMinor()).isEqualTo(1_000);
        f.assertBalances(9_000, 0, 1_000);
    }

    // ------------------------------------------------------------------------------------------
    // Phase 3B recovery

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void recoveryVoidsReservedIntentWithoutRailPaymentIntent(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        UUID id = f.engine.reserve(f.request(3_000)).intent().intentId();

        assertThat(f.engine.recoverOrVoid(id).status()).isEqualTo(IntentStatus.VOIDED);
        f.assertBalances(10_000, 0, 0);
        assertThat(f.engine.createOnRail(id).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.rail.paymentIntents()).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void recoveryCancelsUnconfirmedPaymentIntentBeforeVoiding(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        UUID id = f.engine.reserve(f.request(3_000)).intent().intentId();
        f.engine.createOnRail(id);

        assertThat(f.engine.recoverOrVoid(id).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.railOf(id).status()).isEqualTo(RailPiStatus.CANCELED);
        f.assertBalances(10_000, 0, 0);
        assertThatThrownBy(() -> f.rail.confirm(f.railOf(id).piId(), "confirm_" + id))
                .isInstanceOf(dev.alaka.yaksha.RailException.ConfirmRejected.class);
        assertThat(f.rail.totalChargedMinor()).isZero();
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void processingKeepsHoldUntilRailResolvesSucceeded(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        SpendRequest request = f.request(3_000);
        f.rail.setDefaultConfirmBehavior(ConfirmBehavior.enterProcessing());

        IntentView afterExecute = f.engine.execute(request).intent();
        UUID id = afterExecute.intentId();
        assertThat(afterExecute.status()).isEqualTo(IntentStatus.CONFIRMING);
        assertThat(f.engine.recoverOrVoid(id).status()).isEqualTo(IntentStatus.CONFIRMING);
        assertThat(f.engine.recoverOrVoid(id).status()).isEqualTo(IntentStatus.CONFIRMING);
        f.assertBalances(7_000, 3_000, 0);
        assertThat(f.railOf(id).status()).isEqualTo(RailPiStatus.PROCESSING);

        f.rail.resolveProcessingAsSucceeded(afterExecute.railPaymentIntentId(), 2_000);
        IntentView recovered = f.engine.recoverOrVoid(id);
        assertThat(recovered.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(recovered.capturedAmountMinor()).isEqualTo(2_000);
        f.assertBalances(8_000, 0, 2_000);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void processingKeepsHoldUntilRailResolvesCanceled(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        f.rail.setDefaultConfirmBehavior(ConfirmBehavior.enterProcessing());
        IntentView intent = f.engine.execute(f.request(3_000)).intent();
        assertThat(f.engine.recoverOrVoid(intent.intentId()).status()).isEqualTo(IntentStatus.CONFIRMING);
        f.assertBalances(7_000, 3_000, 0);

        f.rail.resolveProcessingAsCanceled(intent.railPaymentIntentId());
        assertThat(f.engine.recoverOrVoid(intent.intentId()).status()).isEqualTo(IntentStatus.VOIDED);
        f.assertBalances(10_000, 0, 0);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void cancelRejectedBecauseConfirmLandedFirstLeadsToCapture(RuntimeMode mode) {
        // The rail confirms the payment intent just before our /cancel reaches it: the delayed
        // in-flight confirm packet of Trap 1 wins the race.
        SimulatedPaymentRail rail = new SimulatedPaymentRail();
        AtomicBoolean landed = new AtomicBoolean();
        PaymentRailPort racing = new ForwardingRail(rail) {
            @Override
            public RailPaymentIntent cancel(String piId) {
                if (landed.compareAndSet(false, true)) {
                    RailPaymentIntent pi = rail.retrieve(piId);
                    rail.confirm(piId, "confirm_" + pi.intentId());
                }
                return rail.cancel(piId);
            }
        };
        Fixture f = new Fixture(mode, racing);
        UUID id = f.engine.reserve(f.request(2_000)).intent().intentId();
        f.engine.createOnRail(id);

        IntentView recovered = f.engine.recoverOrVoid(id);
        assertThat(landed).isTrue();
        assertThat(recovered.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(rail.findByIntentId(id).orElseThrow().status()).isEqualTo(RailPiStatus.SUCCEEDED);
        f.assertBalances(8_000, 0, 2_000);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void voidRacingInFlightCreateCancelsTheLatePaymentIntent(RuntimeMode mode) {
        // Recovery voids the RESERVED intent while its create packet is still in flight.
        SimulatedPaymentRail rail = new SimulatedPaymentRail();
        SpendEngine[] engineRef = new SpendEngine[1];
        PaymentRailPort slowCreate = new ForwardingRail(rail) {
            @Override
            public RailPaymentIntent createUnconfirmed(
                    String key, UUID intentId, String merchantId, String currency, long amountMinor) {
                assertThat(engineRef[0].recoverOrVoid(intentId).status()).isEqualTo(IntentStatus.VOIDED);
                return rail.createUnconfirmed(key, intentId, merchantId, currency, amountMinor);
            }
        };
        Fixture f = new Fixture(mode, slowCreate);
        engineRef[0] = f.engine;
        UUID id = f.engine.reserve(f.request(2_000)).intent().intentId();

        assertThat(f.engine.createOnRail(id).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(rail.findByIntentId(id).orElseThrow().status()).isEqualTo(RailPiStatus.CANCELED);
        f.assertBalances(10_000, 0, 0);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void createTimeoutsEndVoidedAndNeverCharge(RuntimeMode mode) {
        for (RailFault fault : List.of(RailFault.TIMEOUT_BEFORE_APPLY, RailFault.TIMEOUT_AFTER_APPLY)) {
            Fixture f = new Fixture(mode);
            SpendRequest request = f.request(2_000);
            UUID[] id = new UUID[1];
            SpendResult result = withNextIntent(f, intentId -> {
                id[0] = intentId;
                f.rail.setCreateFault(intentId, fault);
            }, request);

            assertThat(result.intent().status()).as(fault.name()).isEqualTo(IntentStatus.VOIDED);
            f.assertBalances(10_000, 0, 0);
            assertThat(f.rail.totalChargedMinor()).isZero();
            if (fault == RailFault.TIMEOUT_AFTER_APPLY) {
                // The engine never learned the id; the orphan is unconfirmed and can never charge.
                assertThat(f.railOf(id[0]).status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
            } else {
                assertThat(f.rail.findByIntentId(id[0])).isEmpty();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void confirmTimeoutsAreResolvedByAskingTheRail(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        f.rail.setDefaultConfirmBehavior(ConfirmBehavior.succeedFull().withFault(RailFault.TIMEOUT_BEFORE_APPLY));
        IntentView lost = f.engine.execute(f.request(2_000)).intent();
        assertThat(lost.status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.railOf(lost.intentId()).status()).isEqualTo(RailPiStatus.CANCELED);

        f.rail.setDefaultConfirmBehavior(ConfirmBehavior.succeedPartial(1_500).withFault(RailFault.TIMEOUT_AFTER_APPLY));
        IntentView applied = f.engine.execute(f.request(2_000)).intent();
        assertThat(applied.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(applied.capturedAmountMinor()).isEqualTo(1_500);

        f.assertBalances(8_500, 0, 1_500);
        assertThat(f.rail.totalChargedMinor()).isEqualTo(1_500);
    }

    // ------------------------------------------------------------------------------------------
    // Domain rejections

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void databaseRejectionsAreTyped(RuntimeMode mode) throws Exception {
        Fixture f = new Fixture(mode);
        assertThatThrownBy(() -> f.engine.reserve(f.request(6_001)))
                .isInstanceOf(NidhiException.BudgetExceeded.class);
        assertThatThrownBy(() -> f.engine.reserve(
                new SpendRequest(f.mandate, f.agent, "k-eur", MERCHANT, "EUR", 100)))
                .isInstanceOf(NidhiException.CurrencyMismatch.class);
        assertThatThrownBy(() -> f.engine.reserve(
                new SpendRequest(f.mandate, f.agent, "k-evil", "evil-merchant", "USD", 100)))
                .isInstanceOf(NidhiException.MerchantNotAllowed.class);
        assertThatThrownBy(() -> f.engine.reserve(
                new SpendRequest(f.mandate, "someone-else", "k-agent", MERCHANT, "USD", 100)))
                .isInstanceOf(NidhiException.MandateInactive.class);

        // Overdraw is caught by the deferred conservation trigger at COMMIT.
        f.engine.reserve(f.request(6_000));
        assertThatThrownBy(() -> f.engine.reserve(f.request(4_001)))
                .isInstanceOfSatisfying(NidhiException.BudgetExceeded.class,
                        e -> assertThat(e.sqlState()).isEqualTo("SG003"));
        f.engine.reserve(f.request(4_000));
        f.assertBalances(0, 10_000, 0);

        Fixture expiring = new Fixture(mode);
        UUID shortLived = expiring.engine.createMandate(new NewMandate(
                expiring.agent, "USD", 1_000, 1_000, List.of(MERCHANT), Duration.ofMillis(1), "kid-test"));
        // Past expiry on every backend's clock, which can disagree by hundreds of milliseconds.
        Thread.sleep(1_500);
        assertThatThrownBy(() -> expiring.engine.reserve(
                new SpendRequest(shortLived, expiring.agent, "k-late", MERCHANT, "USD", 100)))
                .isInstanceOf(NidhiException.MandateInactive.class);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void revocationBlocksNewSpendButNotSettlementOfExistingHolds(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        UUID toCapture = f.engine.reserve(f.request(2_000)).intent().intentId();
        UUID toVoid = f.engine.reserve(f.request(1_000)).intent().intentId();
        f.engine.createOnRail(toCapture);

        f.engine.revokeMandate(f.mandate, "agent compromised");
        assertThatThrownBy(() -> f.engine.reserve(f.request(100))).isInstanceOf(NidhiException.MandateInactive.class);
        assertThatThrownBy(() -> f.engine.revokeMandate(f.mandate, "again"))
                .isInstanceOf(NidhiException.IllegalStateTransition.class);

        f.engine.confirmOnRail(toCapture);
        assertThat(f.engine.capture(toCapture).status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(f.engine.recoverOrVoid(toVoid).status()).isEqualTo(IntentStatus.VOIDED);
        f.assertBalances(8_000, 0, 2_000);
    }

    /**
     * Runs {@code execute} after arranging rail behaviour for the intent it is about to reserve.
     * The intent id is only known once Phase 1 has committed, so the rail is wrapped to report it
     * at the first rail call.
     */
    private static SpendResult withNextIntent(Fixture f, Consumer<UUID> arrange, SpendRequest request) {
        AtomicBoolean arranged = new AtomicBoolean();
        PaymentRailPort hook = new ForwardingRail(f.rail) {
            @Override
            public RailPaymentIntent createUnconfirmed(
                    String key, UUID intentId, String merchantId, String currency, long amountMinor) {
                if (arranged.compareAndSet(false, true)) {
                    arrange.accept(intentId);
                }
                return f.rail.createUnconfirmed(key, intentId, merchantId, currency, amountMinor);
            }
        };
        SpendEngine hooked = SpendEngines.create(f.engine.mode(), dataSource, hook);
        return hooked.execute(request);
    }

    /** Delegates every call to a rail; tests override single calls to stage races and faults. */
    private static class ForwardingRail implements PaymentRailPort {
        private final PaymentRailPort delegate;

        ForwardingRail(PaymentRailPort delegate) {
            this.delegate = delegate;
        }

        @Override
        public RailPaymentIntent createUnconfirmed(
                String key, UUID intentId, String merchantId, String currency, long amountMinor) {
            return delegate.createUnconfirmed(key, intentId, merchantId, currency, amountMinor);
        }

        @Override
        public RailPaymentIntent confirm(String piId, String idempotencyKey) {
            return delegate.confirm(piId, idempotencyKey);
        }

        @Override
        public RailPaymentIntent retrieve(String piId) {
            return delegate.retrieve(piId);
        }

        @Override
        public RailPaymentIntent cancel(String piId) {
            return delegate.cancel(piId);
        }
    }
}
