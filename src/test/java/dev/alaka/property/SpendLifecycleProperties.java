package dev.alaka.property;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.core.IdempotencyException;
import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendEngines;
import dev.alaka.core.SpendRequest;
import dev.alaka.core.SpendResult;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.ConfirmBehavior;
import dev.alaka.yaksha.ConfirmBehavior.RailFault;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPiStatus;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.lifecycle.BeforeContainer;
import net.jqwik.api.state.Action;
import net.jqwik.api.state.ActionChain;
import net.jqwik.api.state.Transformer;
import net.jqwik.api.statistics.Statistics;

/**
 * Stateful property suite: arbitrary interleavings of reservations, idempotent retries, tampered
 * retries, full and partial captures, cancels, rails stuck in {@code PROCESSING}, lost confirm
 * responses and revocation, run against PostgreSQL 16 and the simulated rail for both hardened
 * modes.
 *
 * <p>Every try gets a fresh mandate (budget {@value #BUDGET}, per-tx cap {@value #CAP}) and a
 * fresh rail. After every action the engine is compared with an in-memory model of what must have
 * happened (exact balances and the status of every intent), and {@link InvariantChecker} checks
 * I1-I6 against the ledger (raw JDBC as {@code alaka_app}) and the rail.
 */
class SpendLifecycleProperties {

    static final long BUDGET = 10_000;
    static final long CAP = 4_000;
    private static final String MERCHANT = "merchant-a";

    private static HikariDataSource engineData;
    private static HikariDataSource truthData;

    /**
     * Pools shared by this suite and {@link TraceRefinementProperties}, created on first use and
     * left open until the JVM exits (HikariCP's housekeeping threads are daemons).
     */
    static synchronized void ensurePools() {
        if (engineData == null) {
            engineData = NidhiPostgres.shared().newAppDataSource(8);
            truthData = NidhiPostgres.shared().newAppDataSource(2);
        }
    }

    @BeforeContainer
    static void startPools() {
        ensurePools();
    }

    @Property(tries = 30)
    void hardenedPessimisticPreservesInvariants(@ForAll("pessimisticChains") ActionChain<World> chain) {
        run(chain);
    }

    @Property(tries = 30)
    void hardenedSsiPreservesInvariants(@ForAll("ssiChains") ActionChain<World> chain) {
        run(chain);
    }

    private static void run(ActionChain<World> chain) {
        chain.withInvariant("I1-I6 and the model hold", World::assertConsistent).run();
        Statistics.label("chain length").collect(chain.transformations().size() / 10 * 10);
    }

    @Provide
    Arbitrary<ActionChain<World>> pessimisticChains() {
        return chains(RuntimeMode.HARDENED_PESSIMISTIC);
    }

    @Provide
    Arbitrary<ActionChain<World>> ssiChains() {
        return chains(RuntimeMode.HARDENED_SSI);
    }

    private static Arbitrary<ActionChain<World>> chains(RuntimeMode mode) {
        return chains(mode, false);
    }

    /**
     * The action chains of this suite.
     *
     * @param mode hardened mode under test
     * @param traced record every step for trace validation ({@link RefinementTracer})
     * @return the chain arbitrary
     */
    static Arbitrary<ActionChain<World>> chains(RuntimeMode mode, boolean traced) {
        return ActionChain.startWith(() -> new World(mode, traced))
                .withAction(6, new ReserveAction())
                .withAction(2, new OnOpenIntent("DuplicateRetry", World::duplicateRetry, null))
                .withAction(2, new OnOpenIntent("TamperedPayloadRetry", World::tamperedRetry, null))
                .withAction(3, new OnOpenIntent("FullCapture", World::fullCapture, Expect.RESERVED))
                .withAction(3, new PartialCaptureAction())
                .withAction(2, new OnOpenIntent("CancelAndVoid", World::cancelAndVoid, Expect.RESERVED))
                .withAction(2, new OnOpenIntent("CancelAndVoidAfterCreate", World::cancelAndVoidAfterCreate, Expect.RESERVED))
                .withAction(2, new OnOpenIntent("ProcessingRejectsCancel", World::processingRejectsCancel, Expect.RESERVED))
                .withAction(2, new ResolveProcessingAction())
                .withAction(2, new OnOpenIntent("ConfirmResponseLost", World::confirmResponseLost, Expect.RESERVED))
                .withAction(1, new RevokeAction())
                .withMaxTransformations(30);
    }

    // ------------------------------------------------------------------------------------------
    // Model

    /** What the model expects of one intent. */
    enum Expect {
        RESERVED,
        PROCESSING,
        CAPTURED,
        VOIDED;

        boolean terminal() {
            return this == CAPTURED || this == VOIDED;
        }
    }

    static final class ModelIntent {
        final SpendRequest request;
        final UUID intentId;
        Expect expect = Expect.RESERVED;
        long captured;

        ModelIntent(SpendRequest request, UUID intentId) {
            this.request = request;
            this.intentId = intentId;
        }
    }

    /** The system under test plus the model of what it must contain. */
    static final class World {
        final RuntimeMode mode;
        final SimulatedPaymentRail rail = new SimulatedPaymentRail();
        /** The rail as the engine sees it: {@link #rail} itself, or the tracer's view of it. */
        final PaymentRailPort railPort;
        final SpendEngine engine;
        final String agent = "agent-" + UUID.randomUUID();
        final UUID mandate;
        final InvariantChecker checker;
        final RefinementTracer tracer;
        final Map<String, ModelIntent> intents = new LinkedHashMap<>();
        long available = BUDGET;
        long held;
        long settled;
        boolean revoked;
        int nextKey;

        World(RuntimeMode mode, boolean traced) {
            ensurePools();
            this.mode = mode;
            if (traced) {
                this.tracer = new RefinementTracer(truthData, rail);
                this.railPort = tracer.rail();
                this.engine = tracer.engine(SpendEngines.create(mode, engineData, railPort));
            } else {
                this.tracer = null;
                this.railPort = rail;
                this.engine = SpendEngines.create(mode, engineData, rail);
            }
            this.mandate = engine.createMandate(new NewMandate(
                    agent, "USD", BUDGET, CAP, List.of(MERCHANT), Duration.ofHours(1), "kid-property"));
            if (tracer != null) {
                tracer.start(mandate);
            }
            this.checker = new InvariantChecker(engine, rail, truthData, mandate, BUDGET, CAP);
        }

        /** Records a state after a rail-side event the test drove directly. */
        private void traceRailEvent() {
            if (tracer != null) {
                tracer.snapshot();
            }
        }

        List<String> keys(Expect expect) {
            List<String> keys = new ArrayList<>();
            intents.forEach((key, intent) -> {
                if (expect == null || intent.expect == expect) {
                    keys.add(key);
                }
            });
            return keys;
        }

        // Reserve -------------------------------------------------------------------------------

        void reserve(long amount) {
            SpendRequest request = new SpendRequest(mandate, agent, "k" + nextKey++, MERCHANT, "USD", amount);
            if (revoked) {
                outcome("Reserve", "rejected: revoked (SG001)");
                assertThatThrownBy(() -> engine.reserve(request)).isInstanceOf(NidhiException.MandateInactive.class);
            } else if (amount > CAP) {
                outcome("Reserve", "rejected: per-tx cap (SG003)");
                assertThatThrownBy(() -> engine.reserve(request)).isInstanceOf(NidhiException.BudgetExceeded.class);
            } else if (amount > available) {
                outcome("Reserve", "rejected: overdraw (SG003)");
                assertThatThrownBy(() -> engine.reserve(request)).isInstanceOf(NidhiException.BudgetExceeded.class);
            } else {
                outcome("Reserve", amount == available ? "reserved: exactly the remaining budget" : "reserved");
                SpendResult result;
                try {
                    result = engine.reserve(request);
                } catch (NidhiException.MandateInactive e) {
                    // Seen once and never reproduced since: an ACTIVE mandate rejected as outside
                    // its time window on its first reservation. Fail with the evidence needed to
                    // tell a clock step from a stale transaction on a pooled connection.
                    throw new AssertionError("Unexpected SG001 for an active, unexpired mandate; "
                            + "database state: " + diagnoseTimeWindow(), e);
                }
                assertThat(result.replayed()).isFalse();
                assertThat(result.intent().status()).isEqualTo(IntentStatus.RESERVED);
                intents.put(request.idempotencyKey(), new ModelIntent(request, result.intent().intentId()));
                available -= amount;
                held += amount;
            }
        }

        // Retries -------------------------------------------------------------------------------

        void duplicateRetry(String key) {
            ModelIntent intent = intents.get(key);
            if (intent.expect.terminal()) {
                outcome("DuplicateRetry", "replayed stored result");
                SpendResult replay = engine.execute(intent.request);
                assertThat(replay.replayed()).isTrue();
                assertThat(replay.intent().intentId()).isEqualTo(intent.intentId);
            } else {
                outcome("DuplicateRetry", "409 in flight");
                assertThatThrownBy(() -> engine.execute(intent.request))
                        .isInstanceOf(IdempotencyException.InFlight.class);
            }
        }

        void tamperedRetry(String key) {
            SpendRequest original = intents.get(key).request;
            SpendRequest tampered = new SpendRequest(original.mandateId(), original.agentId(),
                    original.idempotencyKey(), "evil-merchant", original.currency(), original.amountMinor() + 1);
            outcome("TamperedPayloadRetry", "422 payload mismatch");
            assertThatThrownBy(() -> engine.execute(tampered)).isInstanceOf(IdempotencyException.PayloadMismatch.class);
        }

        // Settlement ----------------------------------------------------------------------------

        void fullCapture(String key) {
            capture(key, 0);
        }

        void partialCapture(String key, long charged) {
            capture(key, charged);
        }

        private void capture(String key, long charged) {
            ModelIntent intent = intents.get(key);
            long amount = intent.request.amountMinor();
            rail.setConfirmBehavior(intent.intentId,
                    charged == 0 ? ConfirmBehavior.succeedFull() : ConfirmBehavior.succeedPartial(charged));
            engine.createOnRail(intent.intentId);
            assertThat(engine.confirmOnRail(intent.intentId).status()).isEqualTo(RailPiStatus.SUCCEEDED);
            IntentView captured = engine.capture(intent.intentId);
            long expected = charged == 0 ? amount : charged;
            outcome(charged == 0 ? "FullCapture" : "PartialCapture",
                    charged == 0 ? "captured in full" : "captured partially, remainder released");
            assertThat(captured.status()).isEqualTo(IntentStatus.CAPTURED);
            assertThat(captured.capturedAmountMinor()).isEqualTo(expected);
            settle(intent, expected);
        }

        void cancelAndVoid(String key) {
            ModelIntent intent = intents.get(key);
            outcome("CancelAndVoid", "voided before any rail call");
            assertThat(engine.recoverOrVoid(intent.intentId).status()).isEqualTo(IntentStatus.VOIDED);
            assertThat(rail.findByIntentId(intent.intentId)).isEmpty();
            release(intent);
        }

        void cancelAndVoidAfterCreate(String key) {
            ModelIntent intent = intents.get(key);
            engine.createOnRail(intent.intentId);
            outcome("CancelAndVoidAfterCreate", "canceled on the rail, then voided");
            assertThat(engine.recoverOrVoid(intent.intentId).status()).isEqualTo(IntentStatus.VOIDED);
            assertThat(rail.findByIntentId(intent.intentId).orElseThrow().status()).isEqualTo(RailPiStatus.CANCELED);
            release(intent);
        }

        void processingRejectsCancel(String key) {
            ModelIntent intent = intents.get(key);
            rail.setConfirmBehavior(intent.intentId, ConfirmBehavior.enterProcessing());
            engine.createOnRail(intent.intentId);
            assertThat(engine.confirmOnRail(intent.intentId).status()).isEqualTo(RailPiStatus.PROCESSING);
            String piId = engine.findIntent(intent.intentId).orElseThrow().railPaymentIntentId();
            assertThatThrownBy(() -> railPort.cancel(piId)).isInstanceOf(RailException.CancelRejected.class);
            outcome("ProcessingRejectsCancel", "hold kept while PROCESSING");
            assertThat(engine.recoverOrVoid(intent.intentId).status()).isEqualTo(IntentStatus.CONFIRMING);
            intent.expect = Expect.PROCESSING;
        }

        void resolveProcessing(String key, boolean succeeded, long charged) {
            ModelIntent intent = intents.get(key);
            String piId = engine.findIntent(intent.intentId).orElseThrow().railPaymentIntentId();
            if (succeeded) {
                rail.resolveProcessingAsSucceeded(piId, charged);
                traceRailEvent();
                outcome("ResolveProcessing", charged == 0 ? "succeeded in full, captured" : "succeeded partially, captured");
                IntentView after = engine.recoverOrVoid(intent.intentId);
                long expected = charged == 0 ? intent.request.amountMinor() : charged;
                assertThat(after.status()).isEqualTo(IntentStatus.CAPTURED);
                assertThat(after.capturedAmountMinor()).isEqualTo(expected);
                settle(intent, expected);
            } else {
                rail.resolveProcessingAsCanceled(piId);
                traceRailEvent();
                outcome("ResolveProcessing", "failed on the rail, voided");
                assertThat(engine.recoverOrVoid(intent.intentId).status()).isEqualTo(IntentStatus.VOIDED);
                release(intent);
            }
        }

        void confirmResponseLost(String key) {
            ModelIntent intent = intents.get(key);
            rail.setConfirmBehavior(intent.intentId, ConfirmBehavior.succeedFull().withFault(RailFault.TIMEOUT_AFTER_APPLY));
            engine.createOnRail(intent.intentId);
            assertThatThrownBy(() -> engine.confirmOnRail(intent.intentId)).isInstanceOf(RailException.Timeout.class);
            outcome("ConfirmResponseLost", "recovery found the charge and captured");
            IntentView after = engine.recoverOrVoid(intent.intentId);
            assertThat(after.status()).isEqualTo(IntentStatus.CAPTURED);
            settle(intent, intent.request.amountMinor());
        }

        void revoke() {
            engine.revokeMandate(mandate, "property test");
            checker.markRevoked();
            revoked = true;
            outcome("RevokeMandate", "revoked");
        }

        private void settle(ModelIntent intent, long charged) {
            long amount = intent.request.amountMinor();
            held -= amount;
            settled += charged;
            available += amount - charged;
            intent.expect = Expect.CAPTURED;
            intent.captured = charged;
        }

        private void release(ModelIntent intent) {
            held -= intent.request.amountMinor();
            available += intent.request.amountMinor();
            intent.expect = Expect.VOIDED;
        }

        // Checks --------------------------------------------------------------------------------

        void assertConsistent() {
            assertThat(engine.balances(mandate))
                    .as("balances against the model")
                    .isEqualTo(new MandateBalances(mandate, BUDGET, available, held, settled));
            for (ModelIntent intent : intents.values()) {
                IntentView actual = engine.findIntent(intent.intentId).orElseThrow();
                IntentStatus expected = switch (intent.expect) {
                    case RESERVED -> IntentStatus.RESERVED;
                    case PROCESSING -> IntentStatus.CONFIRMING;
                    case CAPTURED -> IntentStatus.CAPTURED;
                    case VOIDED -> IntentStatus.VOIDED;
                };
                assertThat(actual.status()).as("status of %s", intent.request.idempotencyKey()).isEqualTo(expected);
                assertThat(actual.capturedAmountMinor()).isEqualTo(intent.captured);
            }
            assertThat(engine.intentsOf(mandate)).hasSize(intents.size());
            assertThat(rail.totalChargedMinor()).isEqualTo(settled);
            checker.assertHolds("the last action", true);
        }

        private String diagnoseTimeWindow() {
            StringBuilder out = new StringBuilder();
            try (java.sql.Connection c = truthData.getConnection();
                    java.sql.Statement s = c.createStatement()) {
                try (java.sql.ResultSet rs = s.executeQuery(
                        "SELECT not_before, expires_at, created_at, now(), clock_timestamp(), status"
                                + " FROM spend_mandates WHERE mandate_id = '" + mandate + "'")) {
                    rs.next();
                    out.append("not_before=").append(rs.getString(1)).append(" expires_at=").append(rs.getString(2))
                            .append(" created_at=").append(rs.getString(3)).append(" now=").append(rs.getString(4))
                            .append(" clock=").append(rs.getString(5)).append(" status=").append(rs.getString(6));
                }
                try (java.sql.ResultSet rs = s.executeQuery(
                        "SELECT pid, state, xact_start, backend_xid, left(query, 80) FROM pg_stat_activity"
                                + " WHERE usename = 'alaka_app' AND xact_start IS NOT NULL ORDER BY xact_start")) {
                    while (rs.next()) {
                        out.append("\n  pid=").append(rs.getInt(1)).append(" state=").append(rs.getString(2))
                                .append(" xact_start=").append(rs.getString(3)).append(" query=").append(rs.getString(5));
                    }
                }
            } catch (java.sql.SQLException e) {
                out.append("diagnosis failed: ").append(e);
            }
            return out.toString();
        }

        private static void outcome(String action, String outcome) {
            Statistics.label("action").collect(action);
            Statistics.label("outcome").collect(action + ": " + outcome);
        }

        @Override
        public String toString() {
            return mode.cliName() + " world: available=" + available + " held=" + held + " settled=" + settled
                    + " revoked=" + revoked + " intents=" + intents.size();
        }
    }

    // ------------------------------------------------------------------------------------------
    // Actions

    /** Reserves amounts chosen to hit the per-tx cap, the exact remaining budget and overdraw. */
    static final class ReserveAction implements Action.Dependent<World> {
        @Override
        public Arbitrary<Transformer<World>> transformer(World world) {
            List<Long> interesting = new ArrayList<>(List.of(1_000L, 2_500L, CAP, CAP, CAP + 1));
            if (world.available > 0 && world.available <= CAP) {
                // The exact remaining budget fits; one more unit is an overdraw, not a cap breach.
                interesting.add(world.available);
                interesting.add(world.available);
                interesting.add(world.available + 1);
                interesting.add(world.available + 1);
            }
            return Arbitraries.oneOf(Arbitraries.of(interesting), Arbitraries.longs().between(1, CAP + 500))
                    .map(amount -> Transformer.mutate("Reserve(" + amount + ")", w -> w.reserve(amount)));
        }
    }

    /** Applies an action to an existing intent, optionally only to intents in one model state. */
    static final class OnOpenIntent implements Action.Dependent<World> {
        private final String name;
        private final java.util.function.BiConsumer<World, String> step;
        private final Expect required;

        OnOpenIntent(String name, java.util.function.BiConsumer<World, String> step, Expect required) {
            this.name = name;
            this.step = step;
            this.required = required;
        }

        @Override
        public boolean precondition(World world) {
            return !world.keys(required).isEmpty();
        }

        @Override
        public Arbitrary<Transformer<World>> transformer(World world) {
            return Arbitraries.of(world.keys(required))
                    .map(key -> Transformer.mutate(name + "(" + key + ")", w -> step.accept(w, key)));
        }
    }

    static final class PartialCaptureAction implements Action.Dependent<World> {
        @Override
        public boolean precondition(World world) {
            return world.keys(Expect.RESERVED).stream()
                    .anyMatch(key -> world.intents.get(key).request.amountMinor() >= 2);
        }

        @Override
        public Arbitrary<Transformer<World>> transformer(World world) {
            List<String> keys = world.keys(Expect.RESERVED).stream()
                    .filter(key -> world.intents.get(key).request.amountMinor() >= 2)
                    .toList();
            return Arbitraries.of(keys).flatMap(key -> {
                long amount = world.intents.get(key).request.amountMinor();
                return Arbitraries.longs().between(1, amount - 1).map(charged -> Transformer.mutate(
                        "PartialCapture(" + key + ", charged " + charged + " of " + amount + ")",
                        w -> w.partialCapture(key, charged)));
            });
        }
    }

    static final class ResolveProcessingAction implements Action.Dependent<World> {
        @Override
        public boolean precondition(World world) {
            return !world.keys(Expect.PROCESSING).isEmpty();
        }

        @Override
        public Arbitrary<Transformer<World>> transformer(World world) {
            return Arbitraries.of(world.keys(Expect.PROCESSING)).flatMap(key -> {
                long amount = world.intents.get(key).request.amountMinor();
                Arbitrary<Long> charged = Arbitraries.oneOf(Arbitraries.just(0L), Arbitraries.longs().between(1, amount));
                return Arbitraries.oneOf(
                        charged.map(c -> Tuple.of(true, c)),
                        Arbitraries.just(Tuple.of(false, 0L)))
                        .map(t -> Transformer.mutate(
                                "ResolveProcessing(" + key + ", " + (t.get1() ? "succeeded charging " + t.get2() : "canceled") + ")",
                                w -> w.resolveProcessing(key, t.get1(), t.get2())));
            });
        }
    }

    static final class RevokeAction implements Action.Independent<World> {
        @Override
        public boolean precondition(World world) {
            // Only once there is something in flight to settle after revocation; an early revoke
            // would turn the rest of the chain into rejected reservations.
            return !world.revoked && world.intents.size() >= 4;
        }

        @Override
        public Arbitrary<Transformer<World>> transformer() {
            return Arbitraries.just(Transformer.mutate("RevokeMandate", World::revoke));
        }
    }
}
