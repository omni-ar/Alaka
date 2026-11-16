package dev.alaka.chaos;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.core.EngineOptions;
import dev.alaka.core.IdempotencyException;
import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendEngines;
import dev.alaka.core.SpendRequest;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.property.InvariantChecker;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.testsupport.Sweeps;
import dev.alaka.yaksha.MockStripeServer;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import dev.alaka.yaksha.StripeHttpPaymentRail;
import dev.alaka.yaksha.YakshaRecoverySweeper;
import eu.rekawek.toxiproxy.Proxy;
import eu.rekawek.toxiproxy.ToxiproxyClient;
import eu.rekawek.toxiproxy.model.Toxic;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.testcontainers.Testcontainers;
import org.testcontainers.toxiproxy.ToxiproxyContainer;

/**
 * Network faults between Alaka and the payment rail, injected by a real Toxiproxy (Testcontainers)
 * in front of {@link MockStripeServer}: the hardened engine plus {@link YakshaRecoverySweeper} must
 * end every scenario with zero violations of I1-I6.
 *
 * <p>The fault "the rail applied the call but its response never arrived" is a {@code limit_data}
 * toxic of 0 bytes on the downstream (rail to Alaka) direction: the request travels upstream
 * untouched, the mock applies it, and the connection is cut as soon as the first response byte
 * reaches the proxy. The mock answers {@code Connection: close}, so every call gets its own TCP
 * connection and probabilistic toxics are decided per call.
 *
 * <p>Runs in its own database, because the sweeper sweeps every due task of the database it is
 * given.
 */
class ToxiproxyChaosTest {

    private static final String API_KEY = "sk_test_chaos";
    private static final String MERCHANT = "merchant-a";
    private static final int PROXY_PORT = 8666;
    private static final long BUDGET = 10_000;
    private static final long CAP = 2_000;

    private static MockStripeServer stripe;
    private static ToxiproxyContainer toxiproxy;
    private static Proxy proxy;
    private static URI proxiedStripe;
    private static NidhiPostgres database;
    private static HikariDataSource engineData;
    private static HikariDataSource truthData;
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    @BeforeAll
    static void startChaosRig() throws IOException {
        stripe = new MockStripeServer(API_KEY);
        stripe.closeConnectionsAfterEachResponse(true);
        int stripePort = stripe.baseUrl().getPort();
        Testcontainers.exposeHostPorts(stripePort);
        toxiproxy = new ToxiproxyContainer("ghcr.io/shopify/toxiproxy:2.12.0");
        toxiproxy.start();
        proxy = new ToxiproxyClient(toxiproxy.getHost(), toxiproxy.getControlPort())
                .createProxy("stripe", "0.0.0.0:" + PROXY_PORT, "host.testcontainers.internal:" + stripePort);
        proxiedStripe = URI.create("http://" + toxiproxy.getHost() + ":" + toxiproxy.getMappedPort(PROXY_PORT));

        database = NidhiPostgres.shared().isolatedDatabase("alaka_chaos");
        engineData = database.newAppDataSource(30);
        truthData = database.newAppDataSource(2);
    }

    @AfterAll
    static void stopChaosRig() {
        engineData.close();
        truthData.close();
        toxiproxy.stop();
        stripe.close();
    }

    @BeforeEach
    @AfterEach
    void healNetwork() throws IOException {
        for (Toxic toxic : proxy.toxics().getAll()) {
            toxic.remove();
        }
        stripe.resetState();
    }

    /** One engine talking to the mock through the proxy, one mandate, one sweeper, one checker. */
    private static final class Rig {
        final SpendEngine engine;
        final YakshaRecoverySweeper sweeper;
        final InvariantChecker checker;
        final String agent = "agent-" + UUID.randomUUID();
        final UUID mandate;
        final AtomicInteger railTimeouts = new AtomicInteger();
        int keys;

        Rig(RuntimeMode mode) {
            PaymentRailPort http = new StripeHttpPaymentRail(
                    new StripeHttpPaymentRail.Config(proxiedStripe, API_KEY, Duration.ofSeconds(3), "pm_card_visa"), HTTP);
            engine = SpendEngines.create(mode, engineData, counting(http, railTimeouts), new EngineOptions(Duration.ZERO));
            sweeper = new YakshaRecoverySweeper(engineData, engine,
                    new YakshaRecoverySweeper.Options(500, Duration.ofSeconds(30), 200, Duration.ZERO, Duration.ZERO));
            mandate = engine.createMandate(new NewMandate(
                    agent, "USD", BUDGET, CAP, List.of(MERCHANT), Duration.ofHours(1), "kid-chaos"));
            checker = new InvariantChecker(engine, stripe.state, truthData, mandate, BUDGET, CAP);
        }

        SpendRequest request(long amount) {
            return new SpendRequest(mandate, agent, "key-" + keys++, MERCHANT, "USD", amount);
        }

        IntentView intent(UUID id) {
            return engine.findIntent(id).orElseThrow();
        }

        void assertBalances(long available, long held, long settled) {
            assertThat(engine.balances(mandate)).isEqualTo(new MandateBalances(mandate, BUDGET, available, held, settled));
        }
    }

    // ------------------------------------------------------------------------------------------
    // (a) connection cut after Stripe applied /confirm, before the 200 reached Alaka

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void cutAfterConfirmIsAppliedIsRecoveredByGetAndCaptured(RuntimeMode mode) throws IOException, SQLException {
        Rig rig = new Rig(mode);
        UUID id = rig.engine.reserve(rig.request(2_000)).intent().intentId();
        rig.engine.createOnRail(id);

        Toxic cut = proxy.toxics().limitData("cut-confirm-response", ToxicDirection.DOWNSTREAM, 0);
        assertThatThrownBy(() -> rig.engine.confirmOnRail(id)).isInstanceOf(RailException.Timeout.class);
        cut.remove();

        String pi = rig.intent(id).railPaymentIntentId();
        assertThat(stripe.state.retrieve(pi).status()).as("Stripe charged the card").isEqualTo(RailPiStatus.SUCCEEDED);
        assertThat(rig.intent(id).status()).isEqualTo(IntentStatus.CONFIRMING);
        rig.assertBalances(8_000, 2_000, 0);
        rig.checker.assertHolds("the cut confirm response", true);

        Sweeps.until(rig.sweeper, () -> taskStatus(id).equals("COMPLETED"));
        assertThat(attempts(id)).as("one recovery attempt").isEqualTo(1);
        assertThat(rig.intent(id).status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(stripe.requestsTo(pi + "/confirm")).as("never re-POSTed").hasSize(1);
        assertThat(stripe.requestsTo(pi)).extracting(MockStripeServer.Recorded::method).containsExactly("GET");
        rig.assertBalances(8_000, 0, 2_000);
        assertThat(taskStatus(id)).isEqualTo("COMPLETED");
        rig.checker.assertHolds("sweeper recovery", true);
    }

    // ------------------------------------------------------------------------------------------
    // (b) connection cut after Stripe created the unconfirmed PI, before its id reached Alaka

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void cutAfterCreateLeavesAHarmlessOrphanAndTheReservationIsVoided(RuntimeMode mode)
            throws IOException, SQLException {
        Rig rig = new Rig(mode);
        UUID id = rig.engine.reserve(rig.request(2_000)).intent().intentId();

        Toxic cut = proxy.toxics().limitData("cut-create-response", ToxicDirection.DOWNSTREAM, 0);
        assertThatThrownBy(() -> rig.engine.createOnRail(id)).isInstanceOf(RailException.Timeout.class);
        cut.remove();

        RailPaymentIntent orphan = stripe.state.findByIntentId(id).orElseThrow();
        assertThat(orphan.status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
        assertThat(rig.intent(id).status()).isEqualTo(IntentStatus.RESERVED);
        assertThat(rig.intent(id).railPaymentIntentId()).isNull();

        Sweeps.until(rig.sweeper, () -> taskStatus(id).equals("COMPLETED"));
        assertThat(attempts(id)).as("one recovery attempt").isEqualTo(1);
        assertThat(rig.intent(id).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(stripe.state.retrieve(orphan.piId()).status())
                .as("unconfirmed, so it can never move money").isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
        assertThat(stripe.state.totalChargedMinor()).isZero();
        assertThat(stripe.requestsTo("/confirm")).isEmpty();
        rig.assertBalances(BUDGET, 0, 0);
        assertThat(taskStatus(id)).isEqualTo("COMPLETED");
        rig.checker.assertHolds("sweeper void", true);
    }

    // ------------------------------------------------------------------------------------------
    // (c) latency spike + resets + cut responses while 20 virtual threads storm one mandate

    enum Outcome {
        CAPTURED,
        VOIDED,
        STILL_OPEN,
        REPLAYED,
        REJECTED_SG003,
        REJECTED_409,
        REJECTED_422,
        RAIL_UNREACHABLE,
        RETRIES_EXHAUSTED
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void degradedNetworkStormEndsWithZeroViolations(RuntimeMode mode) throws Exception {
        Rig rig = new Rig(mode);
        proxy.toxics().latency("latency", ToxicDirection.DOWNSTREAM, 225).setJitter(75);   // 150-300 ms
        proxy.toxics().resetPeer("reset-20pct", ToxicDirection.UPSTREAM, 0).setToxicity(0.20f);
        proxy.toxics().limitData("cut-response-10pct", ToxicDirection.DOWNSTREAM, 0).setToxicity(0.10f);

        List<SpendRequest> requests = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            requests.add(rig.request(1_000));
        }
        for (int i = 0; i < 4; i++) {          // retry storm: duplicates, half of them tampered
            SpendRequest original = requests.get(i);
            requests.add(new SpendRequest(original.mandateId(), original.agentId(), original.idempotencyKey(),
                    MERCHANT, "USD", i % 2 == 0 ? original.amountMinor() : original.amountMinor() - 1));
        }

        Map<Outcome, Integer> outcomes = new EnumMap<>(Outcome.class);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Outcome>> futures = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (SpendRequest request : requests) {
                futures.add(pool.submit(() -> {
                    go.await();
                    try {
                        var result = rig.engine.execute(request);
                        if (result.replayed()) {
                            return Outcome.REPLAYED;
                        }
                        return switch (result.intent().status()) {
                            case CAPTURED -> Outcome.CAPTURED;
                            case VOIDED, FAILED -> Outcome.VOIDED;
                            default -> Outcome.STILL_OPEN;
                        };
                    } catch (NidhiException.BudgetExceeded e) {
                        return Outcome.REJECTED_SG003;
                    } catch (IdempotencyException.InFlight e) {
                        return Outcome.REJECTED_409;
                    } catch (IdempotencyException.PayloadMismatch e) {
                        return Outcome.REJECTED_422;
                    } catch (RailException e) {
                        return Outcome.RAIL_UNREACHABLE;      // recovery itself could not reach the rail
                    } catch (NidhiException.SerializationFailure e) {
                        return Outcome.RETRIES_EXHAUSTED;
                    }
                }));
            }
            go.countDown();
            for (Future<Outcome> future : futures) {
                outcomes.merge(future.get(), 1, Integer::sum);
            }
        }
        rig.checker.assertHolds("the storm, before recovery", true);

        // The sweeper keeps working while the network is still degraded.
        int rounds = 0;
        while (openTasks(rig.mandate) > 0 && rounds < 100) {
            rig.sweeper.sweepOnce();
            rounds++;
        }
        assertThat(openTasks(rig.mandate)).as("every recovery task completed under faults").isZero();
        assertThat(rig.engine.intentsOf(rig.mandate)).allMatch(i -> i.status().isTerminal());

        InvariantChecker.Report report = rig.checker.assertHolds("the storm and its recovery", true);
        assertThat(report.balances().settledMinor()).isEqualTo(stripe.state.totalChargedMinor());
        assertThat(stripe.state.totalChargedMinor()).isLessThanOrEqualTo(BUDGET);
        Map<String, Integer> chargesPerKey = new java.util.HashMap<>();
        for (IntentView intent : report.intents()) {
            for (RailPaymentIntent pi : report.railIntentsOf(intent.intentId())) {
                if (pi.status() == RailPiStatus.SUCCEEDED) {
                    chargesPerKey.merge(intent.idempotencyKey(), 1, Integer::sum);
                }
            }
        }
        assertThat(chargesPerKey.values()).as("no double charge").allMatch(n -> n == 1);
        assertThat(rig.railTimeouts.get()).as("the chaos actually bit").isPositive();

        System.out.printf("CHAOS %s: outcomes=%s, rail calls that failed=%d, sweep rounds=%d, captured=%d, "
                        + "voided=%d, settled=%d, rail charged=%d, budget=%d%n",
                mode.cliName(), outcomes, rig.railTimeouts.get(), rounds,
                report.intents().stream().filter(i -> i.status() == IntentStatus.CAPTURED).count(),
                report.intents().stream().filter(i -> i.status() == IntentStatus.VOIDED).count(),
                report.balances().settledMinor(), stripe.state.totalChargedMinor(), BUDGET);
    }

    // ------------------------------------------------------------------------------------------

    /** Counts calls whose outcome the network made unknown. */
    private static PaymentRailPort counting(PaymentRailPort rail, AtomicInteger timeouts) {
        return new PaymentRailPort() {
            @Override
            public RailPaymentIntent createUnconfirmed(String key, UUID intentId, String merchant, String currency, long amount) {
                return counted(() -> rail.createUnconfirmed(key, intentId, merchant, currency, amount));
            }

            @Override
            public RailPaymentIntent confirm(String piId, String key) {
                return counted(() -> rail.confirm(piId, key));
            }

            @Override
            public RailPaymentIntent retrieve(String piId) {
                return counted(() -> rail.retrieve(piId));
            }

            @Override
            public RailPaymentIntent cancel(String piId) {
                return counted(() -> rail.cancel(piId));
            }

            private RailPaymentIntent counted(java.util.function.Supplier<RailPaymentIntent> call) {
                try {
                    return call.get();
                } catch (RailException.Timeout e) {
                    timeouts.incrementAndGet();
                    throw e;
                }
            }
        };
    }

    private static String taskStatus(UUID intentId) throws SQLException {
        try (Connection c = truthData.getConnection();
                PreparedStatement ps = c.prepareStatement("SELECT status FROM outbox_tasks WHERE intent_id = ?")) {
            ps.setObject(1, intentId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : "NO_TASK";
            }
        }
    }

    private static long attempts(UUID intentId) throws SQLException {
        try (Connection c = truthData.getConnection();
                PreparedStatement ps = c.prepareStatement("SELECT attempts FROM outbox_tasks WHERE intent_id = ?")) {
            ps.setObject(1, intentId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private static long openTasks(UUID mandateId) throws SQLException {
        try (Connection c = truthData.getConnection();
                PreparedStatement ps = c.prepareStatement(
                        "SELECT count(*) FROM outbox_tasks t JOIN payment_intents i USING (intent_id)"
                                + " WHERE i.mandate_id = ? AND t.status <> 'COMPLETED'")) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }
}
