package dev.alaka.nidhi;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.core.EngineMetrics;
import dev.alaka.core.IdempotencyException;
import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendEngines;
import dev.alaka.core.SpendRequest;
import dev.alaka.core.SpendResult;
import dev.alaka.property.InvariantChecker;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * The same hostile workload against all three runtime modes: 50 virtual threads released together
 * against one mandate, with rail latency so that check-then-act windows overlap.
 *
 * <p>Workload ({@value #THREADS} requests): {@value #DISTINCT_KEYS} distinct spends of
 * {@value #AMOUNT} against a budget of {@value #BUDGET} (demand four times the budget), plus a
 * retry storm of {@value #RETRIES} requests that re-send keys already in use by other threads,
 * half of them with a tampered payload.
 *
 * <p>{@code NAIVE} must overspend on the rail every run (that is what the baseline is for). Both
 * hardened modes must end with zero violations of I1-I6, at most one charge per idempotency key,
 * and ledger settled equal to the rail's total once every intent is terminal.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ConcurrencyStormTest {

    static final int THREADS = 50;
    static final int DISTINCT_KEYS = 40;
    static final int RETRIES = THREADS - DISTINCT_KEYS;
    static final long AMOUNT = 1_000;
    static final long BUDGET = 10_000;
    static final long CAP = 2_000;
    private static final String MERCHANT = "merchant-a";

    private static HikariDataSource engineData;
    private static HikariDataSource truthData;
    private static final Map<String, String> REPORTS = new java.util.LinkedHashMap<>();

    @BeforeAll
    static void startPools() {
        engineData = NidhiPostgres.shared().newAppDataSource(THREADS + 5);
        truthData = NidhiPostgres.shared().newAppDataSource(2);
    }

    @AfterAll
    static void closePoolsAndWriteReport() throws IOException, URISyntaxException {
        engineData.close();
        truthData.close();
        Path classes = Path.of(ConcurrencyStormTest.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path report = classes.getParent().resolve("storm-report.txt");
        Files.writeString(report, String.join("\n", REPORTS.values()) + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println("STORM report written to " + report);
    }

    /** What happened to one request. */
    enum Outcome {
        CAPTURED,
        REPLAYED,
        OTHER_TERMINAL_OR_OPEN,
        REJECTED_SG003,
        REJECTED_409,
        REJECTED_422,
        RETRIES_EXHAUSTED,
        UNEXPECTED
    }

    private record Result(int thread, String key, Outcome outcome, long nanos, Throwable unexpected) {
    }

    private record Run(
            RuntimeMode mode,
            SpendEngine engine,
            SimulatedPaymentRail rail,
            UUID mandate,
            List<Result> results,
            long wallNanos) {
    }

    @Test
    @Order(1)
    void naiveOverspendsTheRail() throws Exception {
        Run run = storm(RuntimeMode.NAIVE);
        long charged = run.rail().totalChargedMinor();

        assertThat(charged)
                .as("NAIVE must overspend on the rail: that is the point of the baseline")
                .isGreaterThan(BUDGET);
        InvariantChecker.Report report = checker(run).check(true);
        assertThat(report.violations()).anySatisfy(v -> assertThat(v.invariant()).isEqualTo("I1"));
        record(run, report);
    }

    @Test
    @Order(2)
    void hardenedPessimisticHasZeroViolations() throws Exception {
        assertHardened(storm(RuntimeMode.HARDENED_PESSIMISTIC));
    }

    @Test
    @Order(3)
    void hardenedSsiHasZeroViolations() throws Exception {
        assertHardened(storm(RuntimeMode.HARDENED_SSI));
    }

    // ------------------------------------------------------------------------------------------
    // Ten mandates at once: the same 50 threads, but spread over independent balance rows

    static final int MANDATES = 10;
    static final int THREADS_PER_MANDATE = 5;
    static final long MULTI_AMOUNT = 3_000;
    static final long MULTI_CAP = 3_000;

    @Test
    @Order(4)
    void tenMandatesPessimisticHaveZeroViolationsAndNoDeadlocks() throws Exception {
        multiMandateStorm(RuntimeMode.HARDENED_PESSIMISTIC);
    }

    @Test
    @Order(5)
    void tenMandatesSsiHaveZeroViolationsAndNoDeadlocks() throws Exception {
        multiMandateStorm(RuntimeMode.HARDENED_SSI);
    }

    private record Lane(SpendEngine engine, SimulatedPaymentRail rail, UUID mandate, String agent) {
    }

    /**
     * 10 engines, each with its own rail and mandate (budget 10,000, cap 3,000), sharing one
     * connection pool; 5 threads per mandate spend 3,000 each, all 50 released by one latch. Each
     * mandate fits three spends, so every lane also exhausts its budget.
     */
    private static void multiMandateStorm(RuntimeMode mode) throws Exception {
        List<Lane> lanes = new ArrayList<>();
        for (int m = 0; m < MANDATES; m++) {
            SimulatedPaymentRail rail = new SimulatedPaymentRail();
            rail.setLatency(Duration.ofMillis(5), Duration.ofMillis(15));
            SpendEngine engine = SpendEngines.create(mode, engineData, rail);
            String agent = "multi-" + mode.cliName() + "-" + m + "-" + UUID.randomUUID();
            UUID mandate = engine.createMandate(new dev.alaka.nidhi.NewMandate(
                    agent, "USD", BUDGET, MULTI_CAP, List.of(MERCHANT), Duration.ofHours(1), "kid-storm"));
            lanes.add(new Lane(engine, rail, mandate, agent));
        }
        long[] scansBefore = postingScans();

        CountDownLatch ready = new CountDownLatch(MANDATES * THREADS_PER_MANDATE);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Result>> futures = new ArrayList<>();
        long wallNanos;
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int m = 0; m < MANDATES; m++) {
                Lane lane = lanes.get(m);
                for (int t = 0; t < THREADS_PER_MANDATE; t++) {
                    int thread = m * THREADS_PER_MANDATE + t;
                    SpendRequest request = new SpendRequest(lane.mandate(), lane.agent(), "multi-key-" + t, MERCHANT,
                            "USD", MULTI_AMOUNT);
                    futures.add(pool.submit(() -> {
                        ready.countDown();
                        go.await();
                        return execute(lane.engine(), request, thread);
                    }));
                }
            }
            ready.await();
            long wallStart = System.nanoTime();
            go.countDown();
            for (Future<Result> future : futures) {
                future.get();
            }
            wallNanos = System.nanoTime() - wallStart;
        }
        List<Result> results = new ArrayList<>();
        for (Future<Result> future : futures) {
            results.add(future.get());
        }
        assertThat(results).noneMatch(r -> r.outcome() == Outcome.UNEXPECTED);

        long serializationFailures = 0;
        long deadlocks = 0;
        long exhausted = 0;
        long settled = 0;
        long charged = 0;
        int violations = 0;
        for (Lane lane : lanes) {
            for (var intent : lane.engine().intentsOf(lane.mandate())) {
                if (!intent.status().isTerminal()) {
                    lane.engine().recoverOrVoid(intent.intentId());
                }
            }
            InvariantChecker.Report report = new InvariantChecker(lane.engine(), lane.rail(), truthData, lane.mandate(),
                    BUDGET, MULTI_CAP).assertHolds("the ten-mandate storm", true);
            violations += report.violations().size();
            assertThat(report.balances().settledMinor()).isEqualTo(lane.rail().totalChargedMinor());
            assertThat(lane.rail().totalChargedMinor()).isLessThanOrEqualTo(BUDGET);
            settled += report.balances().settledMinor();
            charged += lane.rail().totalChargedMinor();
            EngineMetrics metrics = lane.engine().metrics();
            serializationFailures += metrics.serializationFailures();
            deadlocks += metrics.deadlocks();
            exhausted += metrics.retriesExhausted();
        }
        assertThat(deadlocks).as("no deadlock across independent mandates (40P01)").isZero();

        Thread.sleep(1_500);   // other backends flush their table statistics within a second of going idle
        long[] scansAfter = postingScans();

        Map<Outcome, Integer> counts = new EnumMap<>(Outcome.class);
        long[] latencies = new long[results.size()];
        for (int i = 0; i < latencies.length; i++) {
            counts.merge(results.get(i).outcome(), 1, Integer::sum);
            latencies[i] = results.get(i).nanos();
        }
        Arrays.sort(latencies);
        double wallMs = wallNanos / 1e6;
        StringBuilder out = new StringBuilder();
        out.append("=== STORM multi-mandate ").append(mode.cliName()).append(" ===\n");
        line(out, "mandates x threads", MANDATES + " x " + THREADS_PER_MANDATE);
        line(out, "requests attempted", String.valueOf(results.size()));
        line(out, "succeeded (captured)", String.valueOf(counts.getOrDefault(Outcome.CAPTURED, 0)));
        line(out, "rejected SG003 (budget)", String.valueOf(counts.getOrDefault(Outcome.REJECTED_SG003, 0)));
        line(out, "retries exhausted (40001/40P01)", String.valueOf(counts.getOrDefault(Outcome.RETRIES_EXHAUSTED, 0)));
        line(out, "rail total charged vs budget", charged + " / " + (BUDGET * MANDATES));
        line(out, "ledger settled", String.valueOf(settled));
        line(out, "invariant violations", String.valueOf(violations));
        line(out, "latency p50 / p95 / p99 (ms)", String.format(Locale.ROOT, "%.1f / %.1f / %.1f",
                percentile(latencies, 50), percentile(latencies, 95), percentile(latencies, 99)));
        line(out, "wall time (ms)", String.format(Locale.ROOT, "%.1f", wallMs));
        line(out, "throughput (req/s)", String.format(Locale.ROOT, "%.1f", results.size() / (wallMs / 1000)));
        line(out, "40001 / 40P01 / retries exhausted", serializationFailures + " / " + deadlocks + " / " + exhausted);
        line(out, "ledger_postings seq / index scans", (scansAfter[0] - scansBefore[0]) + " / "
                + (scansAfter[1] - scansBefore[1]) + " (storm + its invariant check, all sessions)");
        String text = out.toString();
        System.out.print(text);
        REPORTS.put("multi-" + mode.cliName(), text);
    }

    private static Result execute(SpendEngine engine, SpendRequest request, int thread) {
        long start = System.nanoTime();
        Outcome outcome;
        Throwable unexpected = null;
        try {
            SpendResult result = engine.execute(request);
            outcome = result.replayed() ? Outcome.REPLAYED
                    : result.intent().status() == dev.alaka.nidhi.IntentStatus.CAPTURED ? Outcome.CAPTURED
                    : Outcome.OTHER_TERMINAL_OR_OPEN;
        } catch (NidhiException.BudgetExceeded e) {
            outcome = Outcome.REJECTED_SG003;
        } catch (IdempotencyException.InFlight e) {
            outcome = Outcome.REJECTED_409;
        } catch (IdempotencyException.PayloadMismatch e) {
            outcome = Outcome.REJECTED_422;
        } catch (NidhiException.SerializationFailure | NidhiException.DeadlockDetected e) {
            outcome = Outcome.RETRIES_EXHAUSTED;
        } catch (RuntimeException e) {
            outcome = Outcome.UNEXPECTED;
            unexpected = e;
            e.printStackTrace();
        }
        return new Result(thread, request.idempotencyKey(), outcome, System.nanoTime() - start, unexpected);
    }

    /** Cumulative sequential and index scans of {@code ledger_postings}, from the statistics collector. */
    private static long[] postingScans() throws java.sql.SQLException {
        try (java.sql.Connection c = truthData.getConnection();
                java.sql.Statement s = c.createStatement();
                java.sql.ResultSet rs = s.executeQuery("SELECT seq_scan, COALESCE(idx_scan, 0) FROM pg_stat_user_tables"
                        + " WHERE relname = 'ledger_postings'")) {
            rs.next();
            return new long[] {rs.getLong(1), rs.getLong(2)};
        }
    }

    private void assertHardened(Run run) {
        assertThat(run.results()).noneMatch(r -> r.outcome() == Outcome.UNEXPECTED);
        // Drive any straggler to a terminal state before the final check.
        for (var intent : run.engine().intentsOf(run.mandate())) {
            if (!intent.status().isTerminal()) {
                run.engine().recoverOrVoid(intent.intentId());
            }
        }
        InvariantChecker.Report report = checker(run).assertHolds("the storm", true);
        assertThat(report.balances().settledMinor()).isEqualTo(run.rail().totalChargedMinor());
        assertThat(run.rail().totalChargedMinor()).isLessThanOrEqualTo(BUDGET);

        Map<String, Integer> chargesPerKey = new HashMap<>();
        for (var intent : report.intents()) {
            for (RailPaymentIntent pi : report.railIntentsOf(intent.intentId())) {
                if (pi.chargedMinor() > 0) {
                    chargesPerKey.merge(intent.idempotencyKey(), 1, Integer::sum);
                }
            }
        }
        assertThat(chargesPerKey.values()).allMatch(n -> n == 1);

        // A request that was charged on the rail must never have been reported as failed.
        long capturedResults = run.results().stream().filter(r -> r.outcome() == Outcome.CAPTURED).count();
        long capturedIntents = report.intents().stream()
                .filter(i -> i.status() == dev.alaka.nidhi.IntentStatus.CAPTURED).count();
        assertThat(capturedResults).isEqualTo(capturedIntents);
        record(run, report);
    }

    private static Run storm(RuntimeMode mode) throws Exception {
        SimulatedPaymentRail rail = new SimulatedPaymentRail();
        rail.setLatency(Duration.ofMillis(5), Duration.ofMillis(15));
        SpendEngine engine = SpendEngines.create(mode, engineData, rail);
        String agent = "storm-" + mode.cliName() + "-" + UUID.randomUUID();
        UUID mandate = engine.createMandate(new dev.alaka.nidhi.NewMandate(
                agent, "USD", BUDGET, CAP, List.of(MERCHANT), Duration.ofHours(1), "kid-storm"));

        List<SpendRequest> requests = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            int keyIndex = i < DISTINCT_KEYS ? i : i - DISTINCT_KEYS;
            boolean tampered = i >= DISTINCT_KEYS && i % 2 == 1;
            requests.add(new SpendRequest(mandate, agent, "storm-key-" + keyIndex, MERCHANT, "USD",
                    tampered ? AMOUNT - 1 : AMOUNT));
        }

        CountDownLatch ready = new CountDownLatch(THREADS);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Result>> futures = new ArrayList<>();
        long wallStart;
        long wallNanos;
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < THREADS; i++) {
                int thread = i;
                SpendRequest request = requests.get(i);
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    long start = System.nanoTime();
                    Outcome outcome;
                    Throwable unexpected = null;
                    try {
                        SpendResult result = engine.execute(request);
                        outcome = result.replayed() ? Outcome.REPLAYED
                                : result.intent().status() == dev.alaka.nidhi.IntentStatus.CAPTURED ? Outcome.CAPTURED
                                : Outcome.OTHER_TERMINAL_OR_OPEN;
                    } catch (NidhiException.BudgetExceeded e) {
                        outcome = Outcome.REJECTED_SG003;
                    } catch (IdempotencyException.InFlight e) {
                        outcome = Outcome.REJECTED_409;
                    } catch (IdempotencyException.PayloadMismatch e) {
                        outcome = Outcome.REJECTED_422;
                    } catch (NidhiException.SerializationFailure | NidhiException.DeadlockDetected e) {
                        outcome = Outcome.RETRIES_EXHAUSTED;
                    } catch (RuntimeException e) {
                        outcome = Outcome.UNEXPECTED;
                        unexpected = e;
                    }
                    return new Result(thread, request.idempotencyKey(), outcome, System.nanoTime() - start, unexpected);
                }));
            }
            ready.await();
            wallStart = System.nanoTime();
            go.countDown();
            for (Future<Result> future : futures) {
                future.get();
            }
            wallNanos = System.nanoTime() - wallStart;
        }
        List<Result> results = new ArrayList<>();
        for (Future<Result> future : futures) {
            Result result = future.get();
            if (result.unexpected() != null) {
                result.unexpected().printStackTrace();
            }
            results.add(result);
        }
        return new Run(mode, engine, rail, mandate, results, wallNanos);
    }

    private static InvariantChecker checker(Run run) {
        return new InvariantChecker(run.engine(), run.rail(), truthData, run.mandate(), BUDGET, CAP);
    }

    private static void record(Run run, InvariantChecker.Report report) {
        Map<Outcome, Integer> counts = new EnumMap<>(Outcome.class);
        for (Outcome outcome : Outcome.values()) {
            counts.put(outcome, 0);
        }
        long[] latencies = new long[run.results().size()];
        for (int i = 0; i < latencies.length; i++) {
            Result r = run.results().get(i);
            counts.merge(r.outcome(), 1, Integer::sum);
            latencies[i] = r.nanos();
        }
        Arrays.sort(latencies);
        long charged = run.rail().totalChargedMinor();
        EngineMetrics metrics = run.engine().metrics();
        Map<String, Long> violationsByInvariant = new java.util.TreeMap<>();
        report.violations().forEach(v -> violationsByInvariant.merge(v.invariant(), 1L, Long::sum));
        double wallMs = run.wallNanos() / 1e6;

        StringBuilder out = new StringBuilder();
        out.append("=== STORM ").append(run.mode().cliName()).append(" ===\n");
        line(out, "requests attempted", String.valueOf(run.results().size()));
        line(out, "succeeded (captured)", String.valueOf(counts.get(Outcome.CAPTURED)));
        line(out, "replayed (terminal duplicate)", String.valueOf(counts.get(Outcome.REPLAYED)));
        line(out, "rejected SG003 (budget)", String.valueOf(counts.get(Outcome.REJECTED_SG003)));
        line(out, "rejected 409 (in flight)", String.valueOf(counts.get(Outcome.REJECTED_409)));
        line(out, "rejected 422 (payload mismatch)", String.valueOf(counts.get(Outcome.REJECTED_422)));
        line(out, "retries exhausted (40001/40P01)", String.valueOf(counts.get(Outcome.RETRIES_EXHAUSTED)));
        line(out, "other / unexpected", counts.get(Outcome.OTHER_TERMINAL_OR_OPEN) + " / " + counts.get(Outcome.UNEXPECTED));
        line(out, "rail total charged vs budget", charged + " / " + BUDGET);
        line(out, "overspend", String.valueOf(Math.max(0, charged - BUDGET)));
        line(out, "rail payment intents", String.valueOf(report.railIntents().size()));
        line(out, "ledger/engine settled", String.valueOf(report.balances().settledMinor()));
        line(out, "invariant violations", report.violations().size() + " " + violationsByInvariant);
        line(out, "latency p50 / p95 / p99 (ms)", String.format(Locale.ROOT, "%.1f / %.1f / %.1f",
                percentile(latencies, 50), percentile(latencies, 95), percentile(latencies, 99)));
        line(out, "wall time (ms)", String.format(Locale.ROOT, "%.1f", wallMs));
        line(out, "throughput (req/s)", String.format(Locale.ROOT, "%.1f", run.results().size() / (wallMs / 1000)));
        line(out, "40001 / 40P01 / retries exhausted", metrics.serializationFailures() + " / " + metrics.deadlocks()
                + " / " + metrics.retriesExhausted());
        String text = out.toString();
        System.out.print(text);
        REPORTS.put("single-" + run.mode().cliName(), text);
    }

    private static void line(StringBuilder out, String label, String value) {
        out.append(String.format(Locale.ROOT, "STORM %-22s %-34s %s%n", "", label, value).replaceFirst("STORM {23}", "STORM  "));
    }

    private static double percentile(long[] sorted, int p) {
        int index = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))] / 1e6;
    }
}
