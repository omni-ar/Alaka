package dev.alaka.core.http;

import dev.alaka.core.SpendEngine;
import dev.alaka.yaksha.YakshaRecoverySweeper;
import dev.alaka.yaksha.YakshaRecoverySweeper.RecoveryStats;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operational metrics, exported at {@code /actuator/prometheus}.
 *
 * <ul>
 *   <li>{@code alaka_engine_serialization_failures_total}, {@code alaka_engine_deadlocks_total},
 *       {@code alaka_engine_retries_exhausted_total} (tag {@code mode}): retried {@code 40001} /
 *       {@code 40P01} and abandoned transactions. A rising rate under {@code hardened-ssi} is the
 *       hot-mandate contention the storm benchmarks measure.
 *   <li>{@code alaka_outbox_tasks} (tag {@code status}): recovery tasks per state.
 *   <li>{@code alaka_outbox_oldest_overdue_seconds}: sweeper lag, how long the oldest due task
 *       has waited.
 *   <li>{@code alaka_outbox_dead_letter_held_minor}: budget held by open intents whose recovery is
 *       dead-lettered, the capital locked until the rail resolves. Alert when it is non-zero.
 * </ul>
 * The outbox gauges read {@link YakshaRecoverySweeper#stats()} at most once every five seconds.
 */
final class AlakaMetrics implements MeterBinder {

    private static final Logger LOG = LoggerFactory.getLogger(AlakaMetrics.class);
    private static final Duration CACHE = Duration.ofSeconds(5);

    private final SpendEngine engine;
    private final YakshaRecoverySweeper sweeper;
    private RecoveryStats cached = new RecoveryStats(Map.of(), 0, 0);
    private long cachedAtNanos;

    AlakaMetrics(SpendEngine engine, YakshaRecoverySweeper sweeper) {
        this.engine = Objects.requireNonNull(engine, "engine");
        this.sweeper = sweeper;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        String mode = engine.mode().cliName();
        FunctionCounter.builder("alaka.engine.serialization.failures", engine, e -> e.metrics().serializationFailures())
                .description("Transactions that ended in SQLSTATE 40001 and were retried or abandoned")
                .tag("mode", mode).register(registry);
        FunctionCounter.builder("alaka.engine.deadlocks", engine, e -> e.metrics().deadlocks())
                .description("Transactions that ended in SQLSTATE 40P01").tag("mode", mode).register(registry);
        FunctionCounter.builder("alaka.engine.retries.exhausted", engine, e -> e.metrics().retriesExhausted())
                .description("Transactions abandoned after the retry budget ran out").tag("mode", mode).register(registry);
        if (sweeper == null) {
            return;   // --mode=naive has no recovery tasks
        }
        for (String status : List.of("PENDING", "PROCESSING", "COMPLETED", "DEAD_LETTER")) {
            Gauge.builder("alaka.outbox.tasks", this, m -> m.stats().tasksByStatus().getOrDefault(status, 0L))
                    .description("Recovery tasks per status").tag("status", status).register(registry);
        }
        Gauge.builder("alaka.outbox.oldest.overdue.seconds", this, m -> m.stats().oldestOverdueSeconds())
                .description("How long the oldest due recovery task has waited (sweeper lag)").register(registry);
        Gauge.builder("alaka.outbox.dead.letter.held.minor", this, m -> m.stats().deadLetterHeldMinor())
                .description("Budget held by open intents whose recovery is dead-lettered").register(registry);
    }

    private synchronized RecoveryStats stats() {
        long now = System.nanoTime();
        if (cachedAtNanos == 0 || now - cachedAtNanos > CACHE.toNanos()) {
            try {
                cached = sweeper.stats();
                cachedAtNanos = now;
            } catch (RuntimeException e) {
                LOG.warn("cannot read recovery statistics; serving the last values", e);
            }
        }
        return cached;
    }
}
