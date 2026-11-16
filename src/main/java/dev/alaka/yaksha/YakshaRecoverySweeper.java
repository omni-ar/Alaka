package dev.alaka.yaksha;

import dev.alaka.core.SpendEngine;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.TransactionRunner;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import javax.sql.DataSource;

/**
 * Drives intents whose request died mid-flight (crash, timeout, lost response) to a terminal state,
 * through the engine's recovery protocol ({@link SpendEngine#recoverOrVoid}), which never voids
 * blindly.
 *
 * <p>Every intent gets a recovery task in {@code outbox_tasks} in its Phase 1 transaction, due once
 * the request has had its grace period; the transaction that settles the intent completes the
 * task. A sweep:
 * <ol>
 *   <li>claims up to {@code batchSize} due tasks in one short transaction: {@code PENDING} tasks
 *       whose {@code next_attempt_at} has passed and {@code PROCESSING} tasks whose lease expired
 *       (their sweeper died), with {@code FOR UPDATE SKIP LOCKED} so concurrent sweepers never
 *       claim the same task, marking them {@code PROCESSING} under a fresh lease;
 *   <li>outside any transaction, runs {@code recoverOrVoid} on each claimed intent (rail calls);
 *   <li>records the result: {@code COMPLETED} if the intent is terminal; otherwise (the rail is
 *       still processing, or recovery failed) back to {@code PENDING} with exponential backoff, or
 *       {@code DEAD_LETTER} once {@code maxAttempts} is reached. A dead-lettered intent keeps its
 *       hold: nothing is released until a human or a later event resolves it.
 * </ol>
 * Result updates only apply while this sweeper still holds the claim (same status and attempt
 * number), so a sweeper whose lease expired cannot overwrite a newer claim.
 */
public final class YakshaRecoverySweeper {

    /**
     * Sweeper tunables.
     *
     * @param batchSize tasks claimed per sweep
     * @param lease how long a claim is exclusive; must exceed the longest recovery
     * @param maxAttempts attempts before a task is dead-lettered
     * @param baseBackoff delay after the first failed attempt, doubled per attempt
     * @param maxBackoff upper bound of the delay
     */
    public record Options(int batchSize, Duration lease, int maxAttempts, Duration baseBackoff, Duration maxBackoff) {

        /** Defaults: 50 tasks, 60 s lease, 10 attempts, backoff 1 s doubling up to 5 min. */
        public static final Options DEFAULTS =
                new Options(50, Duration.ofSeconds(60), 10, Duration.ofSeconds(1), Duration.ofMinutes(5));

        public Options {
            if (batchSize < 1 || maxAttempts < 1) {
                throw new IllegalArgumentException("batchSize and maxAttempts must be positive");
            }
            Objects.requireNonNull(lease, "lease");
            Objects.requireNonNull(baseBackoff, "baseBackoff");
            Objects.requireNonNull(maxBackoff, "maxBackoff");
        }
    }

    /**
     * What one sweep did.
     *
     * @param claimed tasks claimed
     * @param completed tasks whose intent reached a terminal state
     * @param rescheduled tasks put back for a later attempt
     * @param deadLettered tasks given up on
     */
    public record SweepReport(int claimed, int completed, int rescheduled, int deadLettered) {
    }

    private record Claim(UUID taskId, UUID intentId, int attempts) {
    }

    private final TransactionRunner tx;
    private final SpendEngine engine;
    private final Options options;

    /**
     * Creates a sweeper.
     *
     * @param appDataSource connections as {@code alaka_app}
     * @param engine a hardened engine
     * @param options tunables
     */
    public YakshaRecoverySweeper(DataSource appDataSource, SpendEngine engine, Options options) {
        this.tx = new TransactionRunner(appDataSource, TransactionRunner.Isolation.READ_COMMITTED,
                new TransactionRunner.RetryPolicy(5, Duration.ofMillis(5), Duration.ofMillis(100)));
        this.engine = Objects.requireNonNull(engine, "engine");
        this.options = Objects.requireNonNull(options, "options");
    }

    /**
     * Runs one sweep.
     *
     * @return what it did
     */
    public SweepReport sweepOnce() {
        List<Claim> claims = claim();
        int completed = 0;
        int rescheduled = 0;
        int deadLettered = 0;
        for (Claim claim : claims) {
            String error = null;
            boolean terminal;
            try {
                IntentView after = engine.recoverOrVoid(claim.intentId());
                terminal = after.status().isTerminal();
                if (!terminal) {
                    error = "intent still " + after.status() + " (rail payment intent not settled)";
                }
            } catch (RuntimeException e) {
                terminal = false;
                error = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            if (terminal) {
                finish(claim, "COMPLETED", null, 0);
                completed++;
            } else if (claim.attempts() >= options.maxAttempts()) {
                finish(claim, "DEAD_LETTER", error, 0);
                deadLettered++;
            } else {
                finish(claim, "PENDING", error, backoffMillis(claim.attempts()));
                rescheduled++;
            }
        }
        return new SweepReport(claims.size(), completed, rescheduled, deadLettered);
    }

    private List<Claim> claim() {
        return tx.inTransaction(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "WITH due AS ("
                            + "  SELECT task_id FROM outbox_tasks"
                            + "   WHERE (status = 'PENDING' AND next_attempt_at <= NOW())"
                            + "      OR (status = 'PROCESSING' AND locked_until < NOW())"
                            + "   ORDER BY next_attempt_at"
                            + "   LIMIT ? FOR UPDATE SKIP LOCKED)"
                            + " UPDATE outbox_tasks t SET status = 'PROCESSING', attempts = t.attempts + 1,"
                            + "        locked_until = NOW() + ? * INTERVAL '1 millisecond', updated_at = NOW()"
                            + "   FROM due WHERE t.task_id = due.task_id"
                            + " RETURNING t.task_id, t.intent_id, t.attempts")) {
                ps.setInt(1, options.batchSize());
                ps.setLong(2, options.lease().toMillis());
                List<Claim> claims = new ArrayList<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        claims.add(new Claim(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getInt(3)));
                    }
                }
                return claims;
            }
        });
    }

    private void finish(Claim claim, String status, String error, long delayMillis) {
        tx.inTransaction(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE outbox_tasks SET status = ?, last_error = ?, locked_until = NULL,"
                            + " next_attempt_at = NOW() + ? * INTERVAL '1 millisecond', updated_at = NOW()"
                            + " WHERE task_id = ? AND status = 'PROCESSING' AND attempts = ?")) {
                ps.setString(1, status);
                ps.setString(2, error);
                ps.setLong(3, delayMillis);
                ps.setObject(4, claim.taskId());
                ps.setInt(5, claim.attempts());
                return ps.executeUpdate();
            }
        });
    }

    /** Exponential backoff with equal jitter: uniform in [window/2, window]. */
    private long backoffMillis(int failedAttempts) {
        long base = options.baseBackoff().toMillis();
        long window = Math.min(options.maxBackoff().toMillis(), base << Math.min(failedAttempts - 1, 30));
        return window / 2 + ThreadLocalRandom.current().nextLong(window / 2 + 1);
    }
}
