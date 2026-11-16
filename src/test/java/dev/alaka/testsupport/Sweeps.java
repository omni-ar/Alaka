package dev.alaka.testsupport;

import dev.alaka.yaksha.YakshaRecoverySweeper;
import java.sql.SQLException;
import java.time.Duration;

/**
 * Drives a recovery sweeper until a condition holds.
 *
 * <p>A task written with a zero grace period is due at its creating backend's {@code NOW()}, and
 * PostgreSQL backends have been measured disagreeing about the time by hundreds of milliseconds,
 * so the sweeper's backend may see it as not yet due on the first pass. Tests that care how many
 * recovery attempts a task needed assert {@code outbox_tasks.attempts}, not the number of sweeps.
 */
public final class Sweeps {

    /** A condition read from the database. */
    @FunctionalInterface
    public interface Condition {
        boolean holds() throws SQLException;
    }

    private static final int MAX_SWEEPS = 50;
    private static final Duration PAUSE = Duration.ofMillis(100);

    private Sweeps() {
    }

    /**
     * Sweeps until {@code done} holds.
     *
     * @param sweeper the sweeper
     * @param done the condition
     * @return how many sweeps it took
     * @throws SQLException if the condition cannot be read
     * @throws AssertionError if it does not hold after 50 sweeps
     */
    public static int until(YakshaRecoverySweeper sweeper, Condition done) throws SQLException {
        for (int sweeps = 1; sweeps <= MAX_SWEEPS; sweeps++) {
            sweeper.sweepOnce();
            if (done.holds()) {
                return sweeps;
            }
            try {
                Thread.sleep(PAUSE);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while sweeping", e);
            }
        }
        throw new AssertionError("condition not reached after " + MAX_SWEEPS + " sweeps");
    }
}
