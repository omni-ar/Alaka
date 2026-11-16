package dev.alaka.nidhi;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import javax.sql.DataSource;

/**
 * Runs units of work in database transactions at a fixed isolation level, retrying the whole unit
 * on serialization failures ({@code 40001}) and deadlocks ({@code 40P01}) with bounded exponential
 * backoff and full jitter.
 *
 * <p>Every exception leaving a unit of work, including one raised by {@code COMMIT} (where the
 * deferred Nidhi guards report), is translated into a {@link NidhiException}, the transaction is
 * rolled back and the connection is returned to the pool clean.
 *
 * <p>While a unit of work runs, {@link #inTransaction()} is {@code true} on the calling thread.
 * The engine's rail guard checks it, which is how "no transaction or row lock is ever held across
 * a rail call" is enforced at run time rather than only by convention.
 */
public final class TransactionRunner {

    /** Isolation level of every transaction a runner opens. */
    public enum Isolation {
        READ_COMMITTED(Connection.TRANSACTION_READ_COMMITTED),
        SERIALIZABLE(Connection.TRANSACTION_SERIALIZABLE);

        private final int jdbcLevel;

        Isolation(int jdbcLevel) {
            this.jdbcLevel = jdbcLevel;
        }
    }

    /**
     * A unit of work run inside one transaction. It may be run more than once, so it must not
     * have side effects outside the database.
     *
     * @param <T> the result type
     */
    @FunctionalInterface
    public interface Work<T> {
        T run(Connection connection) throws SQLException;
    }

    /**
     * Retry budget for retryable failures.
     *
     * @param maxAttempts total attempts, at least 1
     * @param baseDelay backoff before the second attempt, doubled after every further failure
     * @param maxDelay upper bound of the backoff window
     */
    public record RetryPolicy(int maxAttempts, Duration baseDelay, Duration maxDelay) {

        public RetryPolicy {
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("maxAttempts must be at least 1: " + maxAttempts);
            }
            Objects.requireNonNull(baseDelay, "baseDelay");
            Objects.requireNonNull(maxDelay, "maxDelay");
        }

        long backoffNanos(int failedAttempts) {
            long base = baseDelay.toNanos();
            long cap = maxDelay.toNanos();
            int shift = Math.min(failedAttempts - 1, 30);
            long window = Math.min(cap, base << shift);
            return window <= 0 ? 0 : ThreadLocalRandom.current().nextLong(window + 1);
        }
    }

    private static final ThreadLocal<Boolean> ACTIVE = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private final DataSource dataSource;
    private final Isolation isolation;
    private final RetryPolicy retryPolicy;
    private final AtomicLong serializationFailures = new AtomicLong();
    private final AtomicLong deadlocks = new AtomicLong();
    private final AtomicLong retriesExhausted = new AtomicLong();

    /**
     * Creates a runner.
     *
     * @param dataSource connections as {@code alaka_app}
     * @param isolation isolation level of every transaction
     * @param retryPolicy retry budget for {@code 40001} / {@code 40P01}
     */
    public TransactionRunner(DataSource dataSource, Isolation isolation, RetryPolicy retryPolicy) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.isolation = Objects.requireNonNull(isolation, "isolation");
        this.retryPolicy = Objects.requireNonNull(retryPolicy, "retryPolicy");
    }

    /**
     * Returns whether the calling thread is inside a unit of work of any runner.
     *
     * @return {@code true} while a transaction is open on this thread
     */
    public static boolean inTransaction() {
        return ACTIVE.get();
    }

    /**
     * Runs {@code work} in one transaction, retrying the whole transaction on {@code 40001} and
     * {@code 40P01} until the retry budget is spent.
     *
     * @param work the unit of work
     * @param <T> the result type
     * @return the result of the attempt that committed
     * @throws NidhiException the translated error of the last attempt
     */
    public <T> T inTransaction(Work<T> work) {
        if (inTransaction()) {
            throw new IllegalStateException("Nested transactions are not supported");
        }
        for (int attempt = 1; ; attempt++) {
            try {
                return runOnce(work);
            } catch (NidhiException e) {
                if (!SqlStates.isRetryable(e)) {
                    throw e;
                }
                if (e instanceof NidhiException.DeadlockDetected) {
                    deadlocks.incrementAndGet();
                } else {
                    serializationFailures.incrementAndGet();
                }
                if (attempt >= retryPolicy.maxAttempts()) {
                    retriesExhausted.incrementAndGet();
                    throw e;
                }
                sleepNanos(retryPolicy.backoffNanos(attempt));
            }
        }
    }

    /**
     * Runs a read in autocommit mode, outside any explicit transaction.
     *
     * @param work the read
     * @param <T> the result type
     * @return the result
     * @throws NidhiException the translated error
     */
    public <T> T read(Work<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            return work.run(connection);
        } catch (SQLException e) {
            throw SqlStates.translate(e);
        }
    }

    /**
     * Returns the serialization failures seen so far.
     *
     * @return the number of attempts that ended in {@code 40001}
     */
    public long serializationFailures() {
        return serializationFailures.get();
    }

    /**
     * Returns the deadlocks seen so far.
     *
     * @return the number of attempts that ended in {@code 40P01}
     */
    public long deadlocks() {
        return deadlocks.get();
    }

    /**
     * Returns how many units of work were abandoned because the retry budget ran out.
     *
     * @return the number of exhausted retry budgets
     */
    public long retriesExhausted() {
        return retriesExhausted.get();
    }

    private <T> T runOnce(Work<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(isolation.jdbcLevel);
            ACTIVE.set(Boolean.TRUE);
            try {
                T result = work.run(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException | Error e) {
                rollbackQuietly(connection, e);
                throw e;
            } finally {
                ACTIVE.set(Boolean.FALSE);
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw SqlStates.translate(e);
        }
    }

    private static void rollbackQuietly(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private static void sleepNanos(long nanos) {
        if (nanos <= 0) {
            return;
        }
        try {
            Thread.sleep(Duration.ofNanos(nanos));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during retry backoff", e);
        }
    }
}
