package dev.alaka.core;

import dev.alaka.nidhi.TransactionRunner;
import dev.alaka.nidhi.TransactionRunner.Isolation;
import dev.alaka.nidhi.TransactionRunner.RetryPolicy;
import dev.alaka.yaksha.PaymentRailPort;
import java.time.Duration;
import java.util.Objects;
import javax.sql.DataSource;

/** Factory for {@link SpendEngine}s. */
public final class SpendEngines {

    /**
     * Pessimistic writers queue on the balance row and should never conflict; a few attempts only
     * cover the rare deadlock.
     */
    static final RetryPolicy PESSIMISTIC_RETRY = new RetryPolicy(5, Duration.ofMillis(2), Duration.ofMillis(50));

    /**
     * Under SSI every concurrent writer on one mandate conflicts on the balance row, so the budget
     * is sized for a storm of 50 concurrent requests on a single mandate.
     */
    static final RetryPolicy SSI_RETRY = new RetryPolicy(100, Duration.ofMillis(1), Duration.ofMillis(64));

    private SpendEngines() {
    }

    /**
     * Creates an engine for one runtime mode.
     *
     * @param mode the runtime mode
     * @param appDataSource connections authenticated as the least-privilege role {@code alaka_app};
     *     the engine sets the isolation level it needs on every transaction itself
     * @param rail the payment rail
     * @return a thread-safe engine
     */
    public static SpendEngine create(RuntimeMode mode, DataSource appDataSource, PaymentRailPort rail) {
        return create(mode, appDataSource, rail, EngineOptions.DEFAULTS);
    }

    /**
     * Creates an engine for one runtime mode with explicit options.
     *
     * @param mode the runtime mode
     * @param appDataSource connections authenticated as {@code alaka_app}
     * @param rail the payment rail
     * @param options engine tunables (ignored by {@link RuntimeMode#NAIVE})
     * @return a thread-safe engine
     */
    public static SpendEngine create(
            RuntimeMode mode, DataSource appDataSource, PaymentRailPort rail, EngineOptions options) {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(appDataSource, "appDataSource");
        Objects.requireNonNull(rail, "rail");
        Objects.requireNonNull(options, "options");
        return switch (mode) {
            case NAIVE -> new NaiveSpendEngine(
                    new TransactionRunner(appDataSource, Isolation.READ_COMMITTED, new RetryPolicy(1, Duration.ZERO, Duration.ZERO)),
                    rail);
            case HARDENED_PESSIMISTIC -> new HardenedSpendEngine(
                    mode, new TransactionRunner(appDataSource, Isolation.READ_COMMITTED, PESSIMISTIC_RETRY), rail, options);
            case HARDENED_SSI -> new HardenedSpendEngine(
                    mode, new TransactionRunner(appDataSource, Isolation.SERIALIZABLE, SSI_RETRY), rail, options);
        };
    }
}
