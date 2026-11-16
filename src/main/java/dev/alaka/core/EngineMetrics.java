package dev.alaka.core;

/**
 * Counters an engine has accumulated since it was created.
 *
 * @param serializationFailures database transactions that ended in SQLSTATE {@code 40001}
 * @param deadlocks database transactions that ended in SQLSTATE {@code 40P01}
 * @param retriesExhausted operations abandoned because the retry budget ran out
 */
public record EngineMetrics(long serializationFailures, long deadlocks, long retriesExhausted) {
}
