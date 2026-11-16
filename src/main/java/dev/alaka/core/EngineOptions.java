package dev.alaka.core;

import java.time.Duration;
import java.util.Objects;

/**
 * Tunables of a hardened engine.
 *
 * @param recoveryGrace how long a request may take to finish normally before its recovery task
 *     falls due and {@code dev.alaka.yaksha.YakshaRecoverySweeper} treats the intent as stuck
 */
public record EngineOptions(Duration recoveryGrace) {

    /** Defaults: a 30 second recovery grace period. */
    public static final EngineOptions DEFAULTS = new EngineOptions(Duration.ofSeconds(30));

    public EngineOptions {
        Objects.requireNonNull(recoveryGrace, "recoveryGrace");
        if (recoveryGrace.isNegative()) {
            throw new IllegalArgumentException("recoveryGrace must not be negative: " + recoveryGrace);
        }
    }
}
