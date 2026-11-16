package dev.alaka.core;

import java.time.Duration;

/**
 * A request rejected by the idempotency gate (invariant I2) before any money was reserved.
 * Each subtype carries the HTTP status the gateway answers with.
 */
public abstract sealed class IdempotencyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private IdempotencyException(String message) {
        super(message);
    }

    /**
     * Returns the HTTP status the gateway answers with.
     *
     * @return {@code 422} or {@code 409}
     */
    public abstract int httpStatus();

    /**
     * {@code 422 Unprocessable Entity} ({@code IdempotencyKeyPayloadMismatch}): the key was
     * already used by this agent with a different canonical payload.
     */
    public static final class PayloadMismatch extends IdempotencyException {
        private static final long serialVersionUID = 1L;

        public PayloadMismatch(String message) {
            super(message);
        }

        @Override
        public int httpStatus() {
            return 422;
        }
    }

    /**
     * {@code 409 Conflict} with {@code Retry-After}: the key was already used with the same
     * payload and that request is still in flight (its intent is not terminal yet).
     */
    public static final class InFlight extends IdempotencyException {
        private static final long serialVersionUID = 1L;

        private final long retryAfterMillis;

        public InFlight(String message, Duration retryAfter) {
            super(message);
            this.retryAfterMillis = retryAfter.toMillis();
        }

        @Override
        public int httpStatus() {
            return 409;
        }

        /**
         * Returns how long the caller should wait before retrying.
         *
         * @return the {@code Retry-After} hint
         */
        public Duration retryAfter() {
            return Duration.ofMillis(retryAfterMillis);
        }
    }
}
