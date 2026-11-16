package dev.alaka.yaksha;

/** A failed {@link PaymentRailPort} call. The subtype says what the caller may conclude from it. */
public abstract sealed class RailException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private RailException(String message) {
        super(message);
    }

    /**
     * The call timed out and its outcome is unknown: the rail may or may not have applied it, and
     * a delayed packet may still land later. The caller must never conclude that nothing happened;
     * it has to resolve the intent through the recovery protocol (retrieve, then cancel).
     */
    public static final class Timeout extends RailException {
        private static final long serialVersionUID = 1L;

        public Timeout(String message) {
            super(message);
        }
    }

    /**
     * {@code /cancel} was rejected because the payment intent is {@code PROCESSING},
     * {@code SUCCEEDED} or already {@code CANCELED} (Stripe: HTTP 400
     * {@code payment_intent_unexpected_state}). The local hold must not be released on the
     * strength of this error; the caller re-fetches the intent to learn its real state.
     */
    public static final class CancelRejected extends RailException {
        private static final long serialVersionUID = 1L;

        private final RailPiStatus statusAtRejection;

        public CancelRejected(RailPiStatus statusAtRejection, String message) {
            super(message);
            this.statusAtRejection = statusAtRejection;
        }

        /**
         * Returns the rail-side state that caused the rejection.
         *
         * @return the state of the payment intent when {@code /cancel} was evaluated
         */
        public RailPiStatus statusAtRejection() {
            return statusAtRejection;
        }
    }

    /**
     * {@code /confirm} was declined (Stripe: HTTP 402 {@code card_error}). No money moved and the
     * payment intent is back in a cancelable state; recovery cancels it before voiding.
     */
    public static final class Declined extends RailException {
        private static final long serialVersionUID = 1L;

        public Declined(String message) {
            super(message);
        }
    }

    /** {@code /confirm} was rejected because the payment intent is already {@code CANCELED}. */
    public static final class ConfirmRejected extends RailException {
        private static final long serialVersionUID = 1L;

        public ConfirmRejected(String message) {
            super(message);
        }
    }

    /** The rail knows no payment intent with the given id. */
    public static final class UnknownPaymentIntent extends RailException {
        private static final long serialVersionUID = 1L;

        public UnknownPaymentIntent(String message) {
            super(message);
        }
    }
}
