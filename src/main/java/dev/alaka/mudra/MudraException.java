package dev.alaka.mudra;

/**
 * A request rejected by {@code mudra} before it reaches the ledger: an invalid capability token
 * or a spend that drifted from the quote the user approved.
 */
public abstract sealed class MudraException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private MudraException(String message, Throwable cause) {
        super(message, cause);
    }

    /** The token is not a well-formed Mudra token. */
    public static final class MalformedToken extends MudraException {
        private static final long serialVersionUID = 1L;

        public MalformedToken(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** The token names a signing key this verifier does not trust. */
    public static final class UnknownKey extends MudraException {
        private static final long serialVersionUID = 1L;

        public UnknownKey(String message) {
            super(message, null);
        }
    }

    /** The signature does not verify: the claims were tampered with or signed by another key. */
    public static final class BadSignature extends MudraException {
        private static final long serialVersionUID = 1L;

        public BadSignature(String message) {
            super(message, null);
        }
    }

    /** The token is valid but grants a different mandate or a different agent than requested. */
    public static final class MandateMismatch extends MudraException {
        private static final long serialVersionUID = 1L;

        public MandateMismatch(String message) {
            super(message, null);
        }
    }

    /**
     * The signed quote is missing, malformed, signed by an untrusted key, tampered with, or issued
     * for a different request (mandate, agent or idempotency key).
     */
    public static final class InvalidQuote extends MudraException {
        private static final long serialVersionUID = 1L;

        /** Why the quote was rejected. */
        public enum Reason {
            MALFORMED,
            UNKNOWN_KEY,
            BAD_SIGNATURE,
            MISMATCH
        }

        private final Reason reason;

        public InvalidQuote(Reason reason, String message) {
            super(message, null);
            this.reason = reason;
        }

        /**
         * Returns why the quote was rejected.
         *
         * @return the reason
         */
        public Reason reason() {
            return reason;
        }
    }

    /** The spend request drifted from the approved quote. */
    public static final class QuoteDrift extends MudraException {
        private static final long serialVersionUID = 1L;

        /** Which part of the request drifted. */
        public enum Reason {
            MERCHANT,
            CURRENCY,
            QUOTE_EXPIRED,
            PRICE
        }

        private final Reason reason;

        public QuoteDrift(Reason reason, String message) {
            super(message, null);
            this.reason = reason;
        }

        /**
         * Returns what drifted.
         *
         * @return the drift reason
         */
        public Reason reason() {
            return reason;
        }
    }
}
