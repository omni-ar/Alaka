package dev.alaka.yaksha;

/** A webhook delivery rejected before it reached the ledger. Answer it with HTTP 400. */
public final class WebhookRejectedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Why the delivery was rejected. */
    public enum Reason {
        MISSING_SIGNATURE,
        MALFORMED_SIGNATURE,
        TIMESTAMP_OUT_OF_TOLERANCE,
        BAD_SIGNATURE,
        MALFORMED_PAYLOAD
    }

    private final Reason reason;

    public WebhookRejectedException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    /**
     * Returns why the delivery was rejected.
     *
     * @return the reason
     */
    public Reason reason() {
        return reason;
    }
}
