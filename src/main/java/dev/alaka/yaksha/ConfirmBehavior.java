package dev.alaka.yaksha;

import java.util.Objects;

/**
 * What {@link SimulatedPaymentRail} does when a {@code /confirm} reaches it.
 *
 * @param outcome rail-side result of the confirm
 * @param chargedMinor amount to charge when {@code outcome} is {@link Outcome#SUCCEED};
 *     {@code 0} means the full authorised amount, a smaller positive value is a partial capture
 * @param fault what the caller observes, independently of what the rail did
 */
public record ConfirmBehavior(Outcome outcome, long chargedMinor, RailFault fault) {

    /** Rail-side result of a confirm. */
    public enum Outcome {
        /** The payment intent goes straight to {@link RailPiStatus#SUCCEEDED}. */
        SUCCEED,
        /** The payment intent goes to {@link RailPiStatus#PROCESSING} until resolved explicitly. */
        ENTER_PROCESSING
    }

    /** What the caller of a rail operation observes. */
    public enum RailFault {
        /** The call returns normally. */
        NONE,
        /** The rail applies the call, but the caller gets {@link RailException.Timeout}. */
        TIMEOUT_AFTER_APPLY,
        /** The call is lost before reaching the rail; the caller gets {@link RailException.Timeout}. */
        TIMEOUT_BEFORE_APPLY
    }

    public ConfirmBehavior {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(fault, "fault");
        if (chargedMinor < 0) {
            throw new IllegalArgumentException("chargedMinor must not be negative: " + chargedMinor);
        }
    }

    /**
     * Returns the default behaviour: charge the full authorised amount.
     *
     * @return a behaviour that succeeds in full with no fault
     */
    public static ConfirmBehavior succeedFull() {
        return new ConfirmBehavior(Outcome.SUCCEED, 0, RailFault.NONE);
    }

    /**
     * Returns a partial-capture behaviour.
     *
     * @param chargedMinor amount to charge, positive and at most the authorised amount
     * @return a behaviour that succeeds charging {@code chargedMinor}
     */
    public static ConfirmBehavior succeedPartial(long chargedMinor) {
        if (chargedMinor <= 0) {
            throw new IllegalArgumentException("chargedMinor must be positive: " + chargedMinor);
        }
        return new ConfirmBehavior(Outcome.SUCCEED, chargedMinor, RailFault.NONE);
    }

    /**
     * Returns a behaviour that leaves the payment intent {@code PROCESSING}.
     *
     * @return a behaviour that enters processing with no fault
     */
    public static ConfirmBehavior enterProcessing() {
        return new ConfirmBehavior(Outcome.ENTER_PROCESSING, 0, RailFault.NONE);
    }

    /**
     * Returns this behaviour with a different caller-visible fault.
     *
     * @param newFault the fault the caller should observe
     * @return a copy of this behaviour with {@code newFault}
     */
    public ConfirmBehavior withFault(RailFault newFault) {
        return new ConfirmBehavior(outcome, chargedMinor, newFault);
    }
}
