package dev.alaka.nidhi;

/**
 * Lifecycle state of a payment intent, mirroring the {@code intent_status} enum of the Nidhi
 * schema. Transitions are monotonic (invariant I5): {@code RESERVED -> CONFIRMING -> AUTHORIZED ->
 * CAPTURED}, or to {@code VOIDED} / {@code FAILED} from any non-terminal state.
 */
public enum IntentStatus {
    RESERVED,
    CONFIRMING,
    AUTHORIZED,
    CAPTURED,
    VOIDED,
    FAILED;

    /**
     * Returns whether this state can never change again.
     *
     * @return {@code true} for {@code CAPTURED}, {@code VOIDED} and {@code FAILED}
     */
    public boolean isTerminal() {
        return this == CAPTURED || this == VOIDED || this == FAILED;
    }
}
