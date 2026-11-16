package dev.alaka.nidhi;

import java.util.Objects;
import java.util.UUID;

/**
 * Read-only snapshot of a mandate's three budget buckets. For the hardened modes this is the
 * {@code mandate_balances} row; for {@code --mode=naive} it is whatever the naive baseline
 * believes it has spent, which is exactly what makes its drift from the rail observable.
 *
 * @param mandateId mandate id
 * @param totalBudgetMinor signed total budget
 * @param availableMinor {@code MANDATE_AVAILABLE} bucket
 * @param heldMinor {@code MANDATE_HELD} bucket
 * @param settledMinor {@code MANDATE_SETTLED} bucket
 */
public record MandateBalances(
        UUID mandateId, long totalBudgetMinor, long availableMinor, long heldMinor, long settledMinor) {

    public MandateBalances {
        Objects.requireNonNull(mandateId, "mandateId");
    }

    /**
     * Returns whether invariant I3 holds for this snapshot.
     *
     * @return {@code true} if no bucket is negative and the buckets sum to the total budget
     */
    public boolean isConserved() {
        return availableMinor >= 0
                && heldMinor >= 0
                && settledMinor >= 0
                && availableMinor + heldMinor + settledMinor == totalBudgetMinor;
    }
}
