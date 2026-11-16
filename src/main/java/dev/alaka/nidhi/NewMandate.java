package dev.alaka.nidhi;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Terms of a spend mandate to be created. All terms are immutable once the mandate exists.
 *
 * <p>The validity window is expressed as a duration, not as instants, because invariant I4
 * requires every time check to use PostgreSQL transaction time: the mandate is valid from
 * {@code NOW()} to {@code NOW() + validFor} as evaluated by the database.
 *
 * @param agentId agent the mandate is issued to
 * @param currency ISO 4217 currency code, three upper-case letters
 * @param totalBudgetMinor total budget in minor units, positive
 * @param maxPerTxMinor per-transaction cap in minor units, positive and at most the total budget
 * @param allowedMerchants non-empty merchant allowlist
 * @param validFor how long the mandate stays valid, counted from the database's {@code NOW()}
 * @param tokenKid key id of the capability token that authorised the mandate
 */
public record NewMandate(
        String agentId,
        String currency,
        long totalBudgetMinor,
        long maxPerTxMinor,
        List<String> allowedMerchants,
        Duration validFor,
        String tokenKid) {

    public NewMandate {
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(currency, "currency");
        allowedMerchants = List.copyOf(allowedMerchants);
        Objects.requireNonNull(validFor, "validFor");
        Objects.requireNonNull(tokenKid, "tokenKid");
    }
}
