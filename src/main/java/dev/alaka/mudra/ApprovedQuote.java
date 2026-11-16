package dev.alaka.mudra;

import java.time.Instant;
import java.util.Objects;

/**
 * The quote a user approved before the agent was allowed to pay.
 *
 * @param merchantId merchant the user agreed to pay
 * @param currency ISO 4217 currency code of the quote
 * @param quotedAmountMinor quoted price in minor units, positive
 * @param maxSlippageBps how far above the quoted price the settlement amount may go, in basis
 *     points (1 bp = 0.01 %), between 0 and 10000
 * @param quoteExpiresAt instant after which the quote may no longer be acted on
 */
public record ApprovedQuote(
        String merchantId, String currency, long quotedAmountMinor, int maxSlippageBps, Instant quoteExpiresAt) {

    public ApprovedQuote {
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(currency, "currency");
        Objects.requireNonNull(quoteExpiresAt, "quoteExpiresAt");
        if (quotedAmountMinor <= 0) {
            throw new IllegalArgumentException("quotedAmountMinor must be positive: " + quotedAmountMinor);
        }
        if (maxSlippageBps < 0 || maxSlippageBps > 10_000) {
            throw new IllegalArgumentException("maxSlippageBps must be within 0..10000: " + maxSlippageBps);
        }
    }
}
