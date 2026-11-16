package dev.alaka.yaksha;

import java.util.Objects;
import java.util.UUID;

/**
 * Rail-side view of one payment intent, as returned by every {@link PaymentRailPort} call.
 *
 * @param piId rail-assigned id ({@code pi_...})
 * @param intentId gateway intent id the rail was given as metadata at creation
 * @param status rail-side state
 * @param merchantId merchant being paid
 * @param currency ISO 4217 currency code
 * @param amountMinor amount the intent was created for, in minor units
 * @param chargedMinor amount the rail actually charged: {@code 0} unless {@code SUCCEEDED}, then
 *     between {@code 1} and {@code amountMinor} (less than {@code amountMinor} is a partial capture)
 */
public record RailPaymentIntent(
        String piId,
        UUID intentId,
        RailPiStatus status,
        String merchantId,
        String currency,
        long amountMinor,
        long chargedMinor) {

    public RailPaymentIntent {
        Objects.requireNonNull(piId, "piId");
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(status, "status");
    }
}
