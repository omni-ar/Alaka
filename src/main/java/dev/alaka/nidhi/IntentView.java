package dev.alaka.nidhi;

import java.util.Objects;
import java.util.UUID;

/**
 * Read-only snapshot of one {@code payment_intents} row (or, in {@code --mode=naive}, of the
 * naive baseline's equivalent record).
 *
 * @param intentId gateway-side intent id
 * @param mandateId mandate the intent spends against
 * @param agentId agent that issued the request
 * @param idempotencyKey caller-supplied idempotency key, unique per agent
 * @param requestHash lowercase hex SHA-256 of the canonical request payload
 * @param merchantId merchant being paid
 * @param currency ISO 4217 currency code
 * @param authorizedAmountMinor amount reserved, in minor units
 * @param capturedAmountMinor amount settled, in minor units; {@code 0} unless {@code CAPTURED}
 * @param status lifecycle state
 * @param railPaymentIntentId rail-side payment intent id ({@code pi_...}), or {@code null} while
 *     none has been recorded
 */
public record IntentView(
        UUID intentId,
        UUID mandateId,
        String agentId,
        String idempotencyKey,
        String requestHash,
        String merchantId,
        String currency,
        long authorizedAmountMinor,
        long capturedAmountMinor,
        IntentStatus status,
        String railPaymentIntentId) {

    public IntentView {
        Objects.requireNonNull(intentId, "intentId");
        Objects.requireNonNull(mandateId, "mandateId");
        Objects.requireNonNull(status, "status");
    }
}
