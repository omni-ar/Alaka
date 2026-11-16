package dev.alaka.yaksha;

import java.util.UUID;

/**
 * The payment rail as the gateway sees it: the four calls of the two-step confirmation protocol.
 *
 * <p>Implementations are thread-safe. No method may be called while a database transaction or
 * row lock is held; that is the caller's obligation and the reason the protocol has phases.
 */
public interface PaymentRailPort {

    /**
     * Step 2A: creates a payment intent with {@code confirm=false}. Never moves money, so a
     * delayed or duplicated delivery is harmless.
     *
     * <p>Idempotent on {@code idempotencyKey}: a repeated call with the same key returns the
     * payment intent created by the first one.
     *
     * @param idempotencyKey rail idempotency key, {@code "create_" + intentId}
     * @param intentId gateway intent id, stored by the rail as metadata
     * @param merchantId merchant being paid
     * @param currency ISO 4217 currency code
     * @param amountMinor amount to authorise, in minor units
     * @return the payment intent in {@link RailPiStatus#REQUIRES_CONFIRMATION}
     * @throws RailException.Timeout if the outcome is unknown
     */
    RailPaymentIntent createUnconfirmed(
            String idempotencyKey, UUID intentId, String merchantId, String currency, long amountMinor);

    /**
     * Step 2B: confirms a payment intent. This is the only call that can move money.
     *
     * <p>Idempotent on {@code idempotencyKey}: a repeated call returns the current state of the
     * payment intent and never charges twice.
     *
     * @param piId rail payment intent id
     * @param idempotencyKey rail idempotency key, {@code "confirm_" + intentId}
     * @return the payment intent, {@link RailPiStatus#SUCCEEDED} or {@link RailPiStatus#PROCESSING}
     * @throws RailException.ConfirmRejected if the payment intent is already canceled
     * @throws RailException.Timeout if the outcome is unknown
     * @throws RailException.UnknownPaymentIntent if {@code piId} does not exist
     */
    RailPaymentIntent confirm(String piId, String idempotencyKey);

    /**
     * Reads the current state of a payment intent ({@code GET /v1/payment_intents/{id}}). The
     * only read the recovery protocol relies on; strongly consistent.
     *
     * @param piId rail payment intent id
     * @return the payment intent
     * @throws RailException.UnknownPaymentIntent if {@code piId} does not exist
     */
    RailPaymentIntent retrieve(String piId);

    /**
     * Cancels a payment intent. Once this returns, the rail rejects any delayed in-flight
     * {@code /confirm} for it, which is what makes releasing the local hold safe.
     *
     * @param piId rail payment intent id
     * @return the payment intent in {@link RailPiStatus#CANCELED}
     * @throws RailException.CancelRejected if the payment intent is processing, succeeded or
     *     already canceled
     * @throws RailException.UnknownPaymentIntent if {@code piId} does not exist
     */
    RailPaymentIntent cancel(String piId);
}
