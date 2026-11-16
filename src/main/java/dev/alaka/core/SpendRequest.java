package dev.alaka.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/**
 * One spend request from an agent: pay {@code amountMinor} to {@code merchantId} against a
 * mandate, identified for idempotency by {@code (agentId, idempotencyKey)}.
 *
 * @param mandateId mandate to spend against
 * @param agentId agent issuing the request
 * @param idempotencyKey caller-chosen key; a retry of the same request reuses it
 * @param merchantId merchant to pay
 * @param currency ISO 4217 currency code
 * @param amountMinor amount to pay, in minor units
 */
public record SpendRequest(
        UUID mandateId,
        String agentId,
        String idempotencyKey,
        String merchantId,
        String currency,
        long amountMinor) {

    public SpendRequest {
        Objects.requireNonNull(mandateId, "mandateId");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(currency, "currency");
    }

    /**
     * Returns the canonical payload hash stored as {@code payment_intents.request_hash} and
     * compared on every replay of the idempotency key (invariant I2).
     *
     * <p>The canonical payload is the newline-joined sequence {@code mandateId}, {@code agentId},
     * {@code merchantId}, {@code currency}, {@code amountMinor}. The idempotency key is not part
     * of it: the hash answers "is this the same request", the key answers "is this a retry".
     *
     * @return 64 lowercase hex characters, the SHA-256 of the canonical payload in UTF-8
     */
    public String requestHash() {
        String canonical = String.join(
                "\n", mandateId.toString(), agentId, merchantId, currency, Long.toString(amountMinor));
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(sha256.digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required of every Java platform", e);
        }
    }
}
