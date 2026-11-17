package dev.alaka.mudra;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A purchase approval, exactly as signed by the approving party (the user or an approval service
 * holding a quote key), never by the agent.
 *
 * <p>The quote is bound to one request identity: {@code (mandateId, agentId, idempotencyKey)}.
 * Because the ledger allows one intent per {@code (agent_id, idempotency_key)}, a signed quote can
 * authorise at most one intent; presenting it with any other key is rejected.
 *
 * @param mandateId mandate the purchase is charged to
 * @param agentId agent allowed to make it
 * @param idempotencyKey the one request key this approval covers
 * @param merchantId merchant approved
 * @param currency ISO 4217 currency code, three upper-case letters
 * @param quotedAmountMinor approved price in minor units, positive
 * @param maxSlippageBps how far above the approved price settlement may go, 0..10000 basis points
 * @param expiresAtEpochSec instant after which the approval may not be acted on, seconds since the epoch
 * @param quoteKid id of the key that signs the quote
 */
public record MudraQuoteClaims(
        UUID mandateId,
        String agentId,
        String idempotencyKey,
        String merchantId,
        String currency,
        long quotedAmountMinor,
        int maxSlippageBps,
        long expiresAtEpochSec,
        String quoteKid) {

    private static final String DOMAIN = "alaka-mudra-quote-v1";

    public MudraQuoteClaims {
        Objects.requireNonNull(mandateId, "mandateId");
        MudraMandateClaims.requireText(agentId, "agentId");
        MudraMandateClaims.requireText(idempotencyKey, "idempotencyKey");
        MudraMandateClaims.requireText(merchantId, "merchantId");
        MudraMandateClaims.requireText(quoteKid, "quoteKid");
        if (currency == null || !currency.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be three upper-case letters: " + currency);
        }
        // The remaining bounds are those of ApprovedQuote, checked by its constructor. (Record fields
        // are not assigned until this body ends, so the parameters are used, not toApprovedQuote().)
        new ApprovedQuote(merchantId, currency, quotedAmountMinor, maxSlippageBps,
                Instant.ofEpochSecond(expiresAtEpochSec));
    }

    /**
     * Returns the bytes that are signed: the domain tag {@code alaka-mudra-quote-v1} followed by
     * every field, length-prefixed ({@link MudraCodec}).
     *
     * @return the canonical encoding
     */
    public byte[] canonicalBytes() {
        return new MudraCodec.Writer(DOMAIN)
                .field(mandateId.toString())
                .field(agentId)
                .field(idempotencyKey)
                .field(merchantId)
                .field(currency)
                .field(quotedAmountMinor)
                .field(maxSlippageBps)
                .field(expiresAtEpochSec)
                .field(quoteKid)
                .bytes();
    }

    /**
     * Decodes {@link #canonicalBytes()}.
     *
     * @param bytes a canonical encoding
     * @return the claims
     * @throws IllegalArgumentException if the bytes are not a canonical encoding of valid claims
     */
    public static MudraQuoteClaims fromCanonicalBytes(byte[] bytes) {
        MudraCodec.Reader in = new MudraCodec.Reader(bytes, DOMAIN);
        UUID mandateId = UUID.fromString(in.text());
        String agentId = in.text();
        String idempotencyKey = in.text();
        String merchantId = in.text();
        String currency = in.text();
        long quoted = in.number();
        long bps = in.number();
        long expiresAt = in.number();
        String kid = in.text();
        in.end();
        if (bps < Integer.MIN_VALUE || bps > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("slippage out of range: " + bps);
        }
        MudraQuoteClaims claims = new MudraQuoteClaims(
                mandateId, agentId, idempotencyKey, merchantId, currency, quoted, (int) bps, expiresAt, kid);
        MudraCodec.requireCanonical(claims.canonicalBytes(), bytes);
        return claims;
    }

    /**
     * Returns the approval as the drift evaluator consumes it.
     *
     * @return the approved quote
     */
    public ApprovedQuote toApprovedQuote() {
        return new ApprovedQuote(merchantId, currency, quotedAmountMinor, maxSlippageBps,
                Instant.ofEpochSecond(expiresAtEpochSec));
    }
}
