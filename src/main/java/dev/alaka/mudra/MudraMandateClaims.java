package dev.alaka.mudra;

import dev.alaka.nidhi.SignedMandateTerms;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.UUID;

/**
 * The terms an Ed25519 capability mandate grants, exactly as signed.
 *
 * <p>The merchant allowlist is a set: it is stored sorted and without duplicates, so the same
 * grant always has the same canonical encoding regardless of the order the issuer listed it in.
 *
 * @param mandateId mandate the token authorises
 * @param agentId agent the mandate is issued to
 * @param currency ISO 4217 currency code, three upper-case letters
 * @param totalBudgetMinor total budget in minor units, positive
 * @param maxPerTxMinor per-transaction cap, positive and at most the total budget
 * @param allowedMerchants non-empty merchant allowlist
 * @param notBeforeEpochSec start of validity, seconds since the epoch
 * @param expiresAtEpochSec end of validity (exclusive), seconds since the epoch, after the start
 * @param tokenKid id of the key that signs the token
 */
public record MudraMandateClaims(
        UUID mandateId,
        String agentId,
        String currency,
        long totalBudgetMinor,
        long maxPerTxMinor,
        List<String> allowedMerchants,
        long notBeforeEpochSec,
        long expiresAtEpochSec,
        String tokenKid) {

    private static final String DOMAIN = "alaka-mudra-mandate-v1";

    public MudraMandateClaims {
        Objects.requireNonNull(mandateId, "mandateId");
        requireText(agentId, "agentId");
        requireText(tokenKid, "tokenKid");
        if (currency == null || !currency.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be three upper-case letters: " + currency);
        }
        if (totalBudgetMinor <= 0 || maxPerTxMinor <= 0 || maxPerTxMinor > totalBudgetMinor) {
            throw new IllegalArgumentException(
                    "need 0 < maxPerTxMinor <= totalBudgetMinor, got " + maxPerTxMinor + " and " + totalBudgetMinor);
        }
        if (expiresAtEpochSec <= notBeforeEpochSec) {
            throw new IllegalArgumentException("expiresAt must be after notBefore");
        }
        TreeSet<String> merchants = new TreeSet<>();
        for (String merchant : allowedMerchants) {
            requireText(merchant, "allowedMerchants entry");
            merchants.add(merchant);
        }
        if (merchants.isEmpty()) {
            throw new IllegalArgumentException("allowedMerchants must not be empty");
        }
        allowedMerchants = List.copyOf(merchants);
    }

    /**
     * Returns the bytes that are signed: the domain tag {@code alaka-mudra-mandate-v1} followed by
     * every field, each as a 4-byte big-endian length and its UTF-8 bytes ({@link MudraCodec}).
     * Length prefixes make the encoding unambiguous, so no two different claim sets share one.
     *
     * @return the canonical encoding
     */
    public byte[] canonicalBytes() {
        MudraCodec.Writer out = new MudraCodec.Writer(DOMAIN)
                .field(mandateId.toString())
                .field(agentId)
                .field(currency)
                .field(totalBudgetMinor)
                .field(maxPerTxMinor)
                .field(allowedMerchants.size());
        for (String merchant : allowedMerchants) {
            out.field(merchant);
        }
        return out.field(notBeforeEpochSec).field(expiresAtEpochSec).field(tokenKid).bytes();
    }

    /**
     * Decodes {@link #canonicalBytes()}.
     *
     * @param bytes a canonical encoding
     * @return the claims
     * @throws IllegalArgumentException if the bytes are not a canonical encoding of valid claims
     */
    public static MudraMandateClaims fromCanonicalBytes(byte[] bytes) {
        MudraCodec.Reader in = new MudraCodec.Reader(bytes, DOMAIN);
        UUID mandateId = UUID.fromString(in.text());
        String agentId = in.text();
        String currency = in.text();
        long total = in.number();
        long cap = in.number();
        long merchantCount = in.number();
        if (merchantCount < 1 || merchantCount > 1_000) {
            throw new IllegalArgumentException("implausible merchant count " + merchantCount);
        }
        List<String> merchants = new ArrayList<>((int) merchantCount);
        for (int i = 0; i < merchantCount; i++) {
            merchants.add(in.text());
        }
        long notBefore = in.number();
        long expiresAt = in.number();
        String kid = in.text();
        in.end();
        MudraMandateClaims claims =
                new MudraMandateClaims(mandateId, agentId, currency, total, cap, merchants, notBefore, expiresAt, kid);
        // Reject non-canonical encodings (e.g. an unsorted allowlist) so a token has exactly one form.
        MudraCodec.requireCanonical(claims.canonicalBytes(), bytes);
        return claims;
    }

    /**
     * Returns the mandate terms to register in the ledger.
     *
     * @return the terms, with the validity window as instants
     */
    public SignedMandateTerms toTerms() {
        return new SignedMandateTerms(mandateId, agentId, currency, totalBudgetMinor, maxPerTxMinor, allowedMerchants,
                Instant.ofEpochSecond(notBeforeEpochSec), Instant.ofEpochSecond(expiresAtEpochSec), tokenKid);
    }

    static void requireText(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
    }
}
