package dev.alaka.mudra;

import dev.alaka.nidhi.SignedMandateTerms;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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

    private static final byte[] DOMAIN = "alaka-mudra-mandate-v1".getBytes(StandardCharsets.UTF_8);

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
     * Returns the bytes that are signed: a domain tag followed by every field, each as a 4-byte
     * big-endian length and its UTF-8 bytes. Length prefixes make the encoding unambiguous, so no
     * two different claim sets share an encoding.
     *
     * @return the canonical encoding
     */
    public byte[] canonicalBytes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeField(out, DOMAIN);
        writeField(out, mandateId.toString());
        writeField(out, agentId);
        writeField(out, currency);
        writeField(out, Long.toString(totalBudgetMinor));
        writeField(out, Long.toString(maxPerTxMinor));
        writeField(out, Integer.toString(allowedMerchants.size()));
        for (String merchant : allowedMerchants) {
            writeField(out, merchant);
        }
        writeField(out, Long.toString(notBeforeEpochSec));
        writeField(out, Long.toString(expiresAtEpochSec));
        writeField(out, tokenKid);
        return out.toByteArray();
    }

    /**
     * Decodes {@link #canonicalBytes()}.
     *
     * @param bytes a canonical encoding
     * @return the claims
     * @throws IllegalArgumentException if the bytes are not a canonical encoding of valid claims
     */
    public static MudraMandateClaims fromCanonicalBytes(byte[] bytes) {
        ByteBuffer in = ByteBuffer.wrap(bytes);
        if (!java.util.Arrays.equals(readField(in), DOMAIN)) {
            throw new IllegalArgumentException("not a Mudra mandate encoding");
        }
        UUID mandateId = UUID.fromString(readText(in));
        String agentId = readText(in);
        String currency = readText(in);
        long total = Long.parseLong(readText(in));
        long cap = Long.parseLong(readText(in));
        int merchantCount = Integer.parseInt(readText(in));
        if (merchantCount < 1 || merchantCount > 1_000) {
            throw new IllegalArgumentException("implausible merchant count " + merchantCount);
        }
        List<String> merchants = new ArrayList<>(merchantCount);
        for (int i = 0; i < merchantCount; i++) {
            merchants.add(readText(in));
        }
        long notBefore = Long.parseLong(readText(in));
        long expiresAt = Long.parseLong(readText(in));
        String kid = readText(in);
        if (in.hasRemaining()) {
            throw new IllegalArgumentException("trailing bytes after the last field");
        }
        MudraMandateClaims claims =
                new MudraMandateClaims(mandateId, agentId, currency, total, cap, merchants, notBefore, expiresAt, kid);
        // Reject non-canonical encodings (e.g. an unsorted allowlist) so a token has exactly one form.
        if (!java.util.Arrays.equals(claims.canonicalBytes(), bytes)) {
            throw new IllegalArgumentException("encoding is not canonical");
        }
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

    private static void requireText(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
    }

    private static void writeField(ByteArrayOutputStream out, String value) {
        writeField(out, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeField(ByteArrayOutputStream out, byte[] value) {
        out.writeBytes(ByteBuffer.allocate(4).putInt(value.length).array());
        out.writeBytes(value);
    }

    private static byte[] readField(ByteBuffer in) {
        if (in.remaining() < 4) {
            throw new IllegalArgumentException("truncated encoding");
        }
        int length = in.getInt();
        if (length < 0 || length > in.remaining()) {
            throw new IllegalArgumentException("field length " + length + " out of range");
        }
        byte[] value = new byte[length];
        in.get(value);
        return value;
    }

    private static String readText(ByteBuffer in) {
        return new String(readField(in), StandardCharsets.UTF_8);
    }
}
