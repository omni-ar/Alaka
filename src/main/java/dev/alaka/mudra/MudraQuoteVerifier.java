package dev.alaka.mudra;

import dev.alaka.core.SpendRequest;
import dev.alaka.mudra.MudraException.InvalidQuote.Reason;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies signed purchase approvals ({@link MudraQuoteSigner}) against the request they are
 * presented with, in memory and before any database access.
 *
 * <p>Quote keys form their own trust set, separate from the mandate issuer keys of
 * {@link MudraTokenVerifier}: the party that approves a purchase need not be the party that issued
 * the mandate, and a mandate key cannot sign approvals.
 */
public final class MudraQuoteVerifier {

    private final Map<String, PublicKey> trustedQuoteKeys;

    /**
     * Creates a verifier.
     *
     * @param trustedQuoteKeys Ed25519 public keys of approving parties, by key id
     */
    public MudraQuoteVerifier(Map<String, PublicKey> trustedQuoteKeys) {
        this.trustedQuoteKeys = Map.copyOf(trustedQuoteKeys);
    }

    /**
     * Verifies a quote token and checks that it approves exactly this request: same mandate, same
     * agent, same idempotency key. Merchant, currency, price and expiry are judged afterwards by
     * {@link QuoteDriftEvaluator} against the returned claims.
     *
     * @param quoteToken the quote token
     * @param request the spend request it is presented with
     * @return the verified claims
     * @throws MudraException.InvalidQuote if the token is malformed, signed by an untrusted key,
     *     tampered with, or issued for another request
     */
    public MudraQuoteClaims verifyFor(String quoteToken, SpendRequest request) {
        Objects.requireNonNull(request, "request");
        if (quoteToken == null || quoteToken.isBlank()) {
            throw new MudraException.InvalidQuote(Reason.MALFORMED, "a signed quote_token is required");
        }
        MudraCodec.Opened opened;
        MudraQuoteClaims claims;
        try {
            opened = MudraCodec.open(quoteToken, MudraQuoteSigner.PREFIX);
            claims = MudraQuoteClaims.fromCanonicalBytes(opened.payload());
        } catch (IllegalArgumentException e) {
            throw new MudraException.InvalidQuote(Reason.MALFORMED, "undecodable quote token: " + e.getMessage());
        }
        PublicKey key = trustedQuoteKeys.get(claims.quoteKid());
        if (key == null) {
            throw new MudraException.InvalidQuote(Reason.UNKNOWN_KEY, "untrusted quote key " + claims.quoteKid());
        }
        if (!MudraCodec.verify(key, opened)) {
            throw new MudraException.InvalidQuote(Reason.BAD_SIGNATURE,
                    "quote signature does not verify for key " + claims.quoteKid());
        }
        if (!claims.mandateId().equals(request.mandateId())
                || !claims.agentId().equals(request.agentId())
                || !claims.idempotencyKey().equals(request.idempotencyKey())) {
            throw new MudraException.InvalidQuote(Reason.MISMATCH,
                    "quote approves request " + claims.agentId() + "/" + claims.idempotencyKey() + " on mandate "
                            + claims.mandateId() + ", not " + request.agentId() + "/" + request.idempotencyKey()
                            + " on " + request.mandateId());
        }
        return claims;
    }
}
