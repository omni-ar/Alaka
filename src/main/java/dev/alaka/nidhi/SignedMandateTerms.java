package dev.alaka.nidhi;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Terms of a mandate whose id and validity window were fixed by a signed capability token (see
 * {@code dev.alaka.mudra}), as opposed to {@link NewMandate}, whose window starts at the
 * database's {@code NOW()}.
 *
 * <p>The window instants come from the token issuer's clock. Validity is still only ever judged
 * by PostgreSQL's {@code NOW()} (I4); an issuer whose clock runs ahead of the database's would
 * see a mandate that is "not yet valid" for that long, so issuers should backdate
 * {@code notBefore} by a margin rather than sign "now".
 *
 * @param mandateId mandate id chosen by the issuer
 * @param agentId agent the mandate is issued to
 * @param currency ISO 4217 currency code
 * @param totalBudgetMinor total budget in minor units
 * @param maxPerTxMinor per-transaction cap in minor units
 * @param allowedMerchants merchant allowlist
 * @param notBefore start of validity
 * @param expiresAt end of validity, exclusive
 * @param tokenKid id of the signing key
 */
public record SignedMandateTerms(
        UUID mandateId,
        String agentId,
        String currency,
        long totalBudgetMinor,
        long maxPerTxMinor,
        List<String> allowedMerchants,
        Instant notBefore,
        Instant expiresAt,
        String tokenKid) {

    public SignedMandateTerms {
        Objects.requireNonNull(mandateId, "mandateId");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(currency, "currency");
        allowedMerchants = List.copyOf(allowedMerchants);
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(tokenKid, "tokenKid");
    }
}
