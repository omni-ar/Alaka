package dev.alaka.mudra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.alaka.core.SpendRequest;
import dev.alaka.mudra.MudraException.InvalidQuote.Reason;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MudraQuoteTest {

    private static final KeyPair APPROVER = MudraTokenTest.ed25519();
    private static final KeyPair MANDATE_ISSUER = MudraTokenTest.ed25519();

    private final MudraQuoteSigner signer = new MudraQuoteSigner("q-kid", APPROVER.getPrivate());
    private final MudraQuoteVerifier verifier = new MudraQuoteVerifier(Map.of("q-kid", APPROVER.getPublic()));
    private final UUID mandate = UUID.randomUUID();

    private MudraQuoteClaims quote(String key, long quoted, int bps) {
        return new MudraQuoteClaims(mandate, "agent-1", key, "merchant-a", "USD", quoted, bps,
                Instant.now().getEpochSecond() + 300, "q-kid");
    }

    private SpendRequest request(String key, long amount) {
        return new SpendRequest(mandate, "agent-1", key, "merchant-a", "USD", amount);
    }

    @Test
    void signedQuoteVerifiesForExactlyItsRequest() {
        MudraQuoteClaims claims = quote("order-1", 2_000, 100);
        String token = signer.sign(claims);

        assertThat(token).startsWith("mudraq1.");
        assertThat(verifier.verifyFor(token, request("order-1", 2_020))).isEqualTo(claims);
        assertThat(claims.toApprovedQuote().quotedAmountMinor()).isEqualTo(2_000);
    }

    @Test
    void agentRaisingTheQuotedAmountOrSlippageBreaksTheSignature() {
        String token = signer.sign(quote("order-1", 2_000, 100));
        String higherPrice = withPayload(token, quote("order-1", 20_000, 100).canonicalBytes());
        String moreSlippage = withPayload(token, quote("order-1", 2_000, 10_000).canonicalBytes());

        assertRejected(higherPrice, request("order-1", 20_000), Reason.BAD_SIGNATURE);
        assertRejected(moreSlippage, request("order-1", 4_000), Reason.BAD_SIGNATURE);
    }

    @Test
    void quoteCannotBeReplayedForAnotherIdempotencyKeyAgentOrMandate() {
        String token = signer.sign(quote("order-1", 2_000, 0));

        assertRejected(token, request("order-2", 2_000), Reason.MISMATCH);
        assertRejected(token, new SpendRequest(mandate, "agent-2", "order-1", "merchant-a", "USD", 2_000),
                Reason.MISMATCH);
        assertRejected(token, new SpendRequest(UUID.randomUUID(), "agent-1", "order-1", "merchant-a", "USD", 2_000),
                Reason.MISMATCH);
    }

    @Test
    void untrustedKeysAndMandateKeysCannotApprove() {
        MudraQuoteClaims claims = quote("order-1", 2_000, 0);
        String foreignKid = new MudraQuoteSigner("rogue", MANDATE_ISSUER.getPrivate()).sign(
                new MudraQuoteClaims(mandate, "agent-1", "order-1", "merchant-a", "USD", 2_000, 0,
                        claims.expiresAtEpochSec(), "rogue"));
        String sameKidOtherKey = new MudraQuoteSigner("q-kid", MANDATE_ISSUER.getPrivate()).sign(claims);

        assertRejected(foreignKid, request("order-1", 2_000), Reason.UNKNOWN_KEY);
        assertRejected(sameKidOtherKey, request("order-1", 2_000), Reason.BAD_SIGNATURE);
    }

    @Test
    void mandateTokensAreNotQuotesAndMissingQuotesAreRejected() {
        long now = Instant.now().getEpochSecond();
        String mandateToken = new MudraTokenSigner("q-kid", APPROVER.getPrivate()).sign(new MudraMandateClaims(
                mandate, "agent-1", "USD", 10_000, 5_000, List.of("merchant-a"), now - 60, now + 3_600, "q-kid"));
        String relabelled = "mudraq1" + mandateToken.substring("mudra1".length());

        assertRejected(mandateToken, request("order-1", 2_000), Reason.MALFORMED);
        assertRejected(relabelled, request("order-1", 2_000), Reason.MALFORMED);   // domain tag differs
        assertRejected(null, request("order-1", 2_000), Reason.MALFORMED);
        assertRejected("", request("order-1", 2_000), Reason.MALFORMED);
    }

    private void assertRejected(String token, SpendRequest request, Reason reason) {
        assertThatThrownBy(() -> verifier.verifyFor(token, request))
                .isInstanceOfSatisfying(MudraException.InvalidQuote.class, e -> assertThat(e.reason()).isEqualTo(reason));
    }

    private static String withPayload(String token, byte[] payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." + parts[2];
    }
}
