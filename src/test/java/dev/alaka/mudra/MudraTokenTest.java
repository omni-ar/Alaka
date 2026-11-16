package dev.alaka.mudra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MudraTokenTest {

    private static final KeyPair ISSUER = ed25519();
    private static final KeyPair OTHER = ed25519();

    private final MudraTokenSigner signer = new MudraTokenSigner("kid-1", ISSUER.getPrivate());
    private final MudraTokenVerifier verifier = new MudraTokenVerifier(Map.of("kid-1", ISSUER.getPublic()));

    static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Ed25519 is built into JDK 15+", e);
        }
    }

    /** Validity backdated a minute: the issuer's clock may run ahead of the database's NOW(). */
    static MudraMandateClaims claims(UUID mandateId, String agent, List<String> merchants, long budget, String kid) {
        long now = Instant.now().getEpochSecond();
        return new MudraMandateClaims(mandateId, agent, "USD", budget, Math.min(budget, 5_000), merchants,
                now - 60, now + 3_600, kid);
    }

    private static MudraMandateClaims claims() {
        return claims(UUID.randomUUID(), "agent-1", List.of("merchant-b", "merchant-a"), 10_000, "kid-1");
    }

    @Test
    void validTokenRoundTrips() {
        MudraMandateClaims claims = claims();
        String token = signer.sign(claims);

        assertThat(token).startsWith("mudra1.");
        assertThat(verifier.verify(token)).isEqualTo(claims);
        assertThat(verifier.verifyFor(token, claims.mandateId(), "agent-1")).isEqualTo(claims);
        assertThat(claims.allowedMerchants()).containsExactly("merchant-a", "merchant-b");
    }

    @Test
    void canonicalEncodingIgnoresAllowlistOrderAndDuplicates() {
        MudraMandateClaims a = claims();
        MudraMandateClaims b = new MudraMandateClaims(a.mandateId(), a.agentId(), a.currency(), a.totalBudgetMinor(),
                a.maxPerTxMinor(), List.of("merchant-a", "merchant-b", "merchant-a"), a.notBeforeEpochSec(),
                a.expiresAtEpochSec(), a.tokenKid());
        assertThat(b.canonicalBytes()).isEqualTo(a.canonicalBytes());
    }

    @Test
    void tamperedBudgetIsRejected() {
        MudraMandateClaims claims = claims();
        String token = signer.sign(claims);
        MudraMandateClaims richer = new MudraMandateClaims(claims.mandateId(), claims.agentId(), claims.currency(),
                1_000_000, claims.maxPerTxMinor(), claims.allowedMerchants(), claims.notBeforeEpochSec(),
                claims.expiresAtEpochSec(), claims.tokenKid());

        assertThatThrownBy(() -> verifier.verify(withPayload(token, richer.canonicalBytes())))
                .isInstanceOf(MudraException.BadSignature.class);
    }

    @Test
    void tamperedMerchantIsRejected() {
        MudraMandateClaims claims = claims();
        String token = signer.sign(claims);
        MudraMandateClaims widened = new MudraMandateClaims(claims.mandateId(), claims.agentId(), claims.currency(),
                claims.totalBudgetMinor(), claims.maxPerTxMinor(), List.of("merchant-a", "merchant-b", "evil-merchant"),
                claims.notBeforeEpochSec(), claims.expiresAtEpochSec(), claims.tokenKid());

        assertThatThrownBy(() -> verifier.verify(withPayload(token, widened.canonicalBytes())))
                .isInstanceOf(MudraException.BadSignature.class);
    }

    @Test
    void tokenSignedByAnotherKeyUnderATrustedKidIsRejected() {
        String forged = new MudraTokenSigner("kid-1", OTHER.getPrivate()).sign(claims());
        assertThatThrownBy(() -> verifier.verify(forged)).isInstanceOf(MudraException.BadSignature.class);
    }

    @Test
    void unknownKidIsRejected() {
        MudraMandateClaims claims = claims(UUID.randomUUID(), "agent-1", List.of("m"), 1_000, "kid-rogue");
        String token = new MudraTokenSigner("kid-rogue", OTHER.getPrivate()).sign(claims);
        assertThatThrownBy(() -> verifier.verify(token)).isInstanceOf(MudraException.UnknownKey.class);
    }

    @Test
    void tokenForAnotherMandateOrAgentIsRejected() {
        MudraMandateClaims claims = claims();
        String token = signer.sign(claims);
        assertThatThrownBy(() -> verifier.verifyFor(token, UUID.randomUUID(), "agent-1"))
                .isInstanceOf(MudraException.MandateMismatch.class);
        assertThatThrownBy(() -> verifier.verifyFor(token, claims.mandateId(), "agent-2"))
                .isInstanceOf(MudraException.MandateMismatch.class);
    }

    @Test
    void malformedTokensAreRejected() {
        String token = signer.sign(claims());
        String[] parts = token.split("\\.");
        for (String bad : List.of("", "mudra1", "mudra2." + parts[1] + "." + parts[2], "mudra1.!!!." + parts[2],
                "mudra1." + Base64.getUrlEncoder().encodeToString("junk".getBytes(StandardCharsets.UTF_8)) + "." + parts[2],
                token + ".extra")) {
            assertThatThrownBy(() -> verifier.verify(bad)).as(bad).isInstanceOf(MudraException.MalformedToken.class);
        }
        assertThatThrownBy(() -> verifier.verify(parts[0] + "." + parts[1] + ".AAAA"))
                .isInstanceOf(MudraException.BadSignature.class);
    }

    @Test
    void signerRefusesClaimsForAnotherKid() {
        MudraMandateClaims claims = claims(UUID.randomUUID(), "agent-1", List.of("m"), 1_000, "kid-2");
        assertThatThrownBy(() -> signer.sign(claims)).isInstanceOf(IllegalArgumentException.class);
    }

    private static String withPayload(String token, byte[] payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." + parts[2];
    }
}
