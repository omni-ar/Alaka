package dev.alaka.mudra;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Verifies Ed25519 capability tokens issued by {@link MudraTokenSigner}, in memory and before any
 * database access.
 *
 * <p>It deliberately does not judge the validity window against the application clock: I4
 * requires every mandate time check to use PostgreSQL's {@code NOW()}, and the ledger performs it
 * on every reservation. A verified token proves who granted which terms, not that they are
 * currently in force.
 */
public final class MudraTokenVerifier {

    private static final Base64.Decoder B64 = Base64.getUrlDecoder();

    private final Map<String, PublicKey> trustedKeys;

    /**
     * Creates a verifier.
     *
     * @param trustedKeys Ed25519 public keys by key id
     */
    public MudraTokenVerifier(Map<String, PublicKey> trustedKeys) {
        this.trustedKeys = Map.copyOf(trustedKeys);
    }

    /**
     * Verifies a token's signature and returns its claims.
     *
     * @param token the token
     * @return the verified claims
     * @throws MudraException.MalformedToken if the token cannot be parsed
     * @throws MudraException.UnknownKey if the token's key id is not trusted
     * @throws MudraException.BadSignature if the signature does not verify
     */
    public MudraMandateClaims verify(String token) {
        Objects.requireNonNull(token, "token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !MudraTokenSigner.PREFIX.equals(parts[0])) {
            throw new MudraException.MalformedToken("expected mudra1.<claims>.<signature>", null);
        }
        byte[] payload;
        byte[] signature;
        MudraMandateClaims claims;
        try {
            payload = B64.decode(parts[1]);
            signature = B64.decode(parts[2]);
            claims = MudraMandateClaims.fromCanonicalBytes(payload);
        } catch (IllegalArgumentException e) {
            throw new MudraException.MalformedToken("undecodable token: " + e.getMessage(), e);
        }
        PublicKey key = trustedKeys.get(claims.tokenKid());
        if (key == null) {
            throw new MudraException.UnknownKey("untrusted signing key " + claims.tokenKid());
        }
        boolean valid;
        try {
            Signature ed25519 = Signature.getInstance("Ed25519");
            ed25519.initVerify(key);
            ed25519.update(payload);
            valid = ed25519.verify(signature);
        } catch (GeneralSecurityException e) {
            valid = false;
        }
        if (!valid) {
            throw new MudraException.BadSignature("signature does not verify for key " + claims.tokenKid());
        }
        return claims;
    }

    /**
     * Verifies a token and checks that it grants the mandate and agent a request names.
     *
     * @param token the token
     * @param mandateId mandate the request spends against
     * @param agentId agent issuing the request
     * @return the verified claims
     * @throws MudraException.MandateMismatch if the token grants another mandate or agent
     * @throws MudraException as for {@link #verify(String)}
     */
    public MudraMandateClaims verifyFor(String token, UUID mandateId, String agentId) {
        MudraMandateClaims claims = verify(token);
        if (!claims.mandateId().equals(mandateId)) {
            throw new MudraException.MandateMismatch(
                    "token grants mandate " + claims.mandateId() + ", request names " + mandateId);
        }
        if (!claims.agentId().equals(agentId)) {
            throw new MudraException.MandateMismatch(
                    "token grants agent " + claims.agentId() + ", request comes from " + agentId);
        }
        return claims;
    }
}
