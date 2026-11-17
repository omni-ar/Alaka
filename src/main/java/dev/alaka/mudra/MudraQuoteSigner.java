package dev.alaka.mudra;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Signs purchase approvals. Held by the approving party, never by the agent.
 *
 * <p>Token format: {@code mudraq1.<base64url(canonical claims)>.<base64url(Ed25519 signature)>}.
 */
public final class MudraQuoteSigner {

    static final String PREFIX = "mudraq1";

    private final String kid;
    private final PrivateKey privateKey;

    /**
     * Creates a signer.
     *
     * @param kid id of the key, which every signed quote must carry as its {@code quoteKid}
     * @param privateKey an Ed25519 private key
     */
    public MudraQuoteSigner(String kid, PrivateKey privateKey) {
        this.kid = Objects.requireNonNull(kid, "kid");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        MudraCodec.requireEd25519(privateKey);
    }

    /**
     * Signs a quote.
     *
     * @param claims the quote; its {@code quoteKid} must be this signer's key id
     * @return the quote token
     */
    public String sign(MudraQuoteClaims claims) {
        if (!kid.equals(claims.quoteKid())) {
            throw new IllegalArgumentException("quote names key " + claims.quoteKid() + ", signer holds " + kid);
        }
        return MudraCodec.seal(PREFIX, claims.canonicalBytes(), privateKey);
    }
}
