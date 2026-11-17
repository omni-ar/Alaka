package dev.alaka.mudra;

import java.security.PrivateKey;
import java.util.Objects;

/**
 * Issues Ed25519 capability tokens with the JDK's built-in provider (no external crypto).
 *
 * <p>Token format: {@code mudra1.<base64url(canonical claims)>.<base64url(Ed25519 signature)>},
 * unpadded. The key id travels inside the signed claims, so it cannot be swapped without breaking
 * the signature.
 */
public final class MudraTokenSigner {

    static final String PREFIX = "mudra1";

    private final String kid;
    private final PrivateKey privateKey;

    /**
     * Creates a signer.
     *
     * @param kid id of the key, which every signed claim set must carry as its {@code tokenKid}
     * @param privateKey an Ed25519 private key
     */
    public MudraTokenSigner(String kid, PrivateKey privateKey) {
        this.kid = Objects.requireNonNull(kid, "kid");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        MudraCodec.requireEd25519(privateKey);
    }

    /**
     * Signs a claim set.
     *
     * @param claims the claims; their {@code tokenKid} must be this signer's key id
     * @return the token
     */
    public String sign(MudraMandateClaims claims) {
        if (!kid.equals(claims.tokenKid())) {
            throw new IllegalArgumentException("claims name key " + claims.tokenKid() + ", signer holds " + kid);
        }
        return MudraCodec.seal(PREFIX, claims.canonicalBytes(), privateKey);
    }
}
