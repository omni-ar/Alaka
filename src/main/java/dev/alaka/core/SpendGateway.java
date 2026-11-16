package dev.alaka.core;

import dev.alaka.mudra.ApprovedQuote;
import dev.alaka.mudra.MudraException;
import dev.alaka.mudra.MudraMandateClaims;
import dev.alaka.mudra.MudraTokenVerifier;
import dev.alaka.mudra.QuoteDriftEvaluator;
import java.util.Objects;
import java.util.UUID;

/**
 * The agent-facing entry point: proves authority and intent in memory, then hands the request to
 * the engine. Every check here runs before the first database statement, so a forged token or a
 * drifted price never costs a transaction, a lock or a ledger row.
 *
 * <ol>
 *   <li>the Ed25519 capability token verifies under a trusted key and grants this mandate to this
 *       agent ({@link MudraTokenVerifier});
 *   <li>the request matches the quote the user approved: merchant, currency, unexpired, price
 *       within slippage ({@link QuoteDriftEvaluator});
 *   <li>only then {@link SpendEngine#execute}, where the ledger enforces budget, cap, allowlist,
 *       revocation and the validity window against {@code NOW()}.
 * </ol>
 */
public final class SpendGateway {

    private final MudraTokenVerifier verifier;
    private final QuoteDriftEvaluator drift;
    private final SpendEngine engine;

    /**
     * Creates a gateway.
     *
     * @param verifier capability token verifier
     * @param drift quote drift evaluator
     * @param engine the execution engine
     */
    public SpendGateway(MudraTokenVerifier verifier, QuoteDriftEvaluator drift, SpendEngine engine) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.drift = Objects.requireNonNull(drift, "drift");
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /**
     * Registers the mandate a verified token grants.
     *
     * @param mandateToken the capability token
     * @return the mandate id
     * @throws MudraException if the token does not verify
     */
    public UUID registerMandate(String mandateToken) {
        MudraMandateClaims claims = verifier.verify(mandateToken);
        return engine.createMandate(claims.toTerms());
    }

    /**
     * Executes a spend request on the authority of a capability token and an approved quote.
     *
     * @param mandateToken the capability token for {@code request.mandateId()}
     * @param quote the quote the user approved
     * @param request the spend request
     * @return the engine's result
     * @throws MudraException if the token or the quote check rejects the request (no database
     *     access has happened)
     * @throws IdempotencyException as for {@link SpendEngine#execute}
     * @throws dev.alaka.nidhi.NidhiException as for {@link SpendEngine#execute}
     */
    public SpendResult execute(String mandateToken, ApprovedQuote quote, SpendRequest request) {
        verifier.verifyFor(mandateToken, request.mandateId(), request.agentId());
        drift.check(quote, request);
        return engine.execute(request);
    }
}
