package dev.alaka.core;

import dev.alaka.mudra.MudraException;
import dev.alaka.mudra.MudraMandateClaims;
import dev.alaka.mudra.MudraQuoteClaims;
import dev.alaka.mudra.MudraQuoteVerifier;
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
 *   <li>the Ed25519 capability token verifies under a trusted mandate key and grants this mandate
 *       to this agent ({@link MudraTokenVerifier});
 *   <li>the Ed25519 quote token verifies under a trusted quote key and approves exactly this
 *       request: same mandate, agent and idempotency key ({@link MudraQuoteVerifier}). The agent
 *       cannot fabricate or reuse an approval;
 *   <li>the request matches the signed quote: merchant, currency, unexpired, price within
 *       slippage ({@link QuoteDriftEvaluator});
 *   <li>only then {@link SpendEngine#execute}, where the ledger enforces budget, cap, allowlist,
 *       revocation and the validity window against {@code NOW()}.
 * </ol>
 */
public final class SpendGateway {

    private final MudraTokenVerifier verifier;
    private final MudraQuoteVerifier quotes;
    private final QuoteDriftEvaluator drift;
    private final SpendEngine engine;

    /**
     * Creates a gateway.
     *
     * @param verifier capability token verifier (mandate issuer keys)
     * @param quotes quote token verifier (approving-party keys)
     * @param drift quote drift evaluator
     * @param engine the execution engine
     */
    public SpendGateway(
            MudraTokenVerifier verifier, MudraQuoteVerifier quotes, QuoteDriftEvaluator drift, SpendEngine engine) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.quotes = Objects.requireNonNull(quotes, "quotes");
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
     * Executes a spend request on the authority of a capability token and a signed approval.
     *
     * @param mandateToken the capability token for {@code request.mandateId()}
     * @param quoteToken the signed approval of this request
     * @param request the spend request
     * @return the engine's result
     * @throws MudraException if a token or the drift check rejects the request (no database access
     *     has happened)
     * @throws IdempotencyException as for {@link SpendEngine#execute}
     * @throws dev.alaka.nidhi.NidhiException as for {@link SpendEngine#execute}
     */
    public SpendResult execute(String mandateToken, String quoteToken, SpendRequest request) {
        verifier.verifyFor(mandateToken, request.mandateId(), request.agentId());
        MudraQuoteClaims approval = quotes.verifyFor(quoteToken, request);
        drift.check(approval.toApprovedQuote(), request);
        return engine.execute(request);
    }
}
