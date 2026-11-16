package dev.alaka.yaksha;

import dev.alaka.core.RailEventOutcome;
import dev.alaka.core.SpendEngine;
import java.util.Objects;
import java.util.Optional;

/**
 * Receives Stripe webhook deliveries: verifies them, then applies payment intent events through
 * {@link SpendEngine#applyRailEvent}, which deduplicates on the event id in the same transaction
 * that applies the effect. Answer 2xx for any returned outcome (including a duplicate) and 400 for
 * a {@link WebhookRejectedException}.
 */
public final class StripeWebhookHandler {

    private final StripeWebhookVerifier verifier;
    private final SpendEngine engine;

    /**
     * Creates a handler.
     *
     * @param verifier signature verifier
     * @param engine a hardened engine
     */
    public StripeWebhookHandler(StripeWebhookVerifier verifier, SpendEngine engine) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /**
     * Handles one delivery.
     *
     * @param signatureHeader the {@code Stripe-Signature} header
     * @param rawBody the body exactly as received
     * @return what was done; events that carry no payment intent are ignored without touching the
     *     database
     * @throws WebhookRejectedException if verification fails (nothing was written)
     */
    public RailEventOutcome handle(String signatureHeader, byte[] rawBody) {
        StripeWebhookVerifier.VerifiedEvent event = verifier.verify(signatureHeader, rawBody);
        if (event.paymentIntent().isEmpty()) {
            return new RailEventOutcome(RailEventOutcome.Disposition.IGNORED, Optional.empty());
        }
        return engine.applyRailEvent(event.id(), event.type(), event.paymentIntent().get());
    }
}
