/**
 * {@code yaksha}: the two-step rail adapter, outbox worker and zombie recovery sweeper.
 *
 * <p>Named after the <em>Yakshas</em>, the relentless guardians of Kubera's treasury in Alaka.
 * This subsystem owns:
 * <ul>
 *   <li>the Stripe Test Mode and HTTP 402 (MPP/x402) adapter implementing the two-step
 *       confirmation protocol:
 *       <ul>
 *         <li>Step 2A: {@code POST /v1/payment_intents} with {@code confirm=false} and
 *             {@code Idempotency-Key: create_<intent_id>}, then persist the {@code pi_...} id and
 *             advance the intent to {@code CONFIRMING};</li>
 *         <li>Step 2B: {@code POST /v1/payment_intents/{pi_id}/confirm} with
 *             {@code Idempotency-Key: confirm_<intent_id>};</li>
 *       </ul>
 *   </li>
 *   <li>the HMAC-SHA256 webhook verifier and the {@code processed_webhooks} deduplicator;</li>
 *   <li>the crash-recovery sweeper, which resolves stuck {@code RESERVED} and {@code CONFIRMING}
 *       intents by querying {@code GET /v1/payment_intents/{pi_id}} and calling
 *       {@code POST /v1/payment_intents/{pi_id}/cancel}, and which keeps {@code MANDATE_HELD}
 *       locked if the PaymentIntent is in {@code processing} or if the cancel fails because the
 *       charge succeeded.</li>
 * </ul>
 */
package dev.alaka.yaksha;
