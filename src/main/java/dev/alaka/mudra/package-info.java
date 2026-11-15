/**
 * {@code mudra}: the cryptographic capability mandate and drift engine.
 *
 * <p>Named after <em>Mudr&#257;</em>, the sovereign cryptographic seal or coin. This subsystem
 * owns:
 * <ul>
 *   <li>Ed25519 capability token signing and verification over the mandate claims
 *       {@code total_budget_minor}, {@code max_per_tx_minor}, {@code allowed_merchants},
 *       {@code currency}, {@code not_before}, {@code expires_at} and {@code token_kid};</li>
 *   <li>the deterministic quote-to-settlement drift evaluator, which rejects execution before
 *       Phase 1 if the merchant, currency or settlement amount drifts from the user-approved
 *       quote.</li>
 * </ul>
 */
package dev.alaka.mudra;
