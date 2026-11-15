/**
 * {@code alaka-core}: the gateway and execution orchestrator.
 *
 * <p>This subsystem owns:
 * <ul>
 *   <li>the HTTP/gRPC entrypoint through which agents submit spend intents;</li>
 *   <li>the idempotency gate ({@code uq_agent_idempotency} plus SHA-256 {@code request_hash}
 *       verification), which upholds invariant I2: at most one charge per
 *       {@code (agent_id, idempotency_key)}, and a replayed key with a different canonical payload
 *       is rejected;</li>
 *   <li>the three-phase execution coordinator, which never holds a database lock or an open
 *       transaction across an external network call;</li>
 *   <li>the three runtime benchmark modes selected with {@code --mode=} (see
 *       {@link dev.alaka.core.RuntimeMode}): {@code naive}, {@code hardened-pessimistic} and
 *       {@code hardened-ssi}.</li>
 * </ul>
 *
 * <p>It orchestrates the other three subsystems: {@code dev.alaka.mudra} (mandate verification and
 * drift checks), {@code dev.alaka.nidhi} (the double-entry ledger kernel) and
 * {@code dev.alaka.yaksha} (the payment rail adapter and recovery sweeper).
 */
package dev.alaka.core;
