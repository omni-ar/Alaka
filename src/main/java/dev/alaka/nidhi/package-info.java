/**
 * {@code nidhi}: the double-entry PostgreSQL ledger kernel.
 *
 * <p>Named after Kubera's <em>Navanidhi</em>, the nine sacred treasures held under strict
 * conservation laws. This subsystem is the Java side of the ledger defined in
 * {@code migrations/001_init_nidhi_ledger.sql}: the double-entry repository, the canonical lock
 * ordering, and the mapping of the ledger's custom SQLSTATE codes (see
 * {@link dev.alaka.nidhi.AlakaSqlState}).
 *
 * <p>The ledger it fronts owns:
 * <ul>
 *   <li>the three-bucket mandate partition ({@code MANDATE_AVAILABLE}, {@code MANDATE_HELD},
 *       {@code MANDATE_SETTLED});</li>
 *   <li>the {@code DEFERRABLE INITIALLY DEFERRED} conservation triggers, which enforce invariant I3
 *       at every {@code COMMIT}: debits equal credits and
 *       {@code available_minor + held_minor + settled_minor == total_budget_minor};</li>
 *   <li>the per-transition bucket-routing rules ({@code RESERVE}, {@code CAPTURE}, {@code VOID});</li>
 *   <li>the least-privilege role separation ({@code alaka_migrator} versus {@code alaka_app});</li>
 *   <li>the self-asserting SQL adversarial attack suite
 *       ({@code tests/sql/verify_nidhi_attacks.sql}).</li>
 * </ul>
 */
package dev.alaka.nidhi;
