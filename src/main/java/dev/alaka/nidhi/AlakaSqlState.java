package dev.alaka.nidhi;

/**
 * The custom PostgreSQL SQLSTATE codes raised by the Nidhi ledger schema
 * ({@code migrations/001_init_nidhi_ledger.sql}).
 *
 * <p>The ledger uses its own {@code SG} class rather than PL/pgSQL's {@code P0001}-{@code P0004},
 * because those collide with built-in conditions ({@code P0002} is {@code no_data_found}).
 * Each constant is the exact five-character code a JDBC {@link java.sql.SQLException#getSQLState()}
 * returns when the corresponding database rule rejects a statement or a commit.
 */
public final class AlakaSqlState {

    /** {@code SG001}: mandate inactive, expired, or agent mismatch (invariant I4). */
    public static final String SG001_MANDATE_INACTIVE = "SG001";

    /** {@code SG002}: currency or budget mismatch. */
    public static final String SG002_CURRENCY_OR_BUDGET_MISMATCH = "SG002";

    /** {@code SG003}: mandate per-transaction or total budget exceeded (invariant I1). */
    public static final String SG003_BUDGET_EXCEEDED = "SG003";

    /** {@code SG004}: illegal state machine transition or initial state (invariant I5). */
    public static final String SG004_ILLEGAL_STATE_TRANSITION = "SG004";

    /**
     * {@code SG005}: unbalanced double-entry transaction or illegal bucket routing (invariant I3).
     */
    public static final String SG005_LEDGER_CONSERVATION_VIOLATED = "SG005";

    /** {@code SG006}: immutable audit row mutation attempted. */
    public static final String SG006_IMMUTABLE_ROW_MUTATION = "SG006";

    /**
     * {@code SG007}: direct mutation of a materialized balance, bypassing {@code ledger_postings}.
     */
    public static final String SG007_DIRECT_BALANCE_MUTATION = "SG007";

    /** {@code SG008}: merchant not in the mandate allowlist. */
    public static final String SG008_MERCHANT_NOT_ALLOWED = "SG008";

    private AlakaSqlState() {
    }
}
