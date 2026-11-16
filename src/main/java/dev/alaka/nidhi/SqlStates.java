package dev.alaka.nidhi;

import java.sql.SQLException;

/** Translates PostgreSQL errors into the typed {@link NidhiException} hierarchy. */
public final class SqlStates {

    private SqlStates() {
    }

    /**
     * Translates a database error, whether it was raised by a statement or by {@code COMMIT}
     * (where the deferred conservation triggers report).
     *
     * @param e the error reported by the JDBC driver
     * @return the matching subtype; {@link NidhiException.Unclassified} for any other SQLSTATE
     */
    public static NidhiException translate(SQLException e) {
        String state = e.getSQLState() == null ? "" : e.getSQLState();
        String message = e.getMessage();
        return switch (state) {
            case AlakaSqlState.SG001_MANDATE_INACTIVE -> new NidhiException.MandateInactive(message, e);
            case AlakaSqlState.SG002_CURRENCY_OR_BUDGET_MISMATCH -> new NidhiException.CurrencyMismatch(message, e);
            case AlakaSqlState.SG003_BUDGET_EXCEEDED -> new NidhiException.BudgetExceeded(message, e);
            case AlakaSqlState.SG004_ILLEGAL_STATE_TRANSITION -> new NidhiException.IllegalStateTransition(message, e);
            case AlakaSqlState.SG005_LEDGER_CONSERVATION_VIOLATED ->
                    new NidhiException.LedgerConservationViolated(message, e);
            case AlakaSqlState.SG006_IMMUTABLE_ROW_MUTATION -> new NidhiException.ImmutableRowMutation(message, e);
            case AlakaSqlState.SG007_DIRECT_BALANCE_MUTATION -> new NidhiException.DirectBalanceMutation(message, e);
            case AlakaSqlState.SG008_MERCHANT_NOT_ALLOWED -> new NidhiException.MerchantNotAllowed(message, e);
            case NidhiException.UniqueViolation.SQL_STATE -> new NidhiException.UniqueViolation(message, e);
            case NidhiException.SerializationFailure.SQL_STATE -> new NidhiException.SerializationFailure(message, e);
            case NidhiException.DeadlockDetected.SQL_STATE -> new NidhiException.DeadlockDetected(message, e);
            default -> new NidhiException.Unclassified(state, message, e);
        };
    }

    /**
     * Returns whether a translated error means the whole transaction may simply be run again.
     *
     * @param e a translated error
     * @return {@code true} for serialization failures and deadlocks
     */
    public static boolean isRetryable(NidhiException e) {
        return e instanceof NidhiException.SerializationFailure || e instanceof NidhiException.DeadlockDetected;
    }
}
