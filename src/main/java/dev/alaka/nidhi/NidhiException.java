package dev.alaka.nidhi;

/**
 * A rejection raised by the Nidhi ledger kernel, typed by the SQLSTATE PostgreSQL reported.
 *
 * <p>The hierarchy is sealed: every SQLSTATE the kernel is known to raise has exactly one subtype,
 * and anything else surfaces as {@link Unclassified} so that no database error is ever swallowed
 * or mislabelled. See {@link AlakaSqlState} for the custom {@code SG001}-{@code SG008} class.
 */
public abstract sealed class NidhiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String sqlState;

    private NidhiException(String sqlState, String message, Throwable cause) {
        super(message, cause);
        this.sqlState = sqlState;
    }

    /**
     * Returns the SQLSTATE reported by PostgreSQL.
     *
     * @return the five-character SQLSTATE, for example {@code SG003}
     */
    public String sqlState() {
        return sqlState;
    }

    /** {@code SG001}: mandate inactive, outside its time window, or issued to another agent (I4). */
    public static final class MandateInactive extends NidhiException {
        private static final long serialVersionUID = 1L;

        public MandateInactive(String message, Throwable cause) {
            super(AlakaSqlState.SG001_MANDATE_INACTIVE, message, cause);
        }
    }

    /** {@code SG002}: intent currency differs from the mandate's currency. */
    public static final class CurrencyMismatch extends NidhiException {
        private static final long serialVersionUID = 1L;

        public CurrencyMismatch(String message, Throwable cause) {
            super(AlakaSqlState.SG002_CURRENCY_OR_BUDGET_MISMATCH, message, cause);
        }
    }

    /** {@code SG003}: per-transaction cap or total budget exceeded (I1). */
    public static final class BudgetExceeded extends NidhiException {
        private static final long serialVersionUID = 1L;

        public BudgetExceeded(String message, Throwable cause) {
            super(AlakaSqlState.SG003_BUDGET_EXCEEDED, message, cause);
        }
    }

    /** {@code SG004}: illegal state machine transition or initial state (I5). */
    public static final class IllegalStateTransition extends NidhiException {
        private static final long serialVersionUID = 1L;

        public IllegalStateTransition(String message, Throwable cause) {
            super(AlakaSqlState.SG004_ILLEGAL_STATE_TRANSITION, message, cause);
        }
    }

    /** {@code SG005}: unbalanced transaction, illegal bucket routing or broken conservation (I3). */
    public static final class LedgerConservationViolated extends NidhiException {
        private static final long serialVersionUID = 1L;

        public LedgerConservationViolated(String message, Throwable cause) {
            super(AlakaSqlState.SG005_LEDGER_CONSERVATION_VIOLATED, message, cause);
        }
    }

    /** {@code SG006}: mutation of an immutable audit row or of immutable mandate / intent terms. */
    public static final class ImmutableRowMutation extends NidhiException {
        private static final long serialVersionUID = 1L;

        public ImmutableRowMutation(String message, Throwable cause) {
            super(AlakaSqlState.SG006_IMMUTABLE_ROW_MUTATION, message, cause);
        }
    }

    /** {@code SG007}: direct write to {@code mandate_balances} bypassing the ledger. */
    public static final class DirectBalanceMutation extends NidhiException {
        private static final long serialVersionUID = 1L;

        public DirectBalanceMutation(String message, Throwable cause) {
            super(AlakaSqlState.SG007_DIRECT_BALANCE_MUTATION, message, cause);
        }
    }

    /** {@code SG008}: merchant not in the mandate allowlist. */
    public static final class MerchantNotAllowed extends NidhiException {
        private static final long serialVersionUID = 1L;

        public MerchantNotAllowed(String message, Throwable cause) {
            super(AlakaSqlState.SG008_MERCHANT_NOT_ALLOWED, message, cause);
        }
    }

    /** {@code 23505}: unique violation, for example a replayed {@code (agent_id, idempotency_key)}. */
    public static final class UniqueViolation extends NidhiException {
        private static final long serialVersionUID = 1L;

        /** SQLSTATE {@code unique_violation}. */
        public static final String SQL_STATE = "23505";

        public UniqueViolation(String message, Throwable cause) {
            super(SQL_STATE, message, cause);
        }
    }

    /** {@code 40001}: serialization failure; the whole transaction is safe to retry. */
    public static final class SerializationFailure extends NidhiException {
        private static final long serialVersionUID = 1L;

        /** SQLSTATE {@code serialization_failure}. */
        public static final String SQL_STATE = "40001";

        public SerializationFailure(String message, Throwable cause) {
            super(SQL_STATE, message, cause);
        }
    }

    /** {@code 40P01}: deadlock detected; the whole transaction is safe to retry. */
    public static final class DeadlockDetected extends NidhiException {
        private static final long serialVersionUID = 1L;

        /** SQLSTATE {@code deadlock_detected}. */
        public static final String SQL_STATE = "40P01";

        public DeadlockDetected(String message, Throwable cause) {
            super(SQL_STATE, message, cause);
        }
    }

    /** Any other SQLSTATE; never retried and never treated as a business rejection. */
    public static final class Unclassified extends NidhiException {
        private static final long serialVersionUID = 1L;

        public Unclassified(String sqlState, String message, Throwable cause) {
            super(sqlState, message, cause);
        }
    }
}
