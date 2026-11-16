package dev.alaka.nidhi;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class SqlStatesTest {

    @ParameterizedTest
    @CsvSource({
        "SG001, MandateInactive, false",
        "SG002, CurrencyMismatch, false",
        "SG003, BudgetExceeded, false",
        "SG004, IllegalStateTransition, false",
        "SG005, LedgerConservationViolated, false",
        "SG006, ImmutableRowMutation, false",
        "SG007, DirectBalanceMutation, false",
        "SG008, MerchantNotAllowed, false",
        "23505, UniqueViolation, false",
        "40001, SerializationFailure, true",
        "40P01, DeadlockDetected, true",
        "23503, Unclassified, false",
        "P0001, Unclassified, false",
    })
    void translatesEverySqlState(String sqlState, String expectedType, boolean retryable) {
        SQLException cause = new SQLException("boom", sqlState);
        NidhiException translated = SqlStates.translate(cause);

        assertThat(translated.getClass().getSimpleName()).isEqualTo(expectedType);
        assertThat(translated.sqlState()).isEqualTo(sqlState);
        assertThat(translated.getCause()).isSameAs(cause);
        assertThat(SqlStates.isRetryable(translated)).isEqualTo(retryable);
    }
}
