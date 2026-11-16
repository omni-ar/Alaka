package dev.alaka.testsupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.junit.jupiter.api.Test;

class NidhiPostgresTest {

    @Test
    void connectsAsLeastPrivilegeRoleToMigratedSchema() throws SQLException {
        try (Connection connection = NidhiPostgres.shared().openAppConnection();
                Statement statement = connection.createStatement()) {
            try (ResultSet row = statement.executeQuery(
                    "SELECT current_user, session_user,"
                            + " (SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"
                            + "   AND tablename IN ('spend_mandates', 'mandate_balances', 'payment_intents',"
                            + "                     'ledger_transactions', 'ledger_postings'))")) {
                assertThat(row.next()).isTrue();
                assertThat(row.getString(1)).isEqualTo(NidhiPostgres.APP_USER);
                assertThat(row.getString(2)).isEqualTo(NidhiPostgres.APP_USER);
                assertThat(row.getInt(3)).isEqualTo(5);
            }
            assertThatThrownBy(() -> statement.execute("TRUNCATE ledger_postings"))
                    .isInstanceOfSatisfying(
                            SQLException.class, e -> assertThat(e.getSQLState()).isEqualTo("42501"));
        }
    }
}
