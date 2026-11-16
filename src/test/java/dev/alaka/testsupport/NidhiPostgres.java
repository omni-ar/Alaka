package dev.alaka.testsupport;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.stream.Stream;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

/**
 * A throwaway PostgreSQL 16 with the Nidhi schema, shared by every test in the JVM.
 *
 * <p>Setup mirrors production role separation exactly: {@code migrations/000_roles.sql} is applied
 * as the superuser {@code postgres}, every later migration (in file-name order) as
 * {@code alaka_migrator}, each through {@code psql --single-transaction} inside the container.
 * Tests then connect only as the least-privilege runtime role {@code alaka_app}; this class hands
 * out no other kind of connection.
 */
public final class NidhiPostgres {

    /** The runtime role every test connects as. */
    public static final String APP_USER = "alaka_app";

    private static final String APP_PASSWORD = "alaka_app_dev_only";
    private static final String DATABASE = "alaka";
    private static final String MIGRATIONS_IN_CONTAINER = "/alaka-migrations";

    private static NidhiPostgres shared;

    private final PostgreSQLContainer container;

    private NidhiPostgres(PostgreSQLContainer container) {
        this.container = container;
    }

    /**
     * Returns the JVM-wide instance, starting the container and applying the migrations on first
     * use. The container is removed when the JVM exits.
     *
     * @return the shared database
     */
    public static synchronized NidhiPostgres shared() {
        if (shared == null) {
            shared = start();
        }
        return shared;
    }

    /**
     * Returns the JDBC URL of the database.
     *
     * @return a {@code jdbc:postgresql://} URL reachable from the test JVM
     */
    public String jdbcUrl() {
        return container.getJdbcUrl();
    }

    /**
     * Opens a new, unpooled connection as {@code alaka_app}. The caller closes it.
     *
     * @return an open connection in autocommit mode at the default isolation level
     * @throws SQLException if the connection cannot be opened
     */
    public Connection openAppConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl(), APP_USER, APP_PASSWORD);
    }

    /**
     * Creates a new HikariCP pool of {@code alaka_app} connections. The caller closes it.
     *
     * @param maxPoolSize maximum number of connections; the server accepts 300 in total
     * @return a started pool
     */
    public HikariDataSource newAppDataSource(int maxPoolSize) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl());
        config.setUsername(APP_USER);
        config.setPassword(APP_PASSWORD);
        config.setMaximumPoolSize(maxPoolSize);
        config.setPoolName("alaka-app-test");
        return new HikariDataSource(config);
    }

    private static NidhiPostgres start() {
        Path migrations = Path.of("migrations").toAbsolutePath();
        PostgreSQLContainer container = new PostgreSQLContainer("postgres:16-alpine")
                .withDatabaseName(DATABASE)
                .withUsername("postgres")
                .withPassword("alaka_dev_only")
                .withCommand("postgres", "-c", "max_connections=300")
                .withCopyFileToContainer(MountableFile.forHostPath(migrations), MIGRATIONS_IN_CONTAINER);
        container.start();

        List<String> files = migrationFileNames(migrations);
        if (files.isEmpty() || !files.get(0).startsWith("000_")) {
            throw new IllegalStateException("Expected migrations starting with 000_ in " + migrations);
        }
        for (String file : files) {
            applyMigration(container, file.startsWith("000_") ? "postgres" : "alaka_migrator", file);
        }
        return new NidhiPostgres(container);
    }

    private static List<String> migrationFileNames(Path migrations) {
        try (Stream<Path> paths = Files.list(migrations)) {
            return paths.map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".sql"))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot list " + migrations, e);
        }
    }

    private static void applyMigration(PostgreSQLContainer container, String role, String file) {
        ExecResult result;
        try {
            result = container.execInContainer(
                    "psql", "-X", "-v", "ON_ERROR_STOP=1", "--single-transaction",
                    "-U", role, "-d", DATABASE, "-f", MIGRATIONS_IN_CONTAINER + "/" + file);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot run psql for " + file, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while applying " + file, e);
        }
        if (result.getExitCode() != 0) {
            throw new IllegalStateException(
                    "Migration " + file + " failed as " + role + " (exit " + result.getExitCode() + "): "
                            + result.getStderr());
        }
    }
}
