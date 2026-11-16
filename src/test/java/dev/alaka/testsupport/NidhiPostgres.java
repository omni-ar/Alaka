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
    private final String database;

    private NidhiPostgres(PostgreSQLContainer container, String database) {
        this.container = container;
        this.database = database;
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
        return "jdbc:postgresql://" + container.getHost() + ":" + container.getMappedPort(5432) + "/" + database;
    }

    /**
     * Creates (or recreates) a separate database in the same container with every migration
     * applied exactly as for the shared one. For tests whose subject sweeps the whole database,
     * such as the recovery sweeper, so that other test classes' leftover rows cannot interfere.
     *
     * @param name database name, lower-case letters, digits and underscores
     * @return a handle on the fresh database
     */
    public synchronized NidhiPostgres isolatedDatabase(String name) {
        if (!name.matches("[a-z][a-z0-9_]*") || name.equals(DATABASE)) {
            throw new IllegalArgumentException("bad isolated database name " + name);
        }
        exec(container, "postgres", DATABASE, "-c", "DROP DATABASE IF EXISTS " + name + " WITH (FORCE)",
                "-c", "CREATE DATABASE " + name);
        Path migrations = Path.of("migrations").toAbsolutePath();
        for (String file : migrationFileNames(migrations)) {
            applyMigration(container, file.startsWith("000_") ? "postgres" : "alaka_migrator", name, file);
        }
        return new NidhiPostgres(container, name);
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
            applyMigration(container, file.startsWith("000_") ? "postgres" : "alaka_migrator", DATABASE, file);
        }
        return new NidhiPostgres(container, DATABASE);
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

    private static void applyMigration(PostgreSQLContainer container, String role, String database, String file) {
        exec(container, role, database, "--single-transaction", "-f", MIGRATIONS_IN_CONTAINER + "/" + file);
    }

    private static void exec(PostgreSQLContainer container, String role, String database, String... psqlArgs) {
        List<String> command = new java.util.ArrayList<>(
                List.of("psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", database));
        command.addAll(List.of(psqlArgs));
        ExecResult result;
        try {
            result = container.execInContainer(command.toArray(String[]::new));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot run psql " + command, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while running psql " + command, e);
        }
        if (result.getExitCode() != 0) {
            throw new IllegalStateException(
                    "psql " + command + " failed as " + role + " (exit " + result.getExitCode() + "): " + result.getStderr());
        }
    }
}
