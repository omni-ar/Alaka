package dev.alaka.core;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The three runtime benchmark modes of the execution coordinator, selected on the command line
 * with {@code --mode=<name>}.
 */
public enum RuntimeMode {

    /**
     * {@code --mode=naive}: the anti-pattern baseline. Checks balances in application code under
     * {@code READ COMMITTED} and calls the payment rail inside the request flow. It exists
     * specifically to demonstrate invariant failures under concurrency and crashes.
     */
    NAIVE("naive"),

    /**
     * {@code --mode=hardened-pessimistic}: {@code READ COMMITTED} plus the canonical
     * {@code SELECT ... FOR UPDATE} on {@code mandate_balances}.
     */
    HARDENED_PESSIMISTIC("hardened-pessimistic"),

    /**
     * {@code --mode=hardened-ssi}: {@code SERIALIZABLE} isolation plus exponential backoff with
     * jitter on {@code SQLSTATE 40001}.
     */
    HARDENED_SSI("hardened-ssi");

    private final String cliName;

    RuntimeMode(String cliName) {
        this.cliName = cliName;
    }

    /**
     * Returns the name of this mode as written after {@code --mode=} on the command line.
     *
     * @return the CLI name, for example {@code hardened-ssi}
     */
    public String cliName() {
        return cliName;
    }

    /**
     * Parses the value of the {@code --mode=} option.
     *
     * <p>Matching is exact: the value must equal one of the CLI names character for character.
     * It is not trimmed and not case-folded, so a mistyped mode can never silently select a
     * different one.
     *
     * @param value the text after {@code --mode=}, for example {@code naive}
     * @return the mode whose {@link #cliName()} equals {@code value}
     * @throws NullPointerException if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is not the CLI name of any mode
     */
    public static RuntimeMode fromCliName(String value) {
        Objects.requireNonNull(value, "value");
        for (RuntimeMode mode : values()) {
            if (mode.cliName.equals(value)) {
                return mode;
            }
        }
        String expected = Arrays.stream(values())
                .map(RuntimeMode::cliName)
                .collect(Collectors.joining(", "));
        throw new IllegalArgumentException(
                "Unknown --mode value '" + value + "'; expected one of: " + expected);
    }
}
