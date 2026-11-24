package dev.alaka.property;

import dev.alaka.property.RefinementTracer.AbstractIntent;
import dev.alaka.property.RefinementTracer.State;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks recorded runs against {@code spec/AlakaInFlight.tla} with TLC: writes them as the module
 * {@code AlakaTraceData}, runs {@code spec/AlakaInFlightTrace.tla} over them in a separate JVM
 * ({@code tools/tla2tools.jar}), and reports whether every run is a behaviour of the protocol.
 */
public final class TraceValidator {

    /**
     * TLC's verdict.
     *
     * @param accepted every run is a behaviour of the spec
     * @param runs number of runs TLC started from (distinct initial states)
     * @param rejectedRun 1-based index of the rejected run, or 0
     * @param rejectedStep 1-based index of the last accepted state of that run, or 0
     * @param log path of TLC's full output
     */
    public record Verdict(boolean accepted, int runs, int rejectedRun, int rejectedStep, Path log) {
    }

    private static final Pattern INITIAL = Pattern.compile("Finished computing initial states: (\\d+) distinct state");
    private static final Pattern RUN = Pattern.compile("^/\\\\ t = (\\d+)$", Pattern.MULTILINE);
    private static final Pattern STEP = Pattern.compile("^/\\\\ i = (\\d+)$", Pattern.MULTILINE);

    private TraceValidator() {
    }

    /**
     * Validates runs.
     *
     * @param name name of the working directory under the build directory
     * @param budget the mandate's total budget
     * @param cap the mandate's per-transaction cap
     * @param runs recorded runs, each starting in the mandate's initial state
     * @return TLC's verdict
     */
    public static Verdict validate(String name, long budget, long cap, List<List<State>> runs) {
        try {
            Path dir = buildDir().resolve("trace-validation").resolve(name);
            Files.createDirectories(dir);
            Files.copy(Path.of("spec", "AlakaInFlight.tla"), dir.resolve("AlakaInFlight.tla"),
                    StandardCopyOption.REPLACE_EXISTING);
            Files.copy(Path.of("spec", "AlakaInFlightTrace.tla"), dir.resolve("AlakaInFlightTrace.tla"),
                    StandardCopyOption.REPLACE_EXISTING);
            Files.writeString(dir.resolve("AlakaTraceData.tla"), dataModule(budget, cap, runs), StandardCharsets.UTF_8);
            Files.writeString(dir.resolve("AlakaInFlightTrace.cfg"), CONFIG, StandardCharsets.UTF_8);
            Path log = dir.resolve("tlc.log");
            Process tlc = new ProcessBuilder(
                    ProcessHandle.current().info().command().orElse("java"), "-XX:+UseParallelGC",
                    "-cp", Path.of("tools", "tla2tools.jar").toAbsolutePath().toString(),
                    "tlc2.TLC", "-workers", "1", "-metadir", "states",
                    "-config", "AlakaInFlightTrace.cfg", "AlakaInFlightTrace.tla")
                    .directory(dir.toFile())
                    .redirectErrorStream(true)
                    .redirectOutput(log.toFile())
                    .start();
            if (!tlc.waitFor(5, TimeUnit.MINUTES)) {
                tlc.destroyForcibly();
                throw new IllegalStateException("TLC did not finish within 5 minutes; see " + log);
            }
            String output = Files.readString(log, StandardCharsets.UTF_8);
            int initial = find(INITIAL, output);
            boolean accepted = tlc.exitValue() == 0 && output.contains("Model checking completed. No error has been found.");
            return new Verdict(accepted, initial, accepted ? 0 : find(RUN, output), accepted ? 0 : find(STEP, output), log);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while running TLC", e);
        }
    }

    private static final String CONFIG = """
            CONSTANTS
                IdempKeys <- TraceKeys
                Amounts <- TraceAmounts
                MandateBudget <- TraceBudget
                MaxPerTx <- TraceCap
                PartialCaptureAmounts <- TraceCharges
                AllowBlindVoidWithoutCancel = FALSE
                AllowVoidOnCancelFailure = FALSE
            INIT TraceInit
            NEXT TraceNext
            CHECK_DEADLOCK TRUE
            """;

    private static String dataModule(long budget, long cap, List<List<State>> runs) {
        TreeSet<String> keys = new TreeSet<>();
        TreeSet<Long> amounts = new TreeSet<>();
        TreeSet<Long> charges = new TreeSet<>();
        for (List<State> run : runs) {
            for (State state : run) {
                keys.addAll(state.intents().keySet());
                state.intents().values().forEach(intent -> amounts.add(intent.amount()));
                charges.addAll(state.railCharged().values());
            }
        }
        if (keys.isEmpty()) {
            keys.add("unused");   // the spec assumes a non-empty key set
        }
        amounts.remove(0L);
        charges.remove(0L);
        StringBuilder out = new StringBuilder()
                .append("---- MODULE AlakaTraceData ----\n")
                .append("\\* Generated by dev.alaka.property.TraceValidator. Do not edit.\n")
                .append("EXTENDS TLC, Integers, Sequences\n")
                .append("TraceKeys == ").append(set(keys, s -> quote(s))).append('\n')
                .append("TraceAmounts == ").append(set(amounts, String::valueOf)).append('\n')
                .append("TraceCharges == ").append(set(charges, String::valueOf)).append('\n')
                .append("TraceBudget == ").append(budget).append('\n')
                .append("TraceCap == ").append(cap).append('\n')
                .append("Traces == <<\n");
        StringJoiner allRuns = new StringJoiner(",\n");
        for (List<State> run : runs) {
            StringJoiner states = new StringJoiner(",\n    ", "  <<\n    ", "\n  >>");
            for (State state : run) {
                states.add(state(state, keys));
            }
            allRuns.add(states.toString());
        }
        return out.append(allRuns).append("\n>>\n====\n").toString();
    }

    private static String state(State s, TreeSet<String> keys) {
        return "[ms |-> " + quote(s.mandateStatus())
                + ", av |-> " + s.available() + ", he |-> " + s.held() + ", se |-> " + s.settled()
                + ", it |-> " + fn(keys, k -> {
                    AbstractIntent intent = s.intents().getOrDefault(k, new AbstractIntent("NONE", 0, 0));
                    return "[state |-> " + quote(intent.state()) + ", amount |-> " + intent.amount()
                            + ", captured |-> " + intent.captured() + "]";
                })
                + ", wc |-> " + fn(keys, k -> quote(orNone(s.wire(), k)))
                + ", rp |-> " + fn(keys, k -> quote(orNone(s.railState(), k)))
                + ", rc |-> " + fn(keys, k -> String.valueOf(s.railCharged().getOrDefault(k, 0L)))
                + ", cr |-> " + fn(keys, k -> quote(orNone(s.cancelResp(), k)))
                + "]";
    }

    private static String orNone(Map<String, String> values, String key) {
        return values.getOrDefault(key, "NONE");
    }

    private static String fn(TreeSet<String> keys, Function<String, String> value) {
        StringJoiner joined = new StringJoiner(" @@ ", "(", ")");
        for (String key : keys) {
            joined.add("(" + quote(key) + " :> " + value.apply(key) + ")");
        }
        return joined.toString();
    }

    private static <T> String set(TreeSet<T> values, Function<T, String> render) {
        StringJoiner joined = new StringJoiner(", ", "{", "}");
        values.forEach(v -> joined.add(render.apply(v)));
        return joined.toString();
    }

    private static String quote(String s) {
        return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    private static int find(Pattern pattern, String output) {
        Matcher matcher = pattern.matcher(output);
        int last = 0;
        while (matcher.find()) {
            last = Integer.parseInt(matcher.group(1));
        }
        return last;
    }

    private static Path buildDir() {
        try {
            Path classes = Path.of(TraceValidator.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return classes.getParent();
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
