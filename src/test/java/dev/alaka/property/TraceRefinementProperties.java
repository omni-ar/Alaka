package dev.alaka.property;

import static org.assertj.core.api.Assertions.assertThat;

import dev.alaka.core.RuntimeMode;
import dev.alaka.property.RefinementTracer.AbstractIntent;
import dev.alaka.property.RefinementTracer.State;
import dev.alaka.property.SpendLifecycleProperties.World;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterProperty;
import net.jqwik.api.state.ActionChain;

/**
 * Trace validation: the Java engine, PostgreSQL and the simulated rail, driven through random
 * action chains, must produce only behaviours of {@code spec/AlakaInFlight.tla}.
 *
 * <p>Every chain is recorded step by step ({@link RefinementTracer}); after each property TLC
 * checks all its runs with {@code spec/AlakaInFlightTrace.tla} ({@link TraceValidator}). This
 * closes the gap between "the protocol is safe" (model checking) and "the implementation follows
 * the protocol" for the sequential executions exercised here. Concurrent executions are not trace
 * validated.
 *
 * <p>Two negative controls run on the pessimistic traces: a one-unit budget leak in a real trace,
 * and a void of an intent whose rail payment intent is still {@code PROCESSING}. TLC must reject
 * each at the tampered step, or the check proves nothing.
 */
class TraceRefinementProperties {

    private static final List<List<State>> RUNS = new ArrayList<>();
    private static RuntimeMode mode;

    @Property(tries = 12)
    void hardenedPessimisticRunsRefineTheSpec(@ForAll("pessimisticChains") ActionChain<World> chain) {
        record(RuntimeMode.HARDENED_PESSIMISTIC, chain);
    }

    @Property(tries = 12)
    void hardenedSsiRunsRefineTheSpec(@ForAll("ssiChains") ActionChain<World> chain) {
        record(RuntimeMode.HARDENED_SSI, chain);
    }

    @Provide
    Arbitrary<ActionChain<World>> pessimisticChains() {
        return SpendLifecycleProperties.chains(RuntimeMode.HARDENED_PESSIMISTIC, true);
    }

    @Provide
    Arbitrary<ActionChain<World>> ssiChains() {
        return SpendLifecycleProperties.chains(RuntimeMode.HARDENED_SSI, true);
    }

    private static void record(RuntimeMode runMode, ActionChain<World> chain) {
        if (mode != runMode) {
            mode = runMode;
            RUNS.clear();
        }
        chain.run();
        RUNS.add(chain.finalState().orElseThrow().tracer.states());
    }

    @AfterProperty
    void validateRecordedRuns() {
        List<List<State>> runs = List.copyOf(RUNS);
        RUNS.clear();
        if (runs.isEmpty()) {
            return;   // no try completed: the property's own failure is the one to report
        }

        TraceValidator.Verdict verdict = TraceValidator.validate(mode.cliName(), SpendLifecycleProperties.BUDGET,
                SpendLifecycleProperties.CAP, runs);
        Coverage coverage = Coverage.of(runs);
        System.out.printf("TRACE VALIDATION %s: %d runs, %d states, TLC %s (%s)%n", mode.cliName(), runs.size(),
                coverage.states, verdict.accepted() ? "accepted every run" : "REJECTED run " + verdict.rejectedRun()
                        + " after state " + verdict.rejectedStep(), coverage);
        assertThat(verdict.accepted())
                .as("TLC must accept every recorded run as a behaviour of AlakaInFlight; see %s", verdict.log())
                .isTrue();
        assertThat(verdict.runs()).as("one initial state per run").isEqualTo(runs.size());
        // Not vacuous: the runs reached the states the protocol is about.
        assertThat(coverage.processing).as("rail PROCESSING reached").isPositive();
        assertThat(coverage.rejectedCancels).as("/cancel rejected").isPositive();
        assertThat(coverage.partialCaptures).as("partial captures").isPositive();
        assertThat(coverage.voids).as("voids").isPositive();

        if (mode == RuntimeMode.HARDENED_PESSIMISTIC) {
            assertTamperedTracesAreRejected(runs);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Negative controls

    private static void assertTamperedTracesAreRejected(List<List<State>> runs) {
        List<State> longest = runs.stream().max((a, b) -> Integer.compare(a.size(), b.size())).orElseThrow();
        int middle = longest.size() / 2;
        List<State> leaked = new ArrayList<>(longest);
        State s = leaked.get(middle);
        leaked.set(middle, new State(s.mandateStatus(), s.available() + 1, s.held(), s.settled(), s.intents(),
                s.wire(), s.railState(), s.railCharged(), s.cancelResp()));
        TraceValidator.Verdict leak = TraceValidator.validate("negative-budget-leak", SpendLifecycleProperties.BUDGET,
                SpendLifecycleProperties.CAP, List.of(leaked));
        assertThat(leak.accepted()).as("a one-unit budget leak must be rejected").isFalse();
        assertThat(leak.rejectedStep()).as("rejected right before the tampered state").isEqualTo(middle);

        List<State> blindVoid = voidWhileProcessing(runs);
        assertThat(blindVoid).as("some run held an intent while the rail was PROCESSING").isNotNull();
        TraceValidator.Verdict voided = TraceValidator.validate("negative-void-while-processing",
                SpendLifecycleProperties.BUDGET, SpendLifecycleProperties.CAP, List.of(blindVoid));
        assertThat(voided.accepted()).as("voiding while the rail is PROCESSING must be rejected").isFalse();
        assertThat(voided.rejectedStep()).isEqualTo(blindVoid.size() - 1);
        System.out.printf("TRACE VALIDATION negative controls: budget leak rejected after state %d, "
                + "void-while-processing rejected after state %d%n", leak.rejectedStep(), voided.rejectedStep());
    }

    /** A real run cut at a state where an intent is CONFIRMING on a PROCESSING rail, then voided. */
    private static List<State> voidWhileProcessing(List<List<State>> runs) {
        for (List<State> run : runs) {
            for (int i = 0; i < run.size(); i++) {
                State s = run.get(i);
                for (Map.Entry<String, AbstractIntent> e : s.intents().entrySet()) {
                    if (e.getValue().state().equals("CONFIRMING") && "PROCESSING".equals(s.railState().get(e.getKey()))) {
                        Map<String, AbstractIntent> intents = new HashMap<>(s.intents());
                        intents.put(e.getKey(), new AbstractIntent("VOIDED", e.getValue().amount(), 0));
                        long amount = e.getValue().amount();
                        List<State> tampered = new ArrayList<>(run.subList(0, i + 1));
                        tampered.add(new State(s.mandateStatus(), s.available() + amount, s.held() - amount,
                                s.settled(), intents, s.wire(), s.railState(), s.railCharged(), s.cancelResp()));
                        return tampered;
                    }
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------------------------------

    /** What the recorded runs reached. */
    private record Coverage(int states, int processing, int rejectedCancels, int partialCaptures, int voids,
            int revocations) {

        static Coverage of(List<List<State>> runs) {
            int states = 0;
            int processing = 0;
            int rejected = 0;
            int partial = 0;
            int voids = 0;
            int revoked = 0;
            for (List<State> run : runs) {
                states += run.size();
                State last = run.get(run.size() - 1);
                for (Map.Entry<String, AbstractIntent> e : last.intents().entrySet()) {
                    AbstractIntent intent = e.getValue();
                    if (intent.state().equals("VOIDED")) {
                        voids++;
                    }
                    if (intent.state().equals("CAPTURED") && intent.captured() < intent.amount()) {
                        partial++;
                    }
                    if ("REJECTED".equals(last.cancelResp().get(e.getKey()))) {
                        rejected++;
                    }
                }
                if (run.stream().anyMatch(s -> s.railState().containsValue("PROCESSING"))) {
                    processing++;
                }
                if (last.mandateStatus().equals("REVOKED")) {
                    revoked++;
                }
            }
            return new Coverage(states, processing, rejected, partial, voids, revoked);
        }

        @Override
        public String toString() {
            return "runs reaching PROCESSING " + processing + ", rejected cancels " + rejectedCancels
                    + ", partial captures " + partialCaptures + ", voids " + voids + ", revoked mandates " + revocations;
        }
    }
}
