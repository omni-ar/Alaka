package dev.alaka.property;

import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * The one place where invariants I1-I6 of {@code CLAUDE.md} section 4 are checked for one mandate,
 * shared by the stateful property suite and the concurrency storm.
 *
 * <p>The checker compares three independent sources: the engine's own view
 * ({@link SpendEngine#balances}, {@link SpendEngine#intentsOf}, {@link SpendEngine#findIntent}), the
 * ledger's truth read through raw JDBC as {@code alaka_app} in a single {@code REPEATABLE READ}
 * snapshot that the engine has no part in, and the rail's truth
 * ({@link SimulatedPaymentRail#paymentIntents()}, {@link SimulatedPaymentRail#totalChargedMinor()}).
 *
 * <p>For {@link RuntimeMode#NAIVE} there is no ledger to read (the baseline does its own
 * bookkeeping), so the engine's view is taken as the system's claim and only the engine-and-rail
 * checks run; that is exactly what makes the baseline's drift from the rail visible.
 *
 * <p>The checker assumes the rail instance serves this mandate only. It is stateful: it remembers
 * every intent it has seen (for I5) and the set of intents that existed at revocation (for I4).
 * Calls are serialised.
 */
public final class InvariantChecker {

    /**
     * One invariant violation.
     *
     * @param invariant the invariant violated, {@code I1} to {@code I6}, or {@code VIEW} when the
     *     engine's view disagrees with the ledger or the rail contradicts itself
     * @param detail what was observed
     */
    public record Violation(String invariant, String detail) {
        @Override
        public String toString() {
            return invariant + ": " + detail;
        }
    }

    /**
     * Result of one check: the violations found and the facts they were derived from.
     *
     * @param violations every violation found; empty if all invariants hold
     * @param mandateStatus the mandate's status in the ledger, or {@code null} without a ledger
     * @param balances the mandate's buckets, from the ledger where there is one, otherwise from the
     *     engine
     * @param intents the mandate's intents, oldest first, from the ledger where there is one,
     *     otherwise from the engine
     * @param railIntents the rail's payment intents, read after {@code balances} and
     *     {@code intents}
     * @param railTotalChargedMinor the rail's total of succeeded charges
     */
    public record Report(
            List<Violation> violations,
            String mandateStatus,
            MandateBalances balances,
            List<IntentView> intents,
            List<RailPaymentIntent> railIntents,
            long railTotalChargedMinor) {

        public Report {
            violations = List.copyOf(violations);
            intents = List.copyOf(intents);
            railIntents = List.copyOf(railIntents);
        }

        /**
         * Returns whether every invariant held.
         *
         * @return {@code true} if there are no violations
         */
        public boolean clean() {
            return violations.isEmpty();
        }

        /**
         * Finds the rail payment intent of a gateway intent.
         *
         * @param intentId gateway intent id
         * @return the payment intents the rail holds for it; more than one is itself a violation
         */
        public List<RailPaymentIntent> railIntentsOf(UUID intentId) {
            return railIntents.stream().filter(pi -> pi.intentId().equals(intentId)).toList();
        }
    }

    private record LedgerRow(IntentView view, Timestamp createdAt) {
    }

    private record LedgerSnapshot(
            boolean mandateExists,
            String mandateStatus,
            long mandateTotal,
            long mandateCap,
            MandateBalances balances,
            List<LedgerRow> intents,
            Map<String, Long> netByBucket,
            List<String> unbalancedTransactions,
            Map<UUID, Set<String>> transitionsByIntent) {
    }

    private final RuntimeMode mode;
    private final SpendEngine engine;
    private final SimulatedPaymentRail rail;
    private final DataSource truth;
    private final UUID mandateId;
    private final long totalBudgetMinor;
    private final long maxPerTxMinor;

    private final Map<UUID, IntentView> lastSeen = new HashMap<>();
    private Set<UUID> intentsAtRevocation;
    private long checksRun;

    /**
     * Creates a checker for one mandate.
     *
     * @param engine the engine under test
     * @param rail the simulated rail the engine charges, serving this mandate only
     * @param truth {@code alaka_app} connections independent of the engine's, used for the raw
     *     ledger reads
     * @param mandateId the mandate
     * @param totalBudgetMinor the mandate's signed total budget
     * @param maxPerTxMinor the mandate's signed per-transaction cap
     */
    public InvariantChecker(
            SpendEngine engine,
            SimulatedPaymentRail rail,
            DataSource truth,
            UUID mandateId,
            long totalBudgetMinor,
            long maxPerTxMinor) {
        this.mode = engine.mode();
        this.engine = Objects.requireNonNull(engine, "engine");
        this.rail = Objects.requireNonNull(rail, "rail");
        this.truth = Objects.requireNonNull(truth, "truth");
        this.mandateId = Objects.requireNonNull(mandateId, "mandateId");
        this.totalBudgetMinor = totalBudgetMinor;
        this.maxPerTxMinor = maxPerTxMinor;
    }

    /**
     * Returns whether the mode keeps its books in the Nidhi ledger, so that the raw ledger checks
     * apply.
     *
     * @return {@code false} for {@link RuntimeMode#NAIVE}
     */
    public boolean ledgerBacked() {
        return mode != RuntimeMode.NAIVE;
    }

    /**
     * Returns how many checks have been run.
     *
     * @return the number of {@link #check} calls so far
     */
    public synchronized long checksRun() {
        return checksRun;
    }

    /**
     * Records that the mandate has just been revoked: from now on any intent that did not exist at
     * this moment is an I4 violation. Call it after {@link SpendEngine#revokeMandate} has returned
     * and while no reservation is in flight.
     */
    public synchronized void markRevoked() {
        Set<UUID> ids = new HashSet<>();
        for (IntentView intent : truthIntents()) {
            ids.add(intent.intentId());
        }
        intentsAtRevocation = ids;
    }

    /**
     * Checks I1-I6 and throws if any is violated.
     *
     * @param context what had just happened, for the failure message
     * @param quiescent as for {@link #check}
     * @return the clean report
     * @throws AssertionError listing every violation
     */
    public Report assertHolds(String context, boolean quiescent) {
        Report report = check(quiescent);
        if (!report.clean()) {
            StringBuilder message = new StringBuilder()
                    .append(report.violations().size())
                    .append(" invariant violation(s) in mode ")
                    .append(mode.cliName())
                    .append(" on mandate ")
                    .append(mandateId)
                    .append(" after ")
                    .append(context)
                    .append(':');
            for (Violation violation : report.violations()) {
                message.append("\n  ").append(violation);
            }
            message.append("\n  balances: ").append(report.balances());
            message.append("\n  rail total charged: ").append(report.railTotalChargedMinor());
            throw new AssertionError(message.toString());
        }
        return report;
    }

    /**
     * Checks I1-I6.
     *
     * @param quiescent {@code true} if no engine call is in flight, which additionally enables the
     *     checks that need the engine, the ledger and the rail to be read at the same instant
     *     (engine view against ledger, worst-case rail exposure, rail self-consistency). With
     *     {@code false} only checks that are sound while requests are running are made: the ledger
     *     facts come from one snapshot, and the rail is read before it (for "every payment intent
     *     has an intent") and after it (for I6 on terminal intents, which never change).
     * @return the violations and the facts behind them
     */
    public synchronized Report check(boolean quiescent) {
        checksRun++;
        List<Violation> violations = new ArrayList<>();

        List<RailPaymentIntent> railBefore = rail.paymentIntents();
        String mandateStatus = null;
        MandateBalances balances;
        List<IntentView> intents;
        if (ledgerBacked()) {
            LedgerSnapshot ledger = readLedger();
            mandateStatus = ledger.mandateStatus();
            balances = ledger.balances();
            intents = ledger.intents().stream().map(LedgerRow::view).toList();
            checkLedger(ledger, violations);
            if (quiescent) {
                checkEngineViewAgainstLedger(ledger, violations);
            }
        } else {
            balances = engine.balances(mandateId);
            intents = engine.intentsOf(mandateId);
        }
        List<RailPaymentIntent> railAfter = rail.paymentIntents();
        long railTotal = rail.totalChargedMinor();

        if (balances != null) {
            checkBalances(balances, violations);
        }
        checkIntentsAndRail(intents, railBefore, railAfter, railTotal, quiescent, violations);
        checkRevocation(mandateStatus, intents, violations);
        checkTransitions(intents, violations);

        return new Report(violations, mandateStatus, balances, intents, railAfter, railTotal);
    }

    // ------------------------------------------------------------------------------------------
    // I1 / I3 on the three buckets

    private void checkBalances(MandateBalances balances, List<Violation> violations) {
        if (balances.totalBudgetMinor() != totalBudgetMinor) {
            violations.add(new Violation("I3", "total budget is " + balances.totalBudgetMinor()
                    + " but the mandate was signed for " + totalBudgetMinor));
        }
        if (balances.availableMinor() < 0 || balances.heldMinor() < 0 || balances.settledMinor() < 0) {
            violations.add(new Violation("I3", "negative bucket: " + balances));
        }
        if (balances.availableMinor() + balances.heldMinor() + balances.settledMinor()
                != balances.totalBudgetMinor()) {
            violations.add(new Violation("I3", "available + held + settled != total: " + balances));
        }
        if (balances.heldMinor() + balances.settledMinor() > totalBudgetMinor) {
            violations.add(new Violation("I1", "held + settled = "
                    + (balances.heldMinor() + balances.settledMinor()) + " exceeds total budget "
                    + totalBudgetMinor));
        }
    }

    // ------------------------------------------------------------------------------------------
    // I1 / I2 / I6 across intents and the rail

    private void checkIntentsAndRail(
            List<IntentView> intents,
            List<RailPaymentIntent> railBefore,
            List<RailPaymentIntent> railAfter,
            long railTotal,
            boolean quiescent,
            List<Violation> violations) {

        // I1: the rail's ground truth and the per-transaction cap.
        if (railTotal > totalBudgetMinor) {
            violations.add(new Violation("I1", "rail charged " + railTotal + " against a total budget of "
                    + totalBudgetMinor + " (overspend " + (railTotal - totalBudgetMinor) + ")"));
        }
        for (IntentView intent : intents) {
            if (intent.authorizedAmountMinor() > maxPerTxMinor) {
                violations.add(new Violation("I1", "intent " + describe(intent) + " authorises "
                        + intent.authorizedAmountMinor() + " above the per-tx cap " + maxPerTxMinor));
            }
            if (intent.authorizedAmountMinor() <= 0) {
                violations.add(new Violation("I1", "intent " + describe(intent)
                        + " authorises a non-positive amount"));
            }
        }

        // I2: one intent per (agent, key).
        Map<String, List<IntentView>> byKey = new LinkedHashMap<>();
        Map<UUID, IntentView> byId = new HashMap<>();
        for (IntentView intent : intents) {
            byKey.computeIfAbsent(intent.agentId() + "\u0000" + intent.idempotencyKey(), k -> new ArrayList<>())
                    .add(intent);
            if (byId.put(intent.intentId(), intent) != null) {
                violations.add(new Violation("I2", "intent id " + intent.intentId() + " listed twice"));
            }
        }
        for (List<IntentView> sameKey : byKey.values()) {
            if (sameKey.size() > 1) {
                violations.add(new Violation("I2", sameKey.size() + " intents share idempotency key "
                        + describe(sameKey.get(0))));
            }
        }

        // I2: one rail payment intent per gateway intent, hence at most one charge per key.
        Map<UUID, List<RailPaymentIntent>> railByIntent = new LinkedHashMap<>();
        Map<String, RailPaymentIntent> railByPi = new HashMap<>();
        for (RailPaymentIntent pi : railAfter) {
            railByIntent.computeIfAbsent(pi.intentId(), k -> new ArrayList<>()).add(pi);
            if (railByPi.put(pi.piId(), pi) != null) {
                violations.add(new Violation("VIEW", "rail lists payment intent " + pi.piId() + " twice"));
            }
        }
        for (Map.Entry<UUID, List<RailPaymentIntent>> entry : railByIntent.entrySet()) {
            if (entry.getValue().size() > 1) {
                violations.add(new Violation("I2", entry.getValue().size()
                        + " rail payment intents for gateway intent " + entry.getKey() + ": " + entry.getValue()));
            }
        }
        Map<String, Integer> chargesByKey = new HashMap<>();
        for (RailPaymentIntent pi : railAfter) {
            IntentView owner = ownerOf(pi, byId, intents);
            if (pi.status() == RailPiStatus.SUCCEEDED) {
                if (owner == null) {
                    if (quiescent || !ledgerBacked()) {
                        violations.add(new Violation("I2", "rail charge " + pi + " belongs to no intent"));
                    }
                } else {
                    chargesByKey.merge(owner.agentId() + "\u0000" + owner.idempotencyKey(), 1, Integer::sum);
                }
            }
            if (pi.amountMinor() > maxPerTxMinor) {
                violations.add(new Violation("I1", "rail payment intent " + pi + " exceeds the per-tx cap "
                        + maxPerTxMinor));
            }
            if (pi.status() == RailPiStatus.SUCCEEDED
                    ? (pi.chargedMinor() < 1 || pi.chargedMinor() > pi.amountMinor())
                    : pi.chargedMinor() != 0) {
                violations.add(new Violation("VIEW", "rail payment intent has an impossible charge: " + pi));
            }
        }
        for (Map.Entry<String, Integer> entry : chargesByKey.entrySet()) {
            if (entry.getValue() > 1) {
                violations.add(new Violation("I2", entry.getValue() + " succeeded charges for idempotency key "
                        + entry.getKey().replace('\u0000', '/')));
            }
        }
        if (ledgerBacked()) {
            // The rail was read before the ledger here: an intent is committed before its payment
            // intent is created and never disappears, so each of these must have an owner.
            for (RailPaymentIntent pi : railBefore) {
                if (!byId.containsKey(pi.intentId())) {
                    violations.add(new Violation("I2", "rail payment intent " + pi
                            + " refers to no intent of the mandate"));
                }
            }
        }

        // I6 and capture consistency, intent by intent.
        long exposure = 0;
        for (IntentView intent : intents) {
            List<RailPaymentIntent> pis = railIntentsFor(intent, railByIntent, railByPi);
            RailPaymentIntent pi = pis.isEmpty() ? null : pis.get(0);
            if (intent.railPaymentIntentId() != null) {
                if (pi == null) {
                    violations.add(new Violation("I6", "intent " + describe(intent) + " records rail payment intent "
                            + intent.railPaymentIntentId() + " which the rail does not know"));
                    continue;
                }
                if (!pi.piId().equals(intent.railPaymentIntentId())) {
                    violations.add(new Violation("I6", "intent " + describe(intent) + " records "
                            + intent.railPaymentIntentId() + " but the rail holds " + pi.piId() + " for it"));
                }
                if (pi.amountMinor() != intent.authorizedAmountMinor()) {
                    violations.add(new Violation("I6", "intent " + describe(intent) + " authorises "
                            + intent.authorizedAmountMinor() + " but its rail payment intent is for "
                            + pi.amountMinor()));
                }
            }
            switch (intent.status()) {
                case VOIDED, FAILED -> {
                    if (pi != null && pi.status() == RailPiStatus.SUCCEEDED) {
                        violations.add(new Violation("I6", intent.status() + " intent " + describe(intent)
                                + " has a succeeded charge of " + pi.chargedMinor() + " on the rail (" + pi.piId()
                                + ")"));
                    } else if (pi != null && pi.status() == RailPiStatus.PROCESSING) {
                        violations.add(new Violation("I6", intent.status() + " intent " + describe(intent)
                                + " was released while its rail payment intent " + pi.piId()
                                + " is still PROCESSING and can yet succeed"));
                    } else if (pi != null && intent.railPaymentIntentId() != null
                            && pi.status() != RailPiStatus.CANCELED) {
                        violations.add(new Violation("I6", intent.status() + " intent " + describe(intent)
                                + " was released without its rail payment intent " + pi.piId()
                                + " being canceled (rail status " + pi.status() + ")"));
                    }
                    if (intent.capturedAmountMinor() != 0) {
                        violations.add(new Violation("I6", intent.status() + " intent " + describe(intent)
                                + " carries a captured amount of " + intent.capturedAmountMinor()));
                    }
                }
                case CAPTURED -> {
                    if (pi == null || pi.status() != RailPiStatus.SUCCEEDED) {
                        violations.add(new Violation("I6", "CAPTURED intent " + describe(intent)
                                + " has no succeeded charge on the rail (rail: " + pi + ")"));
                    } else if (pi.chargedMinor() != intent.capturedAmountMinor()) {
                        violations.add(new Violation("I6", "CAPTURED intent " + describe(intent) + " settled "
                                + intent.capturedAmountMinor() + " but the rail charged " + pi.chargedMinor()));
                    }
                    if (intent.capturedAmountMinor() < 1
                            || intent.capturedAmountMinor() > intent.authorizedAmountMinor()) {
                        violations.add(new Violation("I6", "CAPTURED intent " + describe(intent)
                                + " has captured amount " + intent.capturedAmountMinor() + " outside 1.."
                                + intent.authorizedAmountMinor()));
                    }
                    if (pi != null && pi.status() == RailPiStatus.SUCCEEDED) {
                        exposure += pi.chargedMinor();
                    }
                }
                default -> {
                    if (intent.capturedAmountMinor() != 0) {
                        violations.add(new Violation("I5", intent.status() + " intent " + describe(intent)
                                + " carries a captured amount of " + intent.capturedAmountMinor()));
                    }
                    if (intent.status() != IntentStatus.RESERVED && intent.railPaymentIntentId() == null) {
                        violations.add(new Violation("I5", intent.status() + " intent " + describe(intent)
                                + " has no rail payment intent recorded"));
                    }
                    if (pi != null) {
                        exposure += pi.status() == RailPiStatus.SUCCEEDED
                                ? pi.chargedMinor()
                                : pi.status() == RailPiStatus.CANCELED ? 0 : pi.amountMinor();
                    }
                }
            }
        }

        if (quiescent) {
            // Look-ahead form of I1 (RailWorstCaseExposureWithinBudget in spec/AlakaInFlight.tla):
            // even if every payment intent that can still succeed were charged in full, the rail
            // total stays within budget.
            if (exposure > totalBudgetMinor) {
                violations.add(new Violation("I1", "worst-case rail exposure " + exposure
                        + " (succeeded charges plus payment intents of open intents that can still succeed)"
                        + " exceeds total budget " + totalBudgetMinor));
            }
            long summed = 0;
            for (RailPaymentIntent pi : railAfter) {
                if (pi.status() == RailPiStatus.SUCCEEDED) {
                    summed += pi.chargedMinor();
                }
            }
            if (summed != railTotal) {
                violations.add(new Violation("VIEW", "rail totalChargedMinor() = " + railTotal
                        + " but its succeeded payment intents sum to " + summed));
            }
        }
    }

    private static IntentView ownerOf(RailPaymentIntent pi, Map<UUID, IntentView> byId, List<IntentView> intents) {
        IntentView owner = byId.get(pi.intentId());
        if (owner != null) {
            return owner;
        }
        for (IntentView intent : intents) {
            if (pi.piId().equals(intent.railPaymentIntentId())) {
                return intent;
            }
        }
        return null;
    }

    private static List<RailPaymentIntent> railIntentsFor(
            IntentView intent,
            Map<UUID, List<RailPaymentIntent>> railByIntent,
            Map<String, RailPaymentIntent> railByPi) {
        List<RailPaymentIntent> pis = railByIntent.get(intent.intentId());
        if (pis != null) {
            return pis;
        }
        RailPaymentIntent byPi = intent.railPaymentIntentId() == null
                ? null
                : railByPi.get(intent.railPaymentIntentId());
        return byPi == null ? List.of() : List.of(byPi);
    }

    // ------------------------------------------------------------------------------------------
    // I4

    private void checkRevocation(String mandateStatus, List<IntentView> intents, List<Violation> violations) {
        if (intentsAtRevocation == null) {
            return;
        }
        if (ledgerBacked() && !"REVOKED".equals(mandateStatus)) {
            violations.add(new Violation("I4", "mandate was revoked but its status is now " + mandateStatus));
        }
        for (IntentView intent : intents) {
            if (!intentsAtRevocation.contains(intent.intentId())) {
                violations.add(new Violation("I4", "intent " + describe(intent) + " for "
                        + intent.authorizedAmountMinor() + " was reserved after the mandate was revoked"));
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // I5

    private void checkTransitions(List<IntentView> intents, List<Violation> violations) {
        Set<UUID> present = new HashSet<>();
        for (IntentView now : intents) {
            present.add(now.intentId());
            IntentView before = lastSeen.put(now.intentId(), now);
            if (before == null) {
                continue;
            }
            if (!sameImmutableFields(before, now)) {
                violations.add(new Violation("I5", "immutable fields of intent " + describe(now)
                        + " changed from " + before + " to " + now));
            }
            if (before.status().isTerminal()) {
                if (!before.equals(now)) {
                    violations.add(new Violation("I5", "terminal intent " + describe(now) + " changed from "
                            + before + " to " + now));
                }
            } else if (before.status() != now.status() && rank(now.status()) <= rank(before.status())) {
                violations.add(new Violation("I5", "intent " + describe(now) + " moved backwards from "
                        + before.status() + " to " + now.status()));
            }
            if (before.railPaymentIntentId() != null
                    && !before.railPaymentIntentId().equals(now.railPaymentIntentId())) {
                violations.add(new Violation("I5", "intent " + describe(now) + " changed its rail payment intent from "
                        + before.railPaymentIntentId() + " to " + now.railPaymentIntentId()));
            }
        }
        for (Map.Entry<UUID, IntentView> seen : lastSeen.entrySet()) {
            if (!present.contains(seen.getKey())) {
                violations.add(new Violation("I5", "intent " + describe(seen.getValue())
                        + " existed earlier and has disappeared"));
            }
        }
    }

    private static int rank(IntentStatus status) {
        return switch (status) {
            case RESERVED -> 0;
            case CONFIRMING -> 1;
            case AUTHORIZED -> 2;
            case CAPTURED, VOIDED, FAILED -> 3;
        };
    }

    private static boolean sameImmutableFields(IntentView a, IntentView b) {
        return a.mandateId().equals(b.mandateId())
                && Objects.equals(a.agentId(), b.agentId())
                && Objects.equals(a.idempotencyKey(), b.idempotencyKey())
                && Objects.equals(a.requestHash(), b.requestHash())
                && Objects.equals(a.merchantId(), b.merchantId())
                && Objects.equals(a.currency(), b.currency())
                && a.authorizedAmountMinor() == b.authorizedAmountMinor();
    }

    // ------------------------------------------------------------------------------------------
    // I3 against the raw ledger

    private void checkLedger(LedgerSnapshot ledger, List<Violation> violations) {
        if (!ledger.mandateExists() || ledger.balances() == null) {
            violations.add(new Violation("I3", "mandate " + mandateId + " or its balance row is missing in the ledger"));
            return;
        }
        if (ledger.mandateTotal() != totalBudgetMinor || ledger.mandateCap() != maxPerTxMinor) {
            violations.add(new Violation("I1", "mandate terms changed: total " + ledger.mandateTotal() + ", cap "
                    + ledger.mandateCap() + ", signed for " + totalBudgetMinor + " / " + maxPerTxMinor));
        }
        MandateBalances row = ledger.balances();

        // The materialised row must be exactly what the postings imply.
        long impliedAvailable = totalBudgetMinor + ledger.netByBucket().getOrDefault("MANDATE_AVAILABLE", 0L);
        long impliedHeld = ledger.netByBucket().getOrDefault("MANDATE_HELD", 0L);
        long impliedSettled = ledger.netByBucket().getOrDefault("MANDATE_SETTLED", 0L);
        if (row.availableMinor() != impliedAvailable
                || row.heldMinor() != impliedHeld
                || row.settledMinor() != impliedSettled) {
            violations.add(new Violation("I3", "mandate_balances " + row + " disagrees with SUM(ledger_postings): available "
                    + impliedAvailable + ", held " + impliedHeld + ", settled " + impliedSettled));
        }
        for (String bucket : ledger.netByBucket().keySet()) {
            if (!Set.of("MANDATE_AVAILABLE", "MANDATE_HELD", "MANDATE_SETTLED").contains(bucket)) {
                violations.add(new Violation("I3", "posting routed to unknown bucket " + bucket));
            }
        }
        for (String unbalanced : ledger.unbalancedTransactions()) {
            violations.add(new Violation("I3", "unbalanced ledger transaction " + unbalanced));
        }

        // The buckets must agree with the intents (LedgerMatchesIntents in the TLA+ model): held is
        // exactly the open authorisations, settled exactly the captured amounts.
        long openAuthorised = 0;
        long captured = 0;
        for (LedgerRow intentRow : ledger.intents()) {
            IntentView intent = intentRow.view();
            if (!intent.status().isTerminal()) {
                openAuthorised += intent.authorizedAmountMinor();
            }
            if (intent.status() == IntentStatus.CAPTURED) {
                captured += intent.capturedAmountMinor();
            }
            Set<String> transitions = ledger.transitionsByIntent().getOrDefault(intent.intentId(), Set.of());
            Set<String> expected = switch (intent.status()) {
                case RESERVED, CONFIRMING, AUTHORIZED -> Set.of("RESERVE");
                case CAPTURED -> Set.of("RESERVE", "CAPTURE");
                case VOIDED, FAILED -> Set.of("RESERVE", "VOID");
            };
            if (!transitions.equals(expected)) {
                violations.add(new Violation("I3", intent.status() + " intent " + describe(intent)
                        + " has ledger transactions " + transitions + ", expected " + expected));
            }
        }
        for (UUID withTransactions : ledger.transitionsByIntent().keySet()) {
            if (ledger.intents().stream().noneMatch(r -> r.view().intentId().equals(withTransactions))) {
                violations.add(new Violation("I3", "ledger transactions exist for unknown intent " + withTransactions));
            }
        }
        if (row.heldMinor() != openAuthorised) {
            violations.add(new Violation("I3", "held is " + row.heldMinor()
                    + " but the authorised amounts of non-terminal intents sum to " + openAuthorised));
        }
        if (row.settledMinor() != captured) {
            violations.add(new Violation("I3", "settled is " + row.settledMinor()
                    + " but the captured amounts sum to " + captured));
        }
    }

    private void checkEngineViewAgainstLedger(LedgerSnapshot ledger, List<Violation> violations) {
        if (ledger.balances() == null) {
            return;
        }
        MandateBalances engineBalances = engine.balances(mandateId);
        if (!ledger.balances().equals(engineBalances)) {
            violations.add(new Violation("VIEW", "engine.balances() = " + engineBalances + " but the ledger row is "
                    + ledger.balances()));
        }
        List<IntentView> engineIntents = engine.intentsOf(mandateId);
        Map<UUID, IntentView> engineById = new HashMap<>();
        for (IntentView intent : engineIntents) {
            engineById.put(intent.intentId(), intent);
        }
        Map<UUID, Timestamp> createdAt = new HashMap<>();
        for (LedgerRow row : ledger.intents()) {
            createdAt.put(row.view().intentId(), row.createdAt());
            IntentView fromEngine = engineById.remove(row.view().intentId());
            if (!row.view().equals(fromEngine)) {
                violations.add(new Violation("VIEW", "engine.intentsOf() has " + fromEngine + " where the ledger has "
                        + row.view()));
            }
            Optional<IntentView> byId = engine.findIntent(row.view().intentId());
            if (byId.isEmpty() || !row.view().equals(byId.get())) {
                violations.add(new Violation("VIEW", "engine.findIntent(id) = " + byId + " where the ledger has "
                        + row.view()));
            }
            Optional<IntentView> byKey = engine.findIntent(row.view().agentId(), row.view().idempotencyKey());
            if (byKey.isEmpty() || !row.view().equals(byKey.get())) {
                violations.add(new Violation("VIEW", "engine.findIntent(agent, key) = " + byKey
                        + " where the ledger has " + row.view()));
            }
        }
        for (IntentView extra : engineById.values()) {
            violations.add(new Violation("VIEW", "engine.intentsOf() lists " + extra + " which is not in the ledger"));
        }
        Timestamp previous = null;
        for (IntentView intent : engineIntents) {
            Timestamp created = createdAt.get(intent.intentId());
            if (created != null && previous != null && created.before(previous)) {
                violations.add(new Violation("VIEW", "engine.intentsOf() is not oldest first at " + describe(intent)));
            }
            if (created != null) {
                previous = created;
            }
        }
    }

    private LedgerSnapshot readLedger() {
        try (Connection connection = truth.getConnection()) {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setReadOnly(true);
            try {
                return readLedger(connection);
            } finally {
                connection.rollback();
                connection.setReadOnly(false);
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Cannot read the ledger of mandate " + mandateId, e);
        }
    }

    private LedgerSnapshot readLedger(Connection connection) throws SQLException {
        boolean mandateExists = false;
        String mandateStatus = null;
        long mandateTotal = 0;
        long mandateCap = 0;
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT status::text, total_budget_minor, max_per_tx_minor FROM spend_mandates WHERE mandate_id = ?")) {
            statement.setObject(1, mandateId);
            try (ResultSet row = statement.executeQuery()) {
                if (row.next()) {
                    mandateExists = true;
                    mandateStatus = row.getString(1);
                    mandateTotal = row.getLong(2);
                    mandateCap = row.getLong(3);
                }
            }
        }

        MandateBalances balances = null;
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT total_budget_minor, available_minor, held_minor, settled_minor"
                        + " FROM mandate_balances WHERE mandate_id = ?")) {
            statement.setObject(1, mandateId);
            try (ResultSet row = statement.executeQuery()) {
                if (row.next()) {
                    balances = new MandateBalances(
                            mandateId, row.getLong(1), row.getLong(2), row.getLong(3), row.getLong(4));
                }
            }
        }

        List<LedgerRow> intents = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT intent_id, agent_id, idempotency_key, request_hash, merchant_id, currency,"
                        + " authorized_amount_minor, captured_amount_minor, status::text, stripe_payment_intent,"
                        + " created_at"
                        + " FROM payment_intents WHERE mandate_id = ? ORDER BY created_at, intent_id")) {
            statement.setObject(1, mandateId);
            try (ResultSet row = statement.executeQuery()) {
                while (row.next()) {
                    IntentView view = new IntentView(
                            row.getObject(1, UUID.class),
                            mandateId,
                            row.getString(2),
                            row.getString(3),
                            row.getString(4),
                            row.getString(5),
                            row.getString(6),
                            row.getLong(7),
                            row.getLong(8),
                            IntentStatus.valueOf(row.getString(9)),
                            row.getString(10));
                    intents.add(new LedgerRow(view, row.getTimestamp(11)));
                }
            }
        }

        Map<String, Long> netByBucket = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT a.bucket::text,"
                        + " COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END), 0)"
                        + " FROM ledger_postings p JOIN ledger_accounts a ON a.account_id = p.account_id"
                        + " WHERE p.mandate_id = ? GROUP BY a.bucket")) {
            statement.setObject(1, mandateId);
            try (ResultSet row = statement.executeQuery()) {
                while (row.next()) {
                    netByBucket.put(row.getString(1), row.getLong(2));
                }
            }
        }

        List<String> unbalanced = new ArrayList<>();
        Map<UUID, Set<String>> transitionsByIntent = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT t.tx_id, t.intent_id, t.transition_type,"
                        + " COALESCE(SUM(CASE WHEN p.direction = 'DEBIT' THEN p.amount_minor ELSE 0 END), 0),"
                        + " COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0),"
                        + " COUNT(p.posting_id)"
                        + " FROM ledger_transactions t LEFT JOIN ledger_postings p ON p.tx_id = t.tx_id"
                        + " WHERE t.mandate_id = ? GROUP BY t.tx_id, t.intent_id, t.transition_type")) {
            statement.setObject(1, mandateId);
            try (ResultSet row = statement.executeQuery()) {
                while (row.next()) {
                    UUID intentId = row.getObject(2, UUID.class);
                    String transition = row.getString(3);
                    long debits = row.getLong(4);
                    long credits = row.getLong(5);
                    long postings = row.getLong(6);
                    if (!transitionsByIntent.computeIfAbsent(intentId, k -> new HashSet<>()).add(transition)) {
                        unbalanced.add(row.getObject(1) + " (second " + transition + " for intent " + intentId + ")");
                    }
                    if (debits != credits || debits == 0 || postings < 2) {
                        unbalanced.add(row.getObject(1) + " (" + transition + " for intent " + intentId + ": debits "
                                + debits + ", credits " + credits + ", postings " + postings + ")");
                    }
                }
            }
        }

        return new LedgerSnapshot(
                mandateExists, mandateStatus, mandateTotal, mandateCap, balances, intents, netByBucket, unbalanced,
                transitionsByIntent);
    }

    private List<IntentView> truthIntents() {
        if (ledgerBacked()) {
            return readLedger().intents().stream().map(LedgerRow::view).toList();
        }
        return engine.intentsOf(mandateId);
    }

    private static String describe(IntentView intent) {
        return intent.agentId() + "/" + intent.idempotencyKey() + " (" + intent.intentId() + ")";
    }
}
