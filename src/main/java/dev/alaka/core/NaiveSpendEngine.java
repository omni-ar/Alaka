package dev.alaka.core;

import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.nidhi.NidhiLedger;
import dev.alaka.nidhi.SignedMandateTerms;
import dev.alaka.nidhi.TransactionRunner;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * {@code --mode=naive}: the anti-pattern baseline, built to fail visibly. DO NOT COPY.
 *
 * <p>Each request, in autocommit {@code READ COMMITTED} with no lock held at any point:
 * <ol>
 *   <li>looks up the idempotency key, and replays a stored result if it finds one;
 *   <li>reads the mandate and checks status, agent, currency, allowlist and per-tx cap in
 *       application code;
 *   <li>sums what the mandate has spent so far and checks the budget in application code;
 *   <li>charges the rail (create, then confirm);
 *   <li>only then appends the outcome to {@code naive_spend_log}, a table with no constraints.
 * </ol>
 * Every concurrent request that passes step 3 before any of them reaches step 5 is charged, so
 * the rail total exceeds the budget (I1), and concurrent duplicates all miss in step 1 and are
 * each charged (I2). On a rail error it records {@code FAILED} without asking the rail what
 * happened, which is the blind void of Trap 1 (I6). Mandate terms come from the real
 * {@code spend_mandates}; the guarded ledger tables are never written.
 */
final class NaiveSpendEngine implements SpendEngine {

    private static final String COLUMNS =
            "intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency,"
                    + " authorized_amount_minor, captured_amount_minor, status, rail_payment_intent";

    private final TransactionRunner tx;
    private final NidhiLedger ledger = new NidhiLedger();
    private final PaymentRailPort rail;

    NaiveSpendEngine(TransactionRunner tx, PaymentRailPort rail) {
        this.tx = Objects.requireNonNull(tx, "tx");
        this.rail = Objects.requireNonNull(rail, "rail");
    }

    @Override
    public RuntimeMode mode() {
        return RuntimeMode.NAIVE;
    }

    @Override
    public UUID createMandate(NewMandate terms) {
        return tx.inTransaction(c -> ledger.insertMandate(c, terms));
    }

    @Override
    public UUID createMandate(SignedMandateTerms terms) {
        tx.inTransaction(c -> {
            ledger.insertSignedMandate(c, terms);
            return null;
        });
        return terms.mandateId();
    }

    @Override
    public RailEventOutcome applyRailEvent(String providerEventId, String eventType, RailPaymentIntent paymentIntent) {
        throw unsupported("applyRailEvent");
    }

    @Override
    public void revokeMandate(UUID mandateId, String reason) {
        String before = tx.inTransaction(c -> ledger.revokeMandate(c, mandateId, reason))
                .orElseThrow(() -> new IllegalArgumentException("Unknown mandate " + mandateId));
        if (!before.equals("ACTIVE") && !before.equals("SUSPENDED")) {
            throw new NidhiException.IllegalStateTransition("Mandate " + mandateId + " is already " + before, null);
        }
    }

    @Override
    public SpendResult execute(SpendRequest request) {
        String requestHash = request.requestHash();

        // 1. Idempotency, checked in application code: racing duplicates all miss here.
        Optional<IntentView> previous = findIntent(request.agentId(), request.idempotencyKey());
        if (previous.isPresent()) {
            if (!previous.get().requestHash().equals(requestHash)) {
                throw new IdempotencyException.PayloadMismatch(
                        "Idempotency key '" + request.idempotencyKey() + "' reused with a different payload");
            }
            return new SpendResult(previous.get(), true);
        }

        // 2. Mandate terms, checked in application code.
        NidhiLedger.MandateRow mandate = tx.read(c -> ledger.findMandate(c, request.mandateId(), false))
                .orElseThrow(() -> new IllegalArgumentException("Unknown mandate " + request.mandateId()));
        if (!mandate.status().equals("ACTIVE") || !mandate.withinWindow()
                || !mandate.agentId().equals(request.agentId())) {
            throw new NidhiException.MandateInactive("naive check: mandate not usable by this agent now", null);
        }
        if (!mandate.currency().equals(request.currency())) {
            throw new NidhiException.CurrencyMismatch("naive check: currency mismatch", null);
        }
        if (!mandate.allowedMerchants().contains(request.merchantId())) {
            throw new NidhiException.MerchantNotAllowed("naive check: merchant not allowed", null);
        }
        if (request.amountMinor() > mandate.maxPerTxMinor()) {
            throw new NidhiException.BudgetExceeded("naive check: per-tx cap exceeded", null);
        }

        // 3. Budget, checked in application code against a read that is stale the moment it returns.
        long spent = tx.read(c -> spentSoFar(c, request.mandateId()));
        if (spent + request.amountMinor() > mandate.totalBudgetMinor()) {
            throw new NidhiException.BudgetExceeded(
                    "naive check: spent " + spent + " + " + request.amountMinor() + " > " + mandate.totalBudgetMinor(),
                    null);
        }

        // 4. Charge the rail inside the request flow.
        UUID intentId = UUID.randomUUID();
        String piId = null;
        IntentStatus status;
        long captured = 0;
        try {
            RailPaymentIntent pi = rail.createUnconfirmed(
                    NidhiLedger.railCreateKey(intentId), intentId, request.merchantId(), request.currency(),
                    request.amountMinor());
            piId = pi.piId();
            RailPaymentIntent confirmed = rail.confirm(piId, NidhiLedger.railConfirmKey(intentId));
            if (confirmed.status() == RailPiStatus.SUCCEEDED) {
                status = IntentStatus.CAPTURED;
                captured = confirmed.chargedMinor();
            } else {
                status = IntentStatus.CONFIRMING;
            }
        } catch (RailException e) {
            // Blind failure: the confirm may still land and charge (Trap 1).
            status = IntentStatus.FAILED;
        }

        // 5. Record the outcome, after the fact.
        IntentView recorded = new IntentView(
                intentId, request.mandateId(), request.agentId(), request.idempotencyKey(), requestHash,
                request.merchantId(), request.currency(), request.amountMinor(), captured, status, piId);
        tx.read(c -> {
            insert(c, recorded);
            return null;
        });
        return new SpendResult(recorded, false);
    }

    @Override
    public SpendResult reserve(SpendRequest request) {
        throw unsupported("reserve");
    }

    @Override
    public IntentView createOnRail(UUID intentId) {
        throw unsupported("createOnRail");
    }

    @Override
    public RailPaymentIntent confirmOnRail(UUID intentId) {
        throw unsupported("confirmOnRail");
    }

    @Override
    public IntentView capture(UUID intentId) {
        throw unsupported("capture");
    }

    @Override
    public IntentView recoverOrVoid(UUID intentId) {
        throw unsupported("recoverOrVoid");
    }

    @Override
    public Optional<IntentView> findIntent(UUID intentId) {
        return tx.read(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT " + COLUMNS + " FROM naive_spend_log WHERE intent_id = ?")) {
                ps.setObject(1, intentId);
                return first(ps);
            }
        });
    }

    @Override
    public Optional<IntentView> findIntent(String agentId, String idempotencyKey) {
        return tx.read(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT " + COLUMNS + " FROM naive_spend_log WHERE agent_id = ? AND idempotency_key = ?"
                            + " ORDER BY created_at LIMIT 1")) {
                ps.setString(1, agentId);
                ps.setString(2, idempotencyKey);
                return first(ps);
            }
        });
    }

    @Override
    public List<IntentView> intentsOf(UUID mandateId) {
        return tx.read(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT " + COLUMNS + " FROM naive_spend_log WHERE mandate_id = ? ORDER BY created_at, intent_id")) {
                ps.setObject(1, mandateId);
                List<IntentView> intents = new ArrayList<>();
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        intents.add(view(rs));
                    }
                }
                return intents;
            }
        });
    }

    /**
     * What the naive bookkeeping believes: nothing is ever held, settled is what it recorded as
     * captured, available is the remainder (and goes negative once it has overspent).
     */
    @Override
    public MandateBalances balances(UUID mandateId) {
        return tx.read(c -> {
            long total = ledger.findMandate(c, mandateId, false)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown mandate " + mandateId))
                    .totalBudgetMinor();
            long settled = spentSoFar(c, mandateId);
            return new MandateBalances(mandateId, total, total - settled, 0, settled);
        });
    }

    @Override
    public EngineMetrics metrics() {
        return new EngineMetrics(0, 0, 0);
    }

    private static long spentSoFar(Connection c, UUID mandateId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT COALESCE(SUM(captured_amount_minor), 0) FROM naive_spend_log WHERE mandate_id = ?")) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private static void insert(Connection c, IntentView intent) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO naive_spend_log (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setObject(1, intent.intentId());
            ps.setObject(2, intent.mandateId());
            ps.setString(3, intent.agentId());
            ps.setString(4, intent.idempotencyKey());
            ps.setString(5, intent.requestHash());
            ps.setString(6, intent.merchantId());
            ps.setString(7, intent.currency());
            ps.setLong(8, intent.authorizedAmountMinor());
            ps.setLong(9, intent.capturedAmountMinor());
            ps.setString(10, intent.status().name());
            ps.setString(11, intent.railPaymentIntentId());
            ps.executeUpdate();
        }
    }

    private static Optional<IntentView> first(PreparedStatement ps) throws SQLException {
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next() ? Optional.of(view(rs)) : Optional.empty();
        }
    }

    private static IntentView view(ResultSet rs) throws SQLException {
        return new IntentView(
                rs.getObject("intent_id", UUID.class),
                rs.getObject("mandate_id", UUID.class),
                rs.getString("agent_id"),
                rs.getString("idempotency_key"),
                rs.getString("request_hash"),
                rs.getString("merchant_id"),
                rs.getString("currency"),
                rs.getLong("authorized_amount_minor"),
                rs.getLong("captured_amount_minor"),
                IntentStatus.valueOf(rs.getString("status")),
                rs.getString("rail_payment_intent"));
    }

    private static UnsupportedOperationException unsupported(String phase) {
        return new UnsupportedOperationException(
                "--mode=naive has no phase protocol; " + phase + " is implemented by the hardened modes only");
    }
}
