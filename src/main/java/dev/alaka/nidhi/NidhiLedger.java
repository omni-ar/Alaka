package dev.alaka.nidhi;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SQL access to the Nidhi ledger, as the least-privilege role {@code alaka_app}.
 *
 * <p>Every method runs on a connection the caller supplies and never opens, commits or rolls back
 * a transaction itself. The three methods that change a reservation's money,
 * {@link #insertReservation}, {@link #recordCapture} and {@link #recordVoid}, each write the intent
 * row together with its ledger transaction and balanced postings, because the schema only accepts
 * them together at {@code COMMIT} ([NIDHI-D9]).
 *
 * <p>Lock order, used by every hardened transaction that takes explicit locks:
 * {@code spend_mandates} ({@code FOR SHARE}), then {@code mandate_balances} ({@code FOR UPDATE}),
 * then {@code payment_intents} ({@code FOR UPDATE}).
 */
public final class NidhiLedger {

    /** The three buckets of a mandate, mirroring the {@code account_bucket} enum. */
    public enum Bucket {
        MANDATE_AVAILABLE,
        MANDATE_HELD,
        MANDATE_SETTLED
    }

    /**
     * Mandate fields the engine needs.
     *
     * @param mandateId mandate id
     * @param agentId agent the mandate was issued to
     * @param currency ISO 4217 currency code
     * @param status mandate status
     * @param totalBudgetMinor total budget
     * @param maxPerTxMinor per-transaction cap
     * @param allowedMerchants merchant allowlist
     * @param withinWindow whether the database's {@code NOW()} lies inside the validity window
     */
    public record MandateRow(
            UUID mandateId,
            String agentId,
            String currency,
            String status,
            long totalBudgetMinor,
            long maxPerTxMinor,
            List<String> allowedMerchants,
            boolean withinWindow) {
    }

    private static final String INTENT_COLUMNS =
            "intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency,"
                    + " authorized_amount_minor, captured_amount_minor, status::text AS status, stripe_payment_intent";

    private final Map<UUID, Map<Bucket, UUID>> accountsByMandate = new ConcurrentHashMap<>();

    /**
     * Inserts an {@code ACTIVE} mandate valid from {@code NOW()} for {@code validFor}; the schema
     * creates its three accounts and its full available balance.
     *
     * @param c connection
     * @param terms mandate terms
     * @return the new mandate id
     * @throws SQLException on any database error
     */
    public UUID insertMandate(Connection c, NewMandate terms) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO spend_mandates (agent_id, currency, total_budget_minor, max_per_tx_minor,"
                        + " allowed_merchants, expires_at, token_kid)"
                        + " VALUES (?, ?, ?, ?, ?, NOW() + ? * INTERVAL '1 millisecond', ?)"
                        + " RETURNING mandate_id")) {
            Array merchants = c.createArrayOf("text", terms.allowedMerchants().toArray());
            ps.setString(1, terms.agentId());
            ps.setString(2, terms.currency());
            ps.setLong(3, terms.totalBudgetMinor());
            ps.setLong(4, terms.maxPerTxMinor());
            ps.setArray(5, merchants);
            ps.setLong(6, terms.validFor().toMillis());
            ps.setString(7, terms.tokenKid());
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getObject(1, UUID.class);
            }
        }
    }

    /**
     * Inserts an {@code ACTIVE} mandate with the id and validity window fixed by a signed token.
     *
     * @param c connection
     * @param terms signed mandate terms
     * @throws SQLException on any database error, including {@code 23505} if the id is taken
     */
    public void insertSignedMandate(Connection c, SignedMandateTerms terms) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor,"
                        + " allowed_merchants, not_before, expires_at, token_kid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setObject(1, terms.mandateId());
            ps.setString(2, terms.agentId());
            ps.setString(3, terms.currency());
            ps.setLong(4, terms.totalBudgetMinor());
            ps.setLong(5, terms.maxPerTxMinor());
            ps.setArray(6, c.createArrayOf("text", terms.allowedMerchants().toArray()));
            ps.setObject(7, java.time.OffsetDateTime.ofInstant(terms.notBefore(), java.time.ZoneOffset.UTC));
            ps.setObject(8, java.time.OffsetDateTime.ofInstant(terms.expiresAt(), java.time.ZoneOffset.UTC));
            ps.setString(9, terms.tokenKid());
            ps.executeUpdate();
        }
    }

    /**
     * Reads a mandate, optionally taking {@code FOR SHARE} (blocks revocation until commit).
     *
     * @param c connection
     * @param mandateId mandate id
     * @param forShare whether to lock the row {@code FOR SHARE}
     * @return the mandate, or empty if it does not exist
     * @throws SQLException on any database error
     */
    public Optional<MandateRow> findMandate(Connection c, UUID mandateId, boolean forShare) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT mandate_id, agent_id, currency, status::text, total_budget_minor, max_per_tx_minor,"
                        + " allowed_merchants, (NOW() >= not_before AND NOW() < expires_at)"
                        + " FROM spend_mandates WHERE mandate_id = ?" + (forShare ? " FOR SHARE" : ""))) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                String[] merchants = (String[]) rs.getArray(7).getArray();
                return Optional.of(new MandateRow(
                        rs.getObject(1, UUID.class),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getString(4),
                        rs.getLong(5),
                        rs.getLong(6),
                        List.of(merchants),
                        rs.getBoolean(8)));
            }
        }
    }

    /**
     * Revokes a mandate if it is not already in a terminal state.
     *
     * @param c connection
     * @param mandateId mandate id
     * @param reason revocation reason
     * @return the status the mandate had before, or empty if it does not exist
     * @throws SQLException on any database error
     */
    public Optional<String> revokeMandate(Connection c, UUID mandateId, String reason) throws SQLException {
        String before;
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT status::text FROM spend_mandates WHERE mandate_id = ? FOR UPDATE")) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                before = rs.getString(1);
            }
        }
        if (before.equals("ACTIVE") || before.equals("SUSPENDED")) {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE spend_mandates SET status = 'REVOKED', revoked_at = NOW(), revocation_reason = ?"
                            + " WHERE mandate_id = ?")) {
                ps.setString(1, reason);
                ps.setObject(2, mandateId);
                ps.executeUpdate();
            }
        }
        return Optional.of(before);
    }

    /**
     * Locks a mandate's balance row {@code FOR UPDATE}, serialising every money movement on it.
     *
     * @param c connection
     * @param mandateId mandate id
     * @throws SQLException on any database error
     */
    public void lockBalances(Connection c, UUID mandateId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT version FROM mandate_balances WHERE mandate_id = ? FOR UPDATE")) {
            ps.setObject(1, mandateId);
            ps.executeQuery().close();
        }
    }

    /**
     * Reads a mandate's balance row.
     *
     * @param c connection
     * @param mandateId mandate id
     * @return the balances, or empty if the mandate does not exist
     * @throws SQLException on any database error
     */
    public Optional<MandateBalances> balances(Connection c, UUID mandateId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT total_budget_minor, available_minor, held_minor, settled_minor"
                        + " FROM mandate_balances WHERE mandate_id = ?")) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new MandateBalances(
                        mandateId, rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4)));
            }
        }
    }

    /**
     * Reads an intent by id.
     *
     * @param c connection
     * @param intentId intent id
     * @param forUpdate whether to lock the row {@code FOR UPDATE}
     * @return the intent, or empty if it does not exist
     * @throws SQLException on any database error
     */
    public Optional<IntentView> findIntent(Connection c, UUID intentId, boolean forUpdate) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT " + INTENT_COLUMNS + " FROM payment_intents WHERE intent_id = ?"
                        + (forUpdate ? " FOR UPDATE" : ""))) {
            ps.setObject(1, intentId);
            return single(ps);
        }
    }

    /**
     * Reads an intent by its idempotency identity.
     *
     * @param c connection
     * @param agentId agent id
     * @param idempotencyKey idempotency key
     * @return the intent, or empty if the key is unused
     * @throws SQLException on any database error
     */
    public Optional<IntentView> findIntent(Connection c, String agentId, String idempotencyKey) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT " + INTENT_COLUMNS + " FROM payment_intents WHERE agent_id = ? AND idempotency_key = ?")) {
            ps.setString(1, agentId);
            ps.setString(2, idempotencyKey);
            return single(ps);
        }
    }

    /**
     * Lists a mandate's intents, oldest first.
     *
     * @param c connection
     * @param mandateId mandate id
     * @return the intents
     * @throws SQLException on any database error
     */
    public List<IntentView> intentsOf(Connection c, UUID mandateId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT " + INTENT_COLUMNS + " FROM payment_intents WHERE mandate_id = ?"
                        + " ORDER BY created_at, intent_id")) {
            ps.setObject(1, mandateId);
            List<IntentView> intents = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    intents.add(intent(rs));
                }
            }
            return intents;
        }
    }

    /**
     * Phase 1 write: inserts the intent in {@code RESERVED} with its {@code RESERVE} ledger
     * transaction, {@code DEBIT MANDATE_AVAILABLE} and {@code CREDIT MANDATE_HELD}. The mandate,
     * time-window, agent, currency, allowlist and per-tx checks fire on the intent insert; the
     * overdraw check ({@code SG003}) fires at {@code COMMIT}.
     *
     * @param c connection
     * @param intent the intent to insert; its status and captured amount are ignored
     * @throws SQLException on any database error, including {@code 23505} for a used key
     */
    public void insertReservation(Connection c, IntentView intent) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash,"
                        + " merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)"
                        + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setObject(1, intent.intentId());
            ps.setObject(2, intent.mandateId());
            ps.setString(3, intent.agentId());
            ps.setString(4, intent.idempotencyKey());
            ps.setString(5, intent.requestHash());
            ps.setString(6, intent.merchantId());
            ps.setString(7, intent.currency());
            ps.setLong(8, intent.authorizedAmountMinor());
            ps.setString(9, railCreateKey(intent.intentId()));
            ps.setString(10, railConfirmKey(intent.intentId()));
            ps.executeUpdate();
        }
        Map<Bucket, UUID> accounts = accounts(c, intent.mandateId());
        UUID tx = insertTransaction(c, intent, "RESERVE");
        long amount = intent.authorizedAmountMinor();
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_AVAILABLE), "DEBIT", amount);
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_HELD), "CREDIT", amount);
    }

    /**
     * Phase 2A write: records the rail payment intent id and advances {@code RESERVED -> CONFIRMING}.
     *
     * @param c connection
     * @param intentId intent id, locked by the caller
     * @param railPaymentIntentId the rail's {@code pi_...} id
     * @throws SQLException on any database error
     */
    public void markConfirming(Connection c, UUID intentId, String railPaymentIntentId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE payment_intents SET stripe_payment_intent = ?, status = 'CONFIRMING' WHERE intent_id = ?")) {
            ps.setString(1, railPaymentIntentId);
            ps.setObject(2, intentId);
            ps.executeUpdate();
        }
    }

    /**
     * Phase 3A write: intent to {@code CAPTURED} with {@code captured_amount_minor = charged}, plus
     * the {@code CAPTURE} ledger transaction: {@code DEBIT MANDATE_HELD} authorised,
     * {@code CREDIT MANDATE_SETTLED} charged and, if charged is less than authorised,
     * {@code CREDIT MANDATE_AVAILABLE} the remainder.
     *
     * @param c connection
     * @param intent the intent, locked by the caller and in a non-terminal state
     * @param chargedMinor amount the rail charged, between 1 and the authorised amount
     * @throws SQLException on any database error
     */
    public void recordCapture(Connection c, IntentView intent, long chargedMinor) throws SQLException {
        long authorized = intent.authorizedAmountMinor();
        if (chargedMinor <= 0 || chargedMinor > authorized) {
            throw new IllegalArgumentException(
                    "Charged amount " + chargedMinor + " outside 1.." + authorized + " for intent " + intent.intentId());
        }
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = ? WHERE intent_id = ?")) {
            ps.setLong(1, chargedMinor);
            ps.setObject(2, intent.intentId());
            ps.executeUpdate();
        }
        Map<Bucket, UUID> accounts = accounts(c, intent.mandateId());
        UUID tx = insertTransaction(c, intent, "CAPTURE");
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_HELD), "DEBIT", authorized);
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_SETTLED), "CREDIT", chargedMinor);
        if (chargedMinor < authorized) {
            insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_AVAILABLE), "CREDIT", authorized - chargedMinor);
        }
        completeRecovery(c, intent.intentId());
    }

    /**
     * Phase 3B write: intent to {@code VOIDED} plus the {@code VOID} ledger transaction:
     * {@code DEBIT MANDATE_HELD}, {@code CREDIT MANDATE_AVAILABLE}, both the authorised amount.
     *
     * @param c connection
     * @param intent the intent, locked by the caller and in a non-terminal state
     * @throws SQLException on any database error
     */
    public void recordVoid(Connection c, IntentView intent) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE payment_intents SET status = 'VOIDED' WHERE intent_id = ?")) {
            ps.setObject(1, intent.intentId());
            ps.executeUpdate();
        }
        Map<Bucket, UUID> accounts = accounts(c, intent.mandateId());
        UUID tx = insertTransaction(c, intent, "VOID");
        long amount = intent.authorizedAmountMinor();
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_HELD), "DEBIT", amount);
        insertPosting(c, tx, intent, accounts.get(Bucket.MANDATE_AVAILABLE), "CREDIT", amount);
        completeRecovery(c, intent.intentId());
    }

    /**
     * Finds the intent that recorded a rail payment intent id.
     *
     * @param c connection
     * @param railPaymentIntentId the rail's {@code pi_...} id
     * @return the intent, or empty if no intent recorded that id
     * @throws SQLException on any database error
     */
    public Optional<IntentView> findIntentByRailId(Connection c, String railPaymentIntentId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT " + INTENT_COLUMNS + " FROM payment_intents WHERE stripe_payment_intent = ?")) {
            ps.setString(1, railPaymentIntentId);
            return single(ps);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Outbox: one recovery task per intent, completed in the transaction that settles it.

    /**
     * Enqueues the recovery task of a new intent, due once the intent has had {@code graceMillis}
     * to finish normally. Call in the Phase 1 transaction.
     *
     * @param c connection
     * @param intentId intent id
     * @param graceMillis how long a healthy request may take before recovery considers it stuck
     * @throws SQLException on any database error
     */
    public void enqueueRecovery(Connection c, UUID intentId, long graceMillis) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO outbox_tasks (intent_id, next_attempt_at) VALUES (?, NOW() + ? * INTERVAL '1 millisecond')")) {
            ps.setObject(1, intentId);
            ps.setLong(2, graceMillis);
            ps.executeUpdate();
        }
    }

    /**
     * Marks an intent's recovery task {@code COMPLETED}. Call in the transaction that moves the
     * intent to a terminal state, so a settled intent never has a live task.
     *
     * @param c connection
     * @param intentId intent id
     * @throws SQLException on any database error
     */
    public void completeRecovery(Connection c, UUID intentId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE outbox_tasks SET status = 'COMPLETED', locked_until = NULL, updated_at = NOW()"
                        + " WHERE intent_id = ? AND status <> 'COMPLETED'")) {
            ps.setObject(1, intentId);
            ps.executeUpdate();
        }
    }

    /**
     * Records a provider event as processed. Call in the transaction that applies the event, so
     * the effect and the dedup marker commit or roll back together.
     *
     * @param c connection
     * @param providerEventId the provider's event id ({@code evt_...})
     * @param intentId intent the event concerns, or {@code null}
     * @param eventType event type
     * @return {@code false} if the event had already been recorded (a replay)
     * @throws SQLException on any database error
     */
    public boolean recordWebhook(Connection c, String providerEventId, UUID intentId, String eventType)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO processed_webhooks (provider_event_id, intent_id, event_type) VALUES (?, ?, ?)"
                        + " ON CONFLICT (provider_event_id) DO NOTHING")) {
            ps.setString(1, providerEventId);
            ps.setObject(2, intentId);
            ps.setString(3, eventType);
            return ps.executeUpdate() == 1;
        }
    }

    /**
     * Returns the rail idempotency key for Step 2A.
     *
     * @param intentId intent id
     * @return {@code "create_" + intentId}
     */
    public static String railCreateKey(UUID intentId) {
        return "create_" + intentId;
    }

    /**
     * Returns the rail idempotency key for Step 2B.
     *
     * @param intentId intent id
     * @return {@code "confirm_" + intentId}
     */
    public static String railConfirmKey(UUID intentId) {
        return "confirm_" + intentId;
    }

    private Map<Bucket, UUID> accounts(Connection c, UUID mandateId) throws SQLException {
        Map<Bucket, UUID> cached = accountsByMandate.get(mandateId);
        if (cached != null) {
            return cached;
        }
        Map<Bucket, UUID> accounts = new EnumMap<>(Bucket.class);
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT bucket::text, account_id FROM ledger_accounts WHERE mandate_id = ?")) {
            ps.setObject(1, mandateId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    accounts.put(Bucket.valueOf(rs.getString(1)), rs.getObject(2, UUID.class));
                }
            }
        }
        if (accounts.size() != Bucket.values().length) {
            throw new IllegalStateException("Mandate " + mandateId + " has " + accounts.size() + " ledger accounts");
        }
        // Accounts are immutable rows, so caching them for the life of the process is safe.
        accountsByMandate.put(mandateId, Map.copyOf(accounts));
        return accounts;
    }

    private static UUID insertTransaction(Connection c, IntentView intent, String transitionType) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO ledger_transactions (intent_id, mandate_id, currency, transition_type)"
                        + " VALUES (?, ?, ?, ?) RETURNING tx_id")) {
            ps.setObject(1, intent.intentId());
            ps.setObject(2, intent.mandateId());
            ps.setString(3, intent.currency());
            ps.setString(4, transitionType);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getObject(1, UUID.class);
            }
        }
    }

    private static void insertPosting(
            Connection c, UUID tx, IntentView intent, UUID accountId, String direction, long amount)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)"
                        + " VALUES (?, ?, ?, ?, ?::entry_direction, ?)")) {
            ps.setObject(1, tx);
            ps.setObject(2, intent.mandateId());
            ps.setObject(3, accountId);
            ps.setString(4, intent.currency());
            ps.setString(5, direction);
            ps.setLong(6, amount);
            ps.executeUpdate();
        }
    }

    private static Optional<IntentView> single(PreparedStatement ps) throws SQLException {
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next() ? Optional.of(intent(rs)) : Optional.empty();
        }
    }

    private static IntentView intent(ResultSet rs) throws SQLException {
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
                rs.getString("stripe_payment_intent"));
    }
}
