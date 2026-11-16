package dev.alaka.yaksha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.core.EngineOptions;
import dev.alaka.core.RailEventOutcome.Disposition;
import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendEngines;
import dev.alaka.core.SpendRequest;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NewMandate;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.ConfirmBehavior.RailFault;
import dev.alaka.yaksha.WebhookRejectedException.Reason;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The hardened engine over Stripe's HTTP wire protocol (against {@link MockStripeServer}), Stripe
 * webhooks through {@link StripeWebhookHandler}, and crash recovery by {@link YakshaRecoverySweeper},
 * all against PostgreSQL 16.
 */
class StripeWireIntegrationTest {

    private static final String API_KEY = "sk_test_mock_key";
    private static final String WEBHOOK_SECRET = "whsec_mock_secret";
    private static final String MERCHANT = "merchant-a";
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    private static HikariDataSource dataSource;

    @BeforeAll
    static void startPool() {
        dataSource = NidhiPostgres.shared().newAppDataSource(10);
    }

    @AfterAll
    static void closePool() {
        dataSource.close();
    }

    private Fixture fixture;

    @AfterEach
    void stopMock() {
        if (fixture != null) {
            fixture.stripe.close();
        }
    }

    private final class Fixture {
        final MockStripeServer stripe = new MockStripeServer(API_KEY);
        final StripeHttpPaymentRail rail;
        final SpendEngine engine;
        final StripeWebhookVerifier verifier =
                new StripeWebhookVerifier(WEBHOOK_SECRET, StripeWebhookVerifier.DEFAULT_TOLERANCE, Clock.systemUTC());
        final StripeWebhookHandler webhooks;
        final String agent = "agent-" + UUID.randomUUID();
        final UUID mandate;
        int keys;

        Fixture(RuntimeMode mode, Duration recoveryGrace, Duration requestTimeout) {
            rail = new StripeHttpPaymentRail(
                    new StripeHttpPaymentRail.Config(stripe.baseUrl(), API_KEY, requestTimeout, "pm_card_visa"), HTTP);
            engine = SpendEngines.create(mode, dataSource, rail, new EngineOptions(recoveryGrace));
            webhooks = new StripeWebhookHandler(verifier, engine);
            mandate = engine.createMandate(new NewMandate(
                    agent, "USD", 10_000, 6_000, List.of(MERCHANT), Duration.ofHours(1), "kid-wire"));
            fixture = this;
        }

        Fixture(RuntimeMode mode) {
            this(mode, Duration.ofSeconds(30), Duration.ofSeconds(5));
        }

        SpendRequest request(long amount) {
            return new SpendRequest(mandate, agent, "key-" + keys++, MERCHANT, "USD", amount);
        }

        void assertBalances(long available, long held, long settled) {
            assertThat(engine.balances(mandate)).isEqualTo(new MandateBalances(mandate, 10_000, available, held, settled));
        }

        IntentView intent(UUID id) {
            return engine.findIntent(id).orElseThrow();
        }

        String signedHeader(long t, byte[] body) {
            return "t=" + t + ",v1=" + HexFormat.of().formatHex(verifier.sign(t, body));
        }

        /** Delivers an event as Stripe would: signed now, over the exact bytes. */
        dev.alaka.core.RailEventOutcome deliver(String eventId, String type, RailPaymentIntent pi) {
            byte[] body = MockStripeServer.eventJson(eventId, type, pi);
            return webhooks.handle(signedHeader(Instant.now().getEpochSecond(), body), body);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Wire protocol

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void executeSpeaksStripeV1WireProtocol(RuntimeMode mode) {
        Fixture f = new Fixture(mode);
        IntentView captured = f.engine.execute(f.request(4_000)).intent();
        UUID id = captured.intentId();

        assertThat(captured.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(captured.railPaymentIntentId()).startsWith("pi_sim_");
        f.assertBalances(6_000, 0, 4_000);

        List<MockStripeServer.Recorded> calls = f.stripe.requests;
        assertThat(calls).extracting(MockStripeServer.Recorded::method, MockStripeServer.Recorded::path).containsExactly(
                org.assertj.core.groups.Tuple.tuple("POST", "/v1/payment_intents"),
                org.assertj.core.groups.Tuple.tuple("POST", "/v1/payment_intents/" + captured.railPaymentIntentId() + "/confirm"));
        MockStripeServer.Recorded create = calls.get(0);
        assertThat(create.headers())
                .containsEntry("authorization", "Bearer " + API_KEY)
                .containsEntry("idempotency-key", "create_" + id)
                .containsEntry("content-type", "application/x-www-form-urlencoded");
        assertThat(create.form())
                .containsEntry("amount", "4000")
                .containsEntry("currency", "usd")
                .containsEntry("confirm", "false")
                .containsEntry("metadata[intent_id]", id.toString())
                .containsEntry("metadata[merchant_id]", MERCHANT);
        MockStripeServer.Recorded confirm = calls.get(1);
        assertThat(confirm.headers()).containsEntry("idempotency-key", "confirm_" + id);
        assertThat(confirm.form()).containsEntry("payment_method", "pm_card_visa");
    }

    @Test
    void partialCaptureOverTheWireReleasesTheRemainder() {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC);
        UUID id = f.engine.reserve(f.request(4_000)).intent().intentId();
        f.stripe.state.setConfirmBehavior(id, ConfirmBehavior.succeedPartial(2_500));
        f.engine.createOnRail(id);
        f.engine.confirmOnRail(id);

        IntentView captured = f.engine.capture(id);
        assertThat(captured.capturedAmountMinor()).isEqualTo(2_500);
        f.assertBalances(7_500, 0, 2_500);
        assertThat(f.stripe.requestsTo(captured.railPaymentIntentId())).hasSize(1); // capture() read it with GET
    }

    @Test
    void stripeErrorsMapOntoThePortSemantics() {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC);
        assertThatThrownBy(() -> f.rail.retrieve("pi_does_not_exist"))
                .isInstanceOf(RailException.UnknownPaymentIntent.class);

        UUID charged = UUID.randomUUID();
        String pi = f.rail.createUnconfirmed("create_" + charged, charged, MERCHANT, "USD", 100).piId();
        f.rail.confirm(pi, "confirm_" + charged);
        assertThatThrownBy(() -> f.rail.cancel(pi)).isInstanceOfSatisfying(RailException.CancelRejected.class,
                e -> assertThat(e.statusAtRejection()).isEqualTo(RailPiStatus.SUCCEEDED));
        assertThat(f.rail.confirm(pi, "confirm_" + charged).status()).isEqualTo(RailPiStatus.SUCCEEDED);

        UUID canceled = UUID.randomUUID();
        String pi2 = f.rail.createUnconfirmed("create_" + canceled, canceled, MERCHANT, "USD", 100).piId();
        assertThat(f.rail.cancel(pi2).status()).isEqualTo(RailPiStatus.CANCELED);
        assertThatThrownBy(() -> f.rail.confirm(pi2, "confirm_" + canceled))
                .isInstanceOf(RailException.ConfirmRejected.class);

        UUID failing = UUID.randomUUID();
        String pi3 = f.rail.createUnconfirmed("create_" + failing, failing, MERCHANT, "USD", 100).piId();
        f.stripe.state.setConfirmBehavior(failing, ConfirmBehavior.succeedFull().withFault(RailFault.TIMEOUT_AFTER_APPLY));
        assertThatThrownBy(() -> f.rail.confirm(pi3, "confirm_" + failing)).isInstanceOf(RailException.Timeout.class);
        assertThat(f.rail.retrieve(pi3).status()).isEqualTo(RailPiStatus.SUCCEEDED);

        StripeHttpPaymentRail badKey = new StripeHttpPaymentRail(new StripeHttpPaymentRail.Config(
                f.stripe.baseUrl(), "sk_test_wrong", Duration.ofSeconds(2), null), HTTP);
        assertThatThrownBy(() -> badKey.retrieve(pi)).isInstanceOf(IllegalStateException.class).hasMessageContaining("401");
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void lostConfirmResponseIsRecoveredWithGetNotARepost(RuntimeMode mode) {
        Fixture f = new Fixture(mode, Duration.ofSeconds(30), Duration.ofMillis(300));
        f.stripe.delayConfirmResponses(Duration.ofSeconds(2));

        IntentView recovered = f.engine.execute(f.request(3_000)).intent();
        assertThat(recovered.status()).isEqualTo(IntentStatus.CAPTURED);
        f.assertBalances(7_000, 0, 3_000);
        String pi = recovered.railPaymentIntentId();
        assertThat(f.stripe.requestsTo(pi + "/confirm")).hasSize(1);
        assertThat(f.stripe.requestsTo(pi)).extracting(MockStripeServer.Recorded::method).containsExactly("GET");
        assertThat(f.stripe.state.totalChargedMinor()).isEqualTo(3_000);
    }

    // ------------------------------------------------------------------------------------------
    // Webhooks

    /** Reserve, create and confirm on the rail, but never capture: the HTTP response "was lost". */
    private static IntentView chargedButNotCaptured(Fixture f, long amount) {
        UUID id = f.engine.reserve(f.request(amount)).intent().intentId();
        f.engine.createOnRail(id);
        assertThat(f.engine.confirmOnRail(id).status()).isEqualTo(RailPiStatus.SUCCEEDED);
        return f.intent(id);
    }

    @Test
    void validWebhookCapturesAndItsReplayIsANoOp() throws SQLException {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC);
        IntentView intent = chargedButNotCaptured(f, 2_000);
        RailPaymentIntent pi = f.stripe.state.retrieve(intent.railPaymentIntentId());
        String eventId = "evt_" + UUID.randomUUID();

        var first = f.deliver(eventId, "payment_intent.succeeded", pi);
        assertThat(first.disposition()).isEqualTo(Disposition.APPLIED);
        assertThat(first.intent()).hasValueSatisfying(i -> assertThat(i.status()).isEqualTo(IntentStatus.CAPTURED));
        f.assertBalances(8_000, 0, 2_000);

        var replay = f.deliver(eventId, "payment_intent.succeeded", pi);
        assertThat(replay.disposition()).isEqualTo(Disposition.DUPLICATE);
        f.assertBalances(8_000, 0, 2_000);
        assertThat(count("SELECT count(*) FROM processed_webhooks WHERE provider_event_id = ?", eventId)).isEqualTo(1);
        assertThat(count("SELECT count(*) FROM ledger_transactions WHERE intent_id = ? AND transition_type = 'CAPTURE'",
                intent.intentId())).isEqualTo(1);
        assertThat(f.engine.capture(intent.intentId()).status()).isEqualTo(IntentStatus.CAPTURED);
    }

    @Test
    void tamperedOrStaleWebhooksAreRejectedBeforeTheLedger() throws SQLException {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC);
        IntentView intent = chargedButNotCaptured(f, 2_000);
        RailPaymentIntent pi = f.stripe.state.retrieve(intent.railPaymentIntentId());
        String eventId = "evt_" + UUID.randomUUID();
        byte[] body = MockStripeServer.eventJson(eventId, "payment_intent.succeeded", pi);
        long now = Instant.now().getEpochSecond();

        byte[] tampered = new String(body, StandardCharsets.UTF_8)
                .replace("\"amount_received\":2000", "\"amount_received\":1").getBytes(StandardCharsets.UTF_8);
        assertThat(tampered).isNotEqualTo(body);
        assertRejected(f, f.signedHeader(now, body), tampered, Reason.BAD_SIGNATURE);
        assertRejected(f, f.signedHeader(now - 301, body), body, Reason.TIMESTAMP_OUT_OF_TOLERANCE);
        assertRejected(f, null, body, Reason.MISSING_SIGNATURE);

        assertThat(count("SELECT count(*) FROM processed_webhooks WHERE provider_event_id = ?", eventId)).isZero();
        assertThat(f.intent(intent.intentId()).status()).isEqualTo(IntentStatus.CONFIRMING);
        f.assertBalances(8_000, 2_000, 0);
    }

    private static void assertRejected(Fixture f, String header, byte[] body, Reason reason) {
        assertThatThrownBy(() -> f.webhooks.handle(header, body))
                .isInstanceOfSatisfying(WebhookRejectedException.class, e -> assertThat(e.reason()).isEqualTo(reason));
    }

    @Test
    void canceledAndPaymentFailedWebhooksVoidOnlyOnceTheRailCannotCharge() {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC);

        UUID canceledId = f.engine.reserve(f.request(1_000)).intent().intentId();
        f.engine.createOnRail(canceledId);
        RailPaymentIntent canceled = f.stripe.state.cancel(f.intent(canceledId).railPaymentIntentId());
        assertThat(f.deliver("evt_" + UUID.randomUUID(), "payment_intent.canceled", canceled).disposition())
                .isEqualTo(Disposition.APPLIED);
        assertThat(f.intent(canceledId).status()).isEqualTo(IntentStatus.VOIDED);

        // payment_failed leaves the payment intent cancelable, not canceled: recovery must cancel it first.
        UUID failedId = f.engine.reserve(f.request(1_000)).intent().intentId();
        f.engine.createOnRail(failedId);
        String failedPi = f.intent(failedId).railPaymentIntentId();
        RailPaymentIntent failed = f.stripe.state.retrieve(failedPi);
        var outcome = f.deliver("evt_" + UUID.randomUUID(), "payment_intent.payment_failed", failed);
        assertThat(outcome.disposition()).isEqualTo(Disposition.APPLIED);
        assertThat(f.intent(failedId).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.stripe.state.retrieve(failedPi).status()).isEqualTo(RailPiStatus.CANCELED);
        f.assertBalances(10_000, 0, 0);

        UUID stranger = UUID.randomUUID();
        RailPaymentIntent unknown = new RailPaymentIntent("pi_unknown_" + stranger, stranger, RailPiStatus.SUCCEEDED,
                MERCHANT, "USD", 100, 100);
        assertThat(f.deliver("evt_" + UUID.randomUUID(), "payment_intent.succeeded", unknown).disposition())
                .isEqualTo(Disposition.IGNORED);
    }

    @ParameterizedTest
    @EnumSource(names = {"HARDENED_PESSIMISTIC", "HARDENED_SSI"})
    void webhookArrivingBeforeTheConfirmResponseSettlesExactlyOnce(RuntimeMode mode) throws SQLException {
        Fixture f = new Fixture(mode);
        AtomicReference<dev.alaka.core.RailEventOutcome> delivered = new AtomicReference<>();
        String eventId = "evt_" + UUID.randomUUID();
        // Stripe can deliver payment_intent.succeeded before the /confirm HTTP response reaches us.
        f.stripe.afterConfirmApplied(pi -> delivered.set(f.deliver(eventId, "payment_intent.succeeded", pi)));

        IntentView result = f.engine.execute(f.request(2_500)).intent();

        assertThat(delivered.get().disposition()).isEqualTo(Disposition.APPLIED);
        assertThat(result.status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(count("SELECT count(*) FROM ledger_transactions WHERE intent_id = ? AND transition_type = 'CAPTURE'",
                result.intentId())).isEqualTo(1);
        f.assertBalances(7_500, 0, 2_500);
    }

    // ------------------------------------------------------------------------------------------
    // Recovery sweeper

    @Test
    void sweeperRecoversIntentsWhoseRequestCrashedMidFlight() throws SQLException {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC, Duration.ZERO, Duration.ofSeconds(5));
        YakshaRecoverySweeper sweeper = new YakshaRecoverySweeper(dataSource, f.engine,
                new YakshaRecoverySweeper.Options(500, Duration.ofSeconds(30), 2, Duration.ZERO, Duration.ZERO));

        // Crashed after Phase 1: nothing was ever sent to the rail.
        UUID reservedOnly = f.engine.reserve(f.request(1_000)).intent().intentId();
        // Crashed after Step 2A: an unconfirmed payment intent exists.
        UUID created = f.engine.reserve(f.request(1_000)).intent().intentId();
        f.engine.createOnRail(created);
        // Crashed after Step 2B: the rail charged, the ledger never heard back.
        UUID charged = chargedButNotCaptured(f, 2_000).intentId();
        // The rail is still processing: the hold must stay and the task must be retried, then dead-lettered.
        UUID processing = f.engine.reserve(f.request(1_500)).intent().intentId();
        f.stripe.state.setConfirmBehavior(processing, ConfirmBehavior.enterProcessing());
        f.engine.createOnRail(processing);
        f.engine.confirmOnRail(processing);
        f.assertBalances(4_500, 5_500, 0);

        sweeper.sweepOnce();
        assertThat(f.intent(reservedOnly).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.intent(created).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(f.stripe.state.retrieve(f.intent(created).railPaymentIntentId()).status())
                .isEqualTo(RailPiStatus.CANCELED);
        assertThat(f.intent(charged).status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(f.intent(processing).status()).isEqualTo(IntentStatus.CONFIRMING);
        for (UUID done : List.of(reservedOnly, created, charged)) {
            assertThat(taskStatus(done)).isEqualTo("COMPLETED");
        }
        assertThat(taskStatus(processing)).isEqualTo("PENDING");
        f.assertBalances(6_500, 1_500, 2_000);

        sweeper.sweepOnce();
        assertThat(taskStatus(processing)).isEqualTo("DEAD_LETTER");
        assertThat(f.intent(processing).status()).isEqualTo(IntentStatus.CONFIRMING);
        f.assertBalances(6_500, 1_500, 2_000);
        assertThat(f.stripe.state.totalChargedMinor()).isEqualTo(2_000);
    }

    @Test
    void sweeperRespectsTheGracePeriodAndReclaimsExpiredLeases() throws SQLException {
        Fixture f = new Fixture(RuntimeMode.HARDENED_PESSIMISTIC, Duration.ofHours(1), Duration.ofSeconds(5));
        YakshaRecoverySweeper sweeper = new YakshaRecoverySweeper(dataSource, f.engine,
                new YakshaRecoverySweeper.Options(500, Duration.ofSeconds(30), 3, Duration.ZERO, Duration.ZERO));
        UUID inFlight = f.engine.reserve(f.request(1_000)).intent().intentId();

        sweeper.sweepOnce();
        assertThat(taskStatus(inFlight)).isEqualTo("PENDING");
        assertThat(f.intent(inFlight).status()).isEqualTo(IntentStatus.RESERVED);

        // A sweeper claimed the task and died: its lease has run out.
        update("UPDATE outbox_tasks SET status = 'PROCESSING', attempts = 1, locked_until = NOW() - INTERVAL '1 second'"
                + " WHERE intent_id = ?", inFlight);
        sweeper.sweepOnce();
        assertThat(f.intent(inFlight).status()).isEqualTo(IntentStatus.VOIDED);
        assertThat(taskStatus(inFlight)).isEqualTo("COMPLETED");
        assertThat(count("SELECT attempts FROM outbox_tasks WHERE intent_id = ?", inFlight)).isEqualTo(2);
    }

    // ------------------------------------------------------------------------------------------

    private static long count(String sql, Object parameter) throws SQLException {
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, parameter);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }

    private static String taskStatus(UUID intentId) throws SQLException {
        try (Connection c = dataSource.getConnection();
                PreparedStatement ps = c.prepareStatement("SELECT status FROM outbox_tasks WHERE intent_id = ?")) {
            ps.setObject(1, intentId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : "NO_TASK";
            }
        }
    }

    private static void update(String sql, Object parameter) throws SQLException {
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, parameter);
            ps.executeUpdate();
        }
    }
}
