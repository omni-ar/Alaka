package dev.alaka.core.http;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.alaka.core.AlakaApplication;
import dev.alaka.mudra.MudraMandateClaims;
import dev.alaka.mudra.MudraQuoteClaims;
import dev.alaka.mudra.MudraQuoteSigner;
import dev.alaka.mudra.MudraTokenSigner;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.ConfirmBehavior;
import dev.alaka.yaksha.MockStripeServer;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.StripeWebhookVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * The real Spring Boot application, started on a random port against PostgreSQL 16 (as
 * {@code alaka_app}) and {@link MockStripeServer}, driven over HTTP: status codes, headers and the
 * end-to-end flow from mandate registration to webhook settlement.
 */
class AlakaHttpControllerTest {

    private static final String API_KEY = "sk_test_http";
    private static final String WEBHOOK_SECRET = "whsec_http";
    private static final String MERCHANT = "merchant-a";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private static MockStripeServer stripe;
    private static ConfigurableApplicationContext app;
    private static URI base;
    private static MudraTokenSigner signer;
    private static MudraQuoteSigner approver;
    private static KeyPair issuer;
    private static NidhiPostgres db;

    @BeforeAll
    static void startApplication() throws NoSuchAlgorithmException {
        issuer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair approverKeys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        signer = new MudraTokenSigner("kid-http", issuer.getPrivate());
        approver = new MudraQuoteSigner("quote-http", approverKeys.getPrivate());
        stripe = new MockStripeServer(API_KEY);
        db = NidhiPostgres.shared().isolatedDatabase("alaka_http");
        app = new SpringApplicationBuilder(AlakaApplication.class).run(
                "--server.port=0",
                "--alaka.mode=hardened-pessimistic",
                "--alaka.db.url=" + db.jdbcUrl(),
                "--alaka.db.username=alaka_app",
                "--alaka.db.password=alaka_app_dev_only",
                "--alaka.stripe.base-url=" + stripe.baseUrl(),
                "--alaka.stripe.secret-key=" + API_KEY,
                "--alaka.stripe.webhook-secret=" + WEBHOOK_SECRET,
                "--alaka.stripe.confirm-payment-method=pm_card_visa",
                "--alaka.stripe.request-timeout=5s",
                "--alaka.mudra.trusted-keys.kid-http=" + Base64.getEncoder().encodeToString(issuer.getPublic().getEncoded()),
                "--alaka.mudra.trusted-quote-keys.quote-http="
                        + Base64.getEncoder().encodeToString(approverKeys.getPublic().getEncoded()),
                "--alaka.recovery.sweep-interval=0s");
        base = URI.create("http://127.0.0.1:" + app.getEnvironment().getProperty("local.server.port"));
    }

    @AfterAll
    static void stopApplication() {
        app.close();
        stripe.close();
    }

    private record Reply(int status, JsonNode body, HttpResponse<String> raw) {
    }

    private static Reply post(String path, String token, String json) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));
        if (token != null) {
            request.header("X-Mudra-Token", token);
        }
        HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
        JsonNode body = response.body().isEmpty() ? JSON.missingNode() : JSON.readTree(response.body());
        return new Reply(response.statusCode(), body, response);
    }

    /** A spend with a quote the approver signed for exactly this request, at {@code quoted} + 1 %. */
    private static String spendJson(UUID mandate, String agent, String key, String merchant, long amount, long quoted) {
        return spendJson(mandate, agent, key, merchant, amount, approver.sign(quoteClaims(mandate, agent, key, merchant,
                quoted, 100, "quote-http")));
    }

    private static MudraQuoteClaims quoteClaims(UUID mandate, String agent, String key, String merchant, long quoted,
            int bps, String kid) {
        return new MudraQuoteClaims(mandate, agent, key, merchant, "USD", quoted, bps,
                Instant.now().getEpochSecond() + 300, kid);
    }

    private static String spendJson(UUID mandate, String agent, String key, String merchant, long amount,
            String quoteToken) {
        com.fasterxml.jackson.databind.node.ObjectNode body = JSON.createObjectNode()
                .put("mandate_id", mandate.toString())
                .put("agent_id", agent)
                .put("idempotency_key", key)
                .put("merchant_id", merchant)
                .put("currency", "USD")
                .put("amount_minor", amount);
        if (quoteToken != null) {
            body.put("quote_token", quoteToken);
        }
        return body.toString();
    }

    /** A mandate valid from a minute ago: the signer's clock may run ahead of the database's NOW(). */
    private static String token(UUID mandate, String agent, List<String> merchants) {
        long now = Instant.now().getEpochSecond();
        return signer.sign(new MudraMandateClaims(mandate, agent, "USD", 10_000, 5_000, merchants, now - 60,
                now + 3_600, "kid-http"));
    }

    private static Reply register(String token) throws IOException, InterruptedException {
        return post("/v1/mandates", null, JSON.createObjectNode().put("token", token).toString());
    }

    @Test
    void endToEndSpendIdempotencyAndBudgetStatusCodes() throws Exception {
        UUID mandate = UUID.randomUUID();
        String agent = "agent-" + UUID.randomUUID();
        String token = token(mandate, agent, List.of(MERCHANT, "merchant-evil-but-signed"));

        Reply registered = register(token);
        assertThat(registered.status()).isEqualTo(201);
        assertThat(registered.body().path("mandate_id").asText()).isEqualTo(mandate.toString());
        assertThat(register(token).status()).as("already registered").isEqualTo(409);

        Reply spent = post("/v1/spends", token, spendJson(mandate, agent, "k1", MERCHANT, 4_000, 4_000));
        assertThat(spent.status()).isEqualTo(200);
        assertThat(spent.body().path("status").asText()).isEqualTo("CAPTURED");
        assertThat(spent.body().path("captured_amount_minor").asLong()).isEqualTo(4_000);
        assertThat(spent.body().path("replayed").asBoolean()).isFalse();

        Reply replay = post("/v1/spends", token, spendJson(mandate, agent, "k1", MERCHANT, 4_000, 4_000));
        assertThat(replay.status()).isEqualTo(200);
        assertThat(replay.body().path("replayed").asBoolean()).isTrue();
        assertThat(replay.body().path("intent_id").asText()).isEqualTo(spent.body().path("intent_id").asText());

        Reply tampered = post("/v1/spends", token, spendJson(mandate, agent, "k1", MERCHANT, 4_001, 4_001));
        assertThat(tampered.status()).isEqualTo(422);
        assertThat(tampered.body().path("error").path("code").asText()).isEqualTo("IdempotencyKeyPayloadMismatch");

        Reply overCap = post("/v1/spends", token, spendJson(mandate, agent, "k2", MERCHANT, 5_001, 5_001));
        assertThat(overCap.status()).as("per-tx cap 5000").isEqualTo(402);
        assertThat(overCap.body().path("error").path("code").asText()).isEqualTo("SG003");
        assertThat(post("/v1/spends", token, spendJson(mandate, agent, "k3", MERCHANT, 5_000, 5_000)).status())
                .isEqualTo(200);
        Reply overdraw = post("/v1/spends", token, spendJson(mandate, agent, "k4", MERCHANT, 1_001, 1_001));
        assertThat(overdraw.status()).as("only 1000 left").isEqualTo(402);

        Reply drift = post("/v1/spends", token, spendJson(mandate, agent, "k5", MERCHANT, 1_000, 900));
        assertThat(drift.status()).isEqualTo(422);
        assertThat(drift.body().path("error").path("code").asText()).isEqualTo("QuoteDrift.PRICE");
    }

    @Test
    void unsignedTamperedReplayedOrUntrustedQuotesAre422BeforePostgres() throws Exception {
        UUID mandate = UUID.randomUUID();
        String agent = "agent-" + UUID.randomUUID();
        String token = token(mandate, agent, List.of(MERCHANT));
        assertThat(register(token).status()).isEqualTo(201);
        String approved = approver.sign(quoteClaims(mandate, agent, "k1", MERCHANT, 2_000, 100, "quote-http"));

        // The pre-signing API shape (an unsigned "quote" object) is refused outright.
        String legacy = JSON.createObjectNode().put("mandate_id", mandate.toString()).put("agent_id", agent)
                .put("idempotency_key", "k1").put("merchant_id", MERCHANT).put("currency", "USD").put("amount_minor", 2_000)
                .<com.fasterxml.jackson.databind.node.ObjectNode>set("quote", JSON.createObjectNode()
                        .put("merchant_id", MERCHANT).put("quoted_amount_minor", 9_000))
                .toString();
        assertThat(post("/v1/spends", token, legacy).status()).isEqualTo(400);

        assertInvalidQuote(token, spendJson(mandate, agent, "k1", MERCHANT, 2_000, (String) null), "MALFORMED");
        assertInvalidQuote(token, spendJson(mandate, agent, "k1", MERCHANT, 9_000,
                withPayload(approved, quoteClaims(mandate, agent, "k1", MERCHANT, 9_000, 100, "quote-http")
                        .canonicalBytes())), "BAD_SIGNATURE");
        assertInvalidQuote(token, spendJson(mandate, agent, "k1", MERCHANT, 4_000,
                withPayload(approved, quoteClaims(mandate, agent, "k1", MERCHANT, 2_000, 10_000, "quote-http")
                        .canonicalBytes())), "BAD_SIGNATURE");
        assertInvalidQuote(token, spendJson(mandate, agent, "k2", MERCHANT, 2_000, approved), "MISMATCH");
        String issuerSigned = new MudraQuoteSigner("kid-http", issuer.getPrivate())
                .sign(quoteClaims(mandate, agent, "k1", MERCHANT, 2_000, 100, "kid-http"));
        assertInvalidQuote(token, spendJson(mandate, agent, "k1", MERCHANT, 2_000, issuerSigned), "UNKNOWN_KEY");

        try (Connection c = db.openAppConnection();
                PreparedStatement ps = c.prepareStatement("SELECT count(*) FROM payment_intents WHERE mandate_id = ?")) {
            ps.setObject(1, mandate);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                assertThat(rs.getLong(1)).as("no rejected quote reached the ledger").isZero();
            }
        }
        Reply honest = post("/v1/spends", token, spendJson(mandate, agent, "k1", MERCHANT, 2_000, approved));
        assertThat(honest.status()).isEqualTo(200);
        assertThat(honest.body().path("status").asText()).isEqualTo("CAPTURED");
    }

    private static void assertInvalidQuote(String token, String body, String reason) throws Exception {
        Reply reply = post("/v1/spends", token, body);
        assertThat(reply.status()).isEqualTo(422);
        assertThat(reply.body().path("error").path("code").asText()).isEqualTo("InvalidQuote." + reason);
    }

    private static String withPayload(String token, byte[] payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." + parts[2];
    }

    @Test
    void tokenAndMandateRejections() throws Exception {
        UUID mandate = UUID.randomUUID();
        String agent = "agent-" + UUID.randomUUID();
        String token = token(mandate, agent, List.of(MERCHANT));
        assertThat(register(token).status()).isEqualTo(201);

        String forged = new MudraTokenSigner("kid-http",
                KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPrivate()).sign(
                forgedClaims(mandate, agent, 1_000_000));
        Reply badToken = post("/v1/spends", forged, spendJson(mandate, agent, "k1", MERCHANT, 100, 100));
        assertThat(badToken.status()).isEqualTo(422);
        assertThat(badToken.body().path("error").path("code").asText()).isEqualTo("BadSignature");
        assertThat(register(forged).status()).isEqualTo(422);

        assertThat(post("/v1/spends", null, spendJson(mandate, agent, "k1", MERCHANT, 100, 100)).status())
                .as("missing X-Mudra-Token").isEqualTo(400);

        Reply merchant = post("/v1/spends", token, spendJson(mandate, agent, "k2", "merchant-other", 100, 100));
        assertThat(merchant.status()).isEqualTo(403);
        assertThat(merchant.body().path("error").path("code").asText()).isEqualTo("SG008");

        assertThat(post("/v1/mandates/" + mandate + "/revoke", null, "{\"reason\":\"compromised\"}").status())
                .isEqualTo(200);
        Reply revoked = post("/v1/spends", token, spendJson(mandate, agent, "k3", MERCHANT, 100, 100));
        assertThat(revoked.status()).isEqualTo(403);
        assertThat(revoked.body().path("error").path("code").asText()).isEqualTo("SG001");
        assertThat(post("/v1/mandates/" + mandate + "/revoke", null, "{}").status()).as("terminal").isEqualTo(409);
        assertThat(post("/v1/mandates/" + UUID.randomUUID() + "/revoke", null, "{}").status()).isEqualTo(404);
    }

    @Test
    void processingSpendAnswers202Then409WithRetryAfterAndSettlesByWebhook() throws Exception {
        UUID mandate = UUID.randomUUID();
        String agent = "agent-" + UUID.randomUUID();
        String token = token(mandate, agent, List.of(MERCHANT));
        assertThat(register(token).status()).isEqualTo(201);
        String body = spendJson(mandate, agent, "k1", MERCHANT, 3_000, 3_000);

        stripe.state.setDefaultConfirmBehavior(ConfirmBehavior.enterProcessing());
        Reply accepted;
        try {
            accepted = post("/v1/spends", token, body);
        } finally {
            stripe.state.setDefaultConfirmBehavior(ConfirmBehavior.succeedFull());
        }
        assertThat(accepted.status()).isEqualTo(202);
        assertThat(accepted.body().path("status").asText()).isEqualTo("CONFIRMING");

        Reply inFlight = post("/v1/spends", token, body);
        assertThat(inFlight.status()).isEqualTo(409);
        assertThat(inFlight.raw().headers().firstValue("Retry-After")).hasValue("1");
        assertThat(inFlight.body().path("error").path("code").asText()).isEqualTo("IdempotencyKeyInFlight");

        // Stripe resolves the payment and tells us by webhook.
        String piId = accepted.body().path("rail_payment_intent_id").asText();
        RailPaymentIntent succeeded = stripe.state.resolveProcessingAsSucceeded(piId, 0);
        String eventId = "evt_" + UUID.randomUUID();
        byte[] event = MockStripeServer.eventJson(eventId, "payment_intent.succeeded", succeeded);
        StripeWebhookVerifier signing = new StripeWebhookVerifier(WEBHOOK_SECRET,
                StripeWebhookVerifier.DEFAULT_TOLERANCE, Clock.systemUTC());
        long t = Instant.now().getEpochSecond();
        String signature = "t=" + t + ",v1=" + HexFormat.of().formatHex(signing.sign(t, event));

        Reply applied = webhook(signature, event);
        assertThat(applied.status()).isEqualTo(200);
        assertThat(applied.body().path("disposition").asText()).isEqualTo("APPLIED");
        assertThat(webhook(signature, event).body().path("disposition").asText()).isEqualTo("DUPLICATE");
        Reply forged = webhook("t=" + t + ",v1=" + "00".repeat(32), event);
        assertThat(forged.status()).isEqualTo(400);
        assertThat(forged.body().path("error").path("code").asText()).isEqualTo("BAD_SIGNATURE");
        assertThat(webhook(null, event).status()).isEqualTo(400);

        Reply settled = post("/v1/spends", token, body);
        assertThat(settled.status()).isEqualTo(200);
        assertThat(settled.body().path("status").asText()).isEqualTo("CAPTURED");
        assertThat(settled.body().path("replayed").asBoolean()).isTrue();
    }

    @Test
    void prometheusEndpointExportsEngineAndRecoveryMetrics() throws Exception {
        HttpResponse<String> scrape = HTTP.send(HttpRequest.newBuilder(base.resolve("/actuator/prometheus")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(scrape.statusCode()).isEqualTo(200);
        assertThat(scrape.body())
                .contains("alaka_engine_serialization_failures_total{mode=\"hardened-pessimistic\"}")
                .contains("alaka_engine_deadlocks_total{mode=\"hardened-pessimistic\"}")
                .contains("alaka_engine_retries_exhausted_total{mode=\"hardened-pessimistic\"}")
                .contains("alaka_outbox_tasks{status=\"DEAD_LETTER\"}")
                .contains("alaka_outbox_tasks{status=\"PENDING\"}")
                .contains("alaka_outbox_oldest_overdue_seconds")
                .contains("alaka_outbox_dead_letter_held_minor");
        HttpResponse<String> health = HTTP.send(HttpRequest.newBuilder(base.resolve("/actuator/health")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(health.statusCode()).isEqualTo(200);
        HttpResponse<String> hidden = HTTP.send(HttpRequest.newBuilder(base.resolve("/actuator/env")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(hidden.statusCode()).as("only health and prometheus are exposed").isEqualTo(404);
    }

    private static Reply webhook(String signature, byte[] event) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve("/v1/webhooks/stripe"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(event));
        if (signature != null) {
            request.header("Stripe-Signature", signature);
        }
        HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), JSON.readTree(response.body()), response);
    }

    private static MudraMandateClaims forgedClaims(UUID mandate, String agent, long budget) {
        long now = Instant.now().getEpochSecond();
        return new MudraMandateClaims(mandate, agent, "USD", budget, 5_000, List.of(MERCHANT), now - 60, now + 3_600,
                "kid-http");
    }
}
