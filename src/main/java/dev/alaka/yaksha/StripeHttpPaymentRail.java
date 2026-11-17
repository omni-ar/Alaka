package dev.alaka.yaksha;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.UUID;

/**
 * {@link PaymentRailPort} over Stripe's v1 HTTP wire protocol ({@code application/x-www-form-urlencoded}
 * requests, JSON responses), on the JDK's {@link HttpClient}. The base URL is configurable, so the
 * same adapter talks to {@code https://api.stripe.com} in test mode, to an in-process mock in
 * integration tests, or through a fault-injecting proxy in chaos tests.
 *
 * <p>Calls: {@code POST /v1/payment_intents} ({@code confirm=false},
 * {@code capture_method=automatic}, {@code Idempotency-Key: create_<intentId>}),
 * {@code POST /v1/payment_intents/{id}/confirm} ({@code Idempotency-Key: confirm_<intentId>}),
 * {@code GET /v1/payment_intents/{id}} and {@code POST /v1/payment_intents/{id}/cancel}.
 *
 * <p>With automatic capture, a succeeded card payment's {@code amount_received} equals its
 * {@code amount}, so this adapter never produces a partial capture. The ledger and the TLA+ model
 * support one ({@code captured_amount_minor < authorized_amount_minor}, remainder back to
 * {@code MANDATE_AVAILABLE}); reaching it on Stripe would need manual capture plus an
 * {@code AUTHORIZED} protocol state.
 *
 * <p>Error mapping, chosen so that the engine never draws a conclusion Stripe did not state:
 * <ul>
 *   <li>I/O error, timeout, HTTP 5xx, 429, or 409 (idempotency key in use):
 *       {@link RailException.Timeout}. The outcome is unknown; Stripe even caches a 500 under the
 *       idempotency key, so recovery must use {@code GET}, never a re-sent POST.
 *   <li>404: {@link RailException.UnknownPaymentIntent}.
 *   <li>402 ({@code card_error}): {@link RailException.Declined}.
 *   <li>400 {@code payment_intent_unexpected_state} on cancel: {@link RailException.CancelRejected}
 *       with the payment intent's actual state; on confirm of a canceled payment intent:
 *       {@link RailException.ConfirmRejected}.
 *   <li>any other 4xx (bad key, bad request): {@link IllegalStateException}, a configuration bug.
 * </ul>
 */
public final class StripeHttpPaymentRail implements PaymentRailPort {

    /**
     * Adapter configuration.
     *
     * @param baseUrl API base, e.g. {@code https://api.stripe.com}
     * @param secretKey secret API key ({@code sk_test_...} in test mode)
     * @param requestTimeout per-request timeout; expiry is reported as {@link RailException.Timeout}
     * @param confirmPaymentMethod payment method attached at confirm (e.g. {@code pm_card_visa} in
     *     test mode), or {@code null} to confirm with the one already attached
     */
    public record Config(URI baseUrl, String secretKey, Duration requestTimeout, String confirmPaymentMethod) {

        public Config {
            Objects.requireNonNull(baseUrl, "baseUrl");
            Objects.requireNonNull(secretKey, "secretKey");
            Objects.requireNonNull(requestTimeout, "requestTimeout");
        }

        /**
         * Returns the configuration for Stripe test mode.
         *
         * @param testSecretKey an {@code sk_test_...} key
         * @return a config against {@code https://api.stripe.com} confirming with {@code pm_card_visa}
         */
        public static Config stripeTestMode(String testSecretKey) {
            if (!testSecretKey.startsWith("sk_test_")) {
                throw new IllegalArgumentException("refusing a non-test Stripe key");
            }
            return new Config(URI.create("https://api.stripe.com"), testSecretKey, Duration.ofSeconds(20), "pm_card_visa");
        }
    }

    private final Config config;
    private final HttpClient http;

    /**
     * Creates an adapter.
     *
     * @param config configuration
     * @param http HTTP client (thread-safe; share one per process)
     */
    public StripeHttpPaymentRail(Config config, HttpClient http) {
        this.config = Objects.requireNonNull(config, "config");
        this.http = Objects.requireNonNull(http, "http");
    }

    @Override
    public RailPaymentIntent createUnconfirmed(
            String idempotencyKey, UUID intentId, String merchantId, String currency, long amountMinor) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("amount", Long.toString(amountMinor));
        form.put("currency", currency.toLowerCase(Locale.ROOT));
        form.put("confirm", "false");
        // Automatic capture: a successful confirm charges the full amount. Partial capture needs
        // capture_method=manual, a /capture call and an AUTHORIZED state this adapter does not
        // implement, so it is pinned explicitly rather than left to the API version's default.
        form.put("capture_method", "automatic");
        form.put("payment_method_types[]", "card");
        form.put("metadata[intent_id]", intentId.toString());
        form.put("metadata[merchant_id]", merchantId);
        Response response = send("POST", "/v1/payment_intents", form, idempotencyKey);
        if (response.ok()) {
            return StripeJson.toRail(response.json());
        }
        throw generalError(response, "create");
    }

    @Override
    public RailPaymentIntent confirm(String piId, String idempotencyKey) {
        Map<String, String> form = new LinkedHashMap<>();
        if (config.confirmPaymentMethod() != null) {
            form.put("payment_method", config.confirmPaymentMethod());
        }
        Response response = send("POST", "/v1/payment_intents/" + encode(piId) + "/confirm", form, idempotencyKey);
        if (response.ok()) {
            return StripeJson.toRail(response.json());
        }
        if (response.status() == 402) {
            throw new RailException.Declined("confirm of " + piId + " declined: " + response.errorMessage());
        }
        if (response.isUnexpectedState()) {
            RailPaymentIntent current = response.errorPaymentIntent().orElseGet(() -> retrieve(piId));
            if (current.status() == RailPiStatus.CANCELED) {
                throw new RailException.ConfirmRejected(piId + " is canceled");
            }
            // Already processing or succeeded: a confirm is idempotent, report the current state.
            return current;
        }
        throw generalError(response, "confirm");
    }

    @Override
    public RailPaymentIntent retrieve(String piId) {
        Response response = send("GET", "/v1/payment_intents/" + encode(piId), Map.of(), null);
        if (response.ok()) {
            return StripeJson.toRail(response.json());
        }
        throw generalError(response, "retrieve");
    }

    @Override
    public RailPaymentIntent cancel(String piId) {
        Response response = send("POST", "/v1/payment_intents/" + encode(piId) + "/cancel", Map.of(), null);
        if (response.ok()) {
            return StripeJson.toRail(response.json());
        }
        if (response.isUnexpectedState()) {
            RailPaymentIntent current = response.errorPaymentIntent().orElseGet(() -> retrieve(piId));
            throw new RailException.CancelRejected(current.status(),
                    "cannot cancel " + piId + " in state " + current.status() + " (payment_intent_unexpected_state)");
        }
        throw generalError(response, "cancel");
    }

    // ------------------------------------------------------------------------------------------

    private record Response(int status, byte[] body) {

        boolean ok() {
            return status >= 200 && status < 300;
        }

        JsonNode json() {
            return StripeJson.parse(body);
        }

        JsonNode error() {
            try {
                return json().path("error");
            } catch (IllegalArgumentException e) {
                return StripeJson.MAPPER.missingNode();
            }
        }

        String errorMessage() {
            JsonNode error = error();
            return error.path("code").asText("") + " " + error.path("message").asText("HTTP " + status);
        }

        boolean isUnexpectedState() {
            return status == 400 && "payment_intent_unexpected_state".equals(error().path("code").asText());
        }

        java.util.Optional<RailPaymentIntent> errorPaymentIntent() {
            JsonNode pi = error().path("payment_intent");
            return pi.isObject() ? java.util.Optional.of(StripeJson.toRail(pi)) : java.util.Optional.empty();
        }
    }

    private Response send(String method, String path, Map<String, String> form, String idempotencyKey) {
        HttpRequest.Builder request = HttpRequest.newBuilder(config.baseUrl().resolve(path))
                .timeout(config.requestTimeout())
                .header("Authorization", "Bearer " + config.secretKey());
        if (idempotencyKey != null) {
            request.header("Idempotency-Key", idempotencyKey);
        }
        if (method.equals("GET")) {
            request.GET();
        } else {
            request.header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody(form)));
        }
        try {
            HttpResponse<byte[]> response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            return new Response(response.statusCode(), response.body());
        } catch (IOException e) {
            throw new RailException.Timeout(method + " " + path + " outcome unknown: " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RailException.Timeout(method + " " + path + " interrupted; outcome unknown");
        }
    }

    private static RuntimeException generalError(Response response, String call) {
        int status = response.status();
        if (status == 404) {
            return new RailException.UnknownPaymentIntent(call + ": " + response.errorMessage());
        }
        if (status >= 500 || status == 429 || status == 409) {
            return new RailException.Timeout(call + ": HTTP " + status + " " + response.errorMessage() + "; outcome unknown");
        }
        return new IllegalStateException("Stripe rejected " + call + ": HTTP " + status + " " + response.errorMessage());
    }

    private static String formBody(Map<String, String> form) {
        StringJoiner body = new StringJoiner("&");
        form.forEach((key, value) -> body.add(encode(key) + "=" + encode(value)));
        return body.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
