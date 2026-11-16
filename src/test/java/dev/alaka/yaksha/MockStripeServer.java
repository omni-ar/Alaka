package dev.alaka.yaksha;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * An in-process HTTP server speaking Stripe's v1 payment intent wire protocol: form-encoded
 * requests, JSON responses, {@code Bearer} auth, {@code Idempotency-Key}, Stripe-shaped errors.
 *
 * <p>State and protocol rules are delegated to a {@link SimulatedPaymentRail} (exposed as
 * {@link #state}, so tests can program confirm outcomes and resolve {@code PROCESSING}). Its
 * timeout faults surface as HTTP 500, which is how Stripe reports a request whose outcome is
 * unknown. Every request is recorded for wire-level assertions.
 */
final class MockStripeServer implements AutoCloseable {

    /** One recorded request. */
    record Recorded(String method, String path, Map<String, String> headers, Map<String, String> form) {
    }

    final SimulatedPaymentRail state = new SimulatedPaymentRail();
    final List<Recorded> requests = new CopyOnWriteArrayList<>();
    private final String apiKey;
    private final HttpServer server;
    private volatile Duration confirmResponseDelay = Duration.ZERO;
    private volatile Consumer<RailPaymentIntent> afterConfirmApplied = pi -> { };

    MockStripeServer(String apiKey) {
        this.apiKey = apiKey;
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/v1/payment_intents", this::handle);
        server.start();
    }

    URI baseUrl() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** Delays every confirm response, after the confirm has been applied (a lost response). */
    void delayConfirmResponses(Duration delay) {
        confirmResponseDelay = delay;
    }

    /** Runs after a confirm is applied and before its response is sent (e.g. deliver a webhook). */
    void afterConfirmApplied(Consumer<RailPaymentIntent> hook) {
        afterConfirmApplied = hook;
    }

    List<Recorded> requestsTo(String pathSuffix) {
        return requests.stream().filter(r -> r.path().endsWith(pathSuffix)).toList();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // ------------------------------------------------------------------------------------------

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(Locale.ROOT), v.get(0)));
            Map<String, String> form = parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            requests.add(new Recorded(method, path, headers, form));

            if (!("Bearer " + apiKey).equals(headers.get("authorization"))) {
                respond(exchange, 401, error("invalid_request_error", null, "Invalid API Key provided", null));
                return;
            }
            String[] segments = path.split("/");   // "", "v1", "payment_intents", [id], [action]
            try {
                if (segments.length == 3 && method.equals("POST")) {
                    create(exchange, headers, form);
                } else if (segments.length == 4 && method.equals("GET")) {
                    respond(exchange, 200, piJson(state.retrieve(segments[3])));
                } else if (segments.length == 5 && method.equals("POST") && segments[4].equals("confirm")) {
                    confirm(exchange, segments[3], headers);
                } else if (segments.length == 5 && method.equals("POST") && segments[4].equals("cancel")) {
                    respond(exchange, 200, piJson(state.cancel(segments[3])));
                } else {
                    respond(exchange, 404, error("invalid_request_error", "resource_missing", "Unrecognized request URL", null));
                }
            } catch (RailException.UnknownPaymentIntent e) {
                respond(exchange, 404, error("invalid_request_error", "resource_missing", "No such payment_intent", null));
            } catch (RailException.CancelRejected e) {
                respond(exchange, 400, error("invalid_request_error", "payment_intent_unexpected_state",
                        "You cannot cancel this PaymentIntent because it has a status of " + stripeStatus(e.statusAtRejection()),
                        state.retrieve(segments[3])));
            } catch (RailException.ConfirmRejected e) {
                respond(exchange, 400, error("invalid_request_error", "payment_intent_unexpected_state",
                        "This PaymentIntent's status is canceled", state.retrieve(segments[3])));
            } catch (RailException.Timeout e) {
                respond(exchange, 500, error("api_error", null, "An unknown error occurred", null));
            }
        }
    }

    private void create(HttpExchange exchange, Map<String, String> headers, Map<String, String> form) throws IOException {
        if (!"false".equals(form.get("confirm"))) {
            respond(exchange, 400, error("invalid_request_error", "parameter_invalid", "confirm must be false here", null));
            return;
        }
        String key = headers.get("idempotency-key");
        if (key == null) {
            respond(exchange, 400, error("invalid_request_error", "parameter_missing", "Idempotency-Key required by this mock", null));
            return;
        }
        RailPaymentIntent pi = state.createUnconfirmed(key, UUID.fromString(form.get("metadata[intent_id]")),
                form.get("metadata[merchant_id]"), form.get("currency").toUpperCase(Locale.ROOT),
                Long.parseLong(form.get("amount")));
        respond(exchange, 200, piJson(pi));
    }

    private void confirm(HttpExchange exchange, String piId, Map<String, String> headers) throws IOException {
        RailPaymentIntent pi = state.confirm(piId, headers.getOrDefault("idempotency-key", ""));
        afterConfirmApplied.accept(pi);
        Duration delay = confirmResponseDelay;
        if (!delay.isZero()) {
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        respond(exchange, 200, piJson(pi));
    }

    // ------------------------------------------------------------------------------------------
    // Stripe-shaped JSON

    static String stripeStatus(RailPiStatus status) {
        return switch (status) {
            case REQUIRES_CONFIRMATION -> "requires_confirmation";
            case PROCESSING -> "processing";
            case SUCCEEDED -> "succeeded";
            case CANCELED -> "canceled";
        };
    }

    static ObjectNode piNode(RailPaymentIntent pi) {
        ObjectNode node = StripeJson.MAPPER.createObjectNode();
        node.put("id", pi.piId());
        node.put("object", "payment_intent");
        node.put("amount", pi.amountMinor());
        node.put("amount_received", pi.chargedMinor());
        node.put("currency", pi.currency().toLowerCase(Locale.ROOT));
        node.put("status", stripeStatus(pi.status()));
        ObjectNode metadata = node.putObject("metadata");
        metadata.put("intent_id", pi.intentId().toString());
        metadata.put("merchant_id", pi.merchantId());
        return node;
    }

    private static byte[] piJson(RailPaymentIntent pi) {
        return piNode(pi).toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Builds a Stripe event body carrying a payment intent. */
    static byte[] eventJson(String eventId, String type, RailPaymentIntent pi) {
        ObjectNode event = StripeJson.MAPPER.createObjectNode();
        event.put("id", eventId);
        event.put("object", "event");
        event.put("type", type);
        event.putObject("data").set("object", piNode(pi));
        return event.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] error(String type, String code, String message, RailPaymentIntent pi) {
        ObjectNode body = StripeJson.MAPPER.createObjectNode();
        ObjectNode error = body.putObject("error");
        error.put("type", type);
        if (code != null) {
            error.put("code", code);
        }
        error.put("message", message);
        if (pi != null) {
            error.set("payment_intent", piNode(pi));
        }
        return body.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        if (body.isEmpty()) {
            return form;
        }
        List<String> pairs = new ArrayList<>(List.of(body.split("&")));
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return form;
    }
}
