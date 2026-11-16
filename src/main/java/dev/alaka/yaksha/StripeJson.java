package dev.alaka.yaksha;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Locale;
import java.util.UUID;

/** Maps Stripe v1 {@code payment_intent} JSON objects onto {@link RailPaymentIntent}. */
final class StripeJson {

    static final ObjectMapper MAPPER = new ObjectMapper();

    private StripeJson() {
    }

    static JsonNode parse(byte[] body) {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            throw new IllegalArgumentException("unparseable Stripe JSON", e);
        }
    }

    /**
     * Maps a {@code payment_intent} object.
     *
     * <ul>
     *   <li>{@code requires_payment_method}, {@code requires_confirmation}, {@code requires_action},
     *       {@code requires_capture}: no money has moved and {@code /cancel} is accepted, so
     *       {@link RailPiStatus#REQUIRES_CONFIRMATION};
     *   <li>{@code processing}: {@link RailPiStatus#PROCESSING};
     *   <li>{@code succeeded}: {@link RailPiStatus#SUCCEEDED}, charged {@code amount_received};
     *   <li>{@code canceled}: {@link RailPiStatus#CANCELED}.
     * </ul>
     */
    static RailPaymentIntent toRail(JsonNode pi) {
        if (!"payment_intent".equals(pi.path("object").asText())) {
            throw new IllegalArgumentException("not a payment_intent object: " + pi.path("object").asText());
        }
        String status = pi.path("status").asText();
        RailPiStatus mapped = switch (status) {
            case "requires_payment_method", "requires_confirmation", "requires_action", "requires_capture" ->
                    RailPiStatus.REQUIRES_CONFIRMATION;
            case "processing" -> RailPiStatus.PROCESSING;
            case "succeeded" -> RailPiStatus.SUCCEEDED;
            case "canceled" -> RailPiStatus.CANCELED;
            default -> throw new IllegalArgumentException("unknown payment_intent status " + status);
        };
        String intentId = pi.path("metadata").path("intent_id").asText(null);
        if (intentId == null) {
            throw new IllegalArgumentException("payment_intent " + pi.path("id").asText() + " has no metadata[intent_id]");
        }
        return new RailPaymentIntent(
                pi.path("id").asText(),
                UUID.fromString(intentId),
                mapped,
                pi.path("metadata").path("merchant_id").asText(null),
                pi.path("currency").asText().toUpperCase(Locale.ROOT),
                pi.path("amount").asLong(),
                mapped == RailPiStatus.SUCCEEDED ? pi.path("amount_received").asLong() : 0);
    }
}
