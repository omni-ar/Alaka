package dev.alaka.yaksha;

import com.fasterxml.jackson.databind.JsonNode;
import dev.alaka.yaksha.WebhookRejectedException.Reason;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies Stripe webhook deliveries.
 *
 * <p>The {@code Stripe-Signature} header has the form {@code t=<unix seconds>,v1=<hex>[,v1=<hex>...]};
 * each {@code v1} is {@code HMAC-SHA256(endpointSecret, t + "." + rawBody)}. A delivery is accepted
 * if any {@code v1} matches (Stripe sends several while a secret is being rolled), compared in
 * constant time, and {@code t} is within the tolerance of this verifier's clock, which bounds how
 * long a captured delivery can be replayed. The signature covers the raw bytes, so the body must
 * be verified exactly as received, before any parsing.
 */
public final class StripeWebhookVerifier {

    /** Stripe's default tolerance. */
    public static final Duration DEFAULT_TOLERANCE = Duration.ofSeconds(300);

    /**
     * A verified event.
     *
     * @param id event id ({@code evt_...})
     * @param type event type, e.g. {@code payment_intent.succeeded}
     * @param paymentIntent the payment intent the event carries, if its object is one
     */
    public record VerifiedEvent(String id, String type, Optional<RailPaymentIntent> paymentIntent) {
    }

    private final byte[] secret;
    private final Duration tolerance;
    private final Clock clock;

    /**
     * Creates a verifier.
     *
     * @param endpointSecret the endpoint's signing secret ({@code whsec_...})
     * @param tolerance accepted distance between the signed timestamp and now
     * @param clock clock to judge the timestamp against
     */
    public StripeWebhookVerifier(String endpointSecret, Duration tolerance, Clock clock) {
        this.secret = endpointSecret.getBytes(StandardCharsets.UTF_8);
        this.tolerance = Objects.requireNonNull(tolerance, "tolerance");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifies a delivery and parses its event.
     *
     * @param signatureHeader value of the {@code Stripe-Signature} header, possibly {@code null}
     * @param rawBody the request body exactly as received
     * @return the event
     * @throws WebhookRejectedException if the header is missing or malformed, the timestamp is
     *     outside the tolerance, no signature matches, or the body is not an event
     */
    public VerifiedEvent verify(String signatureHeader, byte[] rawBody) {
        if (signatureHeader == null || signatureHeader.isBlank()) {
            throw new WebhookRejectedException(Reason.MISSING_SIGNATURE, "no Stripe-Signature header");
        }
        Long timestamp = null;
        List<byte[]> candidates = new ArrayList<>();
        for (String element : signatureHeader.split(",")) {
            int eq = element.indexOf('=');
            if (eq <= 0) {
                throw new WebhookRejectedException(Reason.MALFORMED_SIGNATURE, "bad element '" + element + "'");
            }
            String key = element.substring(0, eq).trim();
            String value = element.substring(eq + 1).trim();
            try {
                if (key.equals("t")) {
                    timestamp = Long.parseLong(value);
                } else if (key.equals("v1")) {
                    candidates.add(HexFormat.of().parseHex(value));
                }
            } catch (IllegalArgumentException e) {
                throw new WebhookRejectedException(Reason.MALFORMED_SIGNATURE, "bad " + key + " value");
            }
        }
        if (timestamp == null || candidates.isEmpty()) {
            throw new WebhookRejectedException(Reason.MALFORMED_SIGNATURE, "need t= and at least one v1=");
        }
        long skew = Math.abs(clock.instant().getEpochSecond() - timestamp);
        if (skew > tolerance.toSeconds()) {
            throw new WebhookRejectedException(Reason.TIMESTAMP_OUT_OF_TOLERANCE,
                    "signed timestamp is " + skew + " s away from now (tolerance " + tolerance.toSeconds() + " s)");
        }
        byte[] expected = sign(timestamp, rawBody);
        boolean matched = false;
        for (byte[] candidate : candidates) {
            // Constant time per candidate; evaluate all of them so timing does not reveal which matched.
            matched |= MessageDigest.isEqual(expected, candidate);
        }
        if (!matched) {
            throw new WebhookRejectedException(Reason.BAD_SIGNATURE, "no v1 signature matches");
        }
        return parse(rawBody);
    }

    /**
     * Computes the {@code v1} signature of a delivery, as Stripe does when it sends one.
     *
     * @param timestamp signed timestamp, unix seconds
     * @param rawBody the body
     * @return the HMAC-SHA256 bytes
     */
    public byte[] sign(long timestamp, byte[] rawBody) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            mac.update((timestamp + ".").getBytes(StandardCharsets.UTF_8));
            return mac.doFinal(rawBody);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is required of every Java platform", e);
        }
    }

    private static VerifiedEvent parse(byte[] rawBody) {
        JsonNode event;
        try {
            event = StripeJson.parse(rawBody);
        } catch (IllegalArgumentException e) {
            throw new WebhookRejectedException(Reason.MALFORMED_PAYLOAD, "body is not JSON");
        }
        String id = event.path("id").asText("");
        String type = event.path("type").asText("");
        if (!"event".equals(event.path("object").asText()) || !id.startsWith("evt_") || type.isEmpty()) {
            throw new WebhookRejectedException(Reason.MALFORMED_PAYLOAD, "body is not a Stripe event");
        }
        JsonNode object = event.path("data").path("object");
        Optional<RailPaymentIntent> pi = Optional.empty();
        if ("payment_intent".equals(object.path("object").asText())) {
            try {
                pi = Optional.of(StripeJson.toRail(object));
            } catch (IllegalArgumentException e) {
                throw new WebhookRejectedException(Reason.MALFORMED_PAYLOAD, "bad payment_intent: " + e.getMessage());
            }
        }
        return new VerifiedEvent(id, type, pi);
    }
}
