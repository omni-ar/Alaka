package dev.alaka.yaksha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.alaka.yaksha.WebhookRejectedException.Reason;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class StripeWebhookVerifierTest {

    private static final Instant NOW = Instant.parse("2026-11-16T10:00:00Z");
    private static final String SECRET = "whsec_test_secret";

    private final StripeWebhookVerifier verifier =
            new StripeWebhookVerifier(SECRET, StripeWebhookVerifier.DEFAULT_TOLERANCE, Clock.fixed(NOW, ZoneOffset.UTC));
    private final UUID intentId = UUID.randomUUID();
    private final byte[] body = MockStripeServer.eventJson("evt_1", "payment_intent.succeeded",
            new RailPaymentIntent("pi_1", intentId, RailPiStatus.SUCCEEDED, "merchant-a", "USD", 500, 500));

    private String header(long t, byte[] payload) {
        return "t=" + t + ",v1=" + HexFormat.of().formatHex(verifier.sign(t, payload));
    }

    @Test
    void validSignatureYieldsTheEvent() {
        StripeWebhookVerifier.VerifiedEvent event = verifier.verify(header(NOW.getEpochSecond(), body), body);
        assertThat(event.id()).isEqualTo("evt_1");
        assertThat(event.type()).isEqualTo("payment_intent.succeeded");
        assertThat(event.paymentIntent()).hasValueSatisfying(pi -> {
            assertThat(pi.intentId()).isEqualTo(intentId);
            assertThat(pi.chargedMinor()).isEqualTo(500);
        });
    }

    @Test
    void tamperedBodyIsRejected() {
        String header = header(NOW.getEpochSecond(), body);
        byte[] tampered = new String(body, StandardCharsets.UTF_8)
                .replace("\"amount_received\":500", "\"amount_received\":5").getBytes(StandardCharsets.UTF_8);
        assertThat(tampered).isNotEqualTo(body);
        assertRejected(header, tampered, Reason.BAD_SIGNATURE);
    }

    @Test
    void signatureFromAnotherSecretIsRejected() {
        StripeWebhookVerifier other = new StripeWebhookVerifier("whsec_other", StripeWebhookVerifier.DEFAULT_TOLERANCE,
                Clock.fixed(NOW, ZoneOffset.UTC));
        long t = NOW.getEpochSecond();
        assertRejected("t=" + t + ",v1=" + HexFormat.of().formatHex(other.sign(t, body)), body, Reason.BAD_SIGNATURE);
    }

    @Test
    void timestampsBeyondThreeHundredSecondsEitherWayAreRejected() {
        verifier.verify(header(NOW.getEpochSecond() - 300, body), body);
        verifier.verify(header(NOW.getEpochSecond() + 300, body), body);
        assertRejected(header(NOW.getEpochSecond() - 301, body), body, Reason.TIMESTAMP_OUT_OF_TOLERANCE);
        assertRejected(header(NOW.getEpochSecond() + 301, body), body, Reason.TIMESTAMP_OUT_OF_TOLERANCE);
    }

    @Test
    void anyMatchingV1IsAcceptedDuringSecretRotation() {
        long t = NOW.getEpochSecond();
        String header = "t=" + t + ",v1=" + "00".repeat(32) + ",v0=ignored,v1="
                + HexFormat.of().formatHex(verifier.sign(t, body));
        assertThat(verifier.verify(header, body).id()).isEqualTo("evt_1");
    }

    @Test
    void missingAndMalformedHeadersAreRejected() {
        assertRejected(null, body, Reason.MISSING_SIGNATURE);
        assertRejected("  ", body, Reason.MISSING_SIGNATURE);
        assertRejected("garbage", body, Reason.MALFORMED_SIGNATURE);
        assertRejected("t=" + NOW.getEpochSecond(), body, Reason.MALFORMED_SIGNATURE);
        assertRejected("v1=" + "00".repeat(32), body, Reason.MALFORMED_SIGNATURE);
        assertRejected("t=abc,v1=00", body, Reason.MALFORMED_SIGNATURE);
        assertRejected("t=" + NOW.getEpochSecond() + ",v1=zz", body, Reason.MALFORMED_SIGNATURE);
    }

    @Test
    void signedNonEventBodyIsRejected() {
        byte[] notAnEvent = "{\"object\":\"list\"}".getBytes(StandardCharsets.UTF_8);
        assertRejected(header(NOW.getEpochSecond(), notAnEvent), notAnEvent, Reason.MALFORMED_PAYLOAD);
    }

    private void assertRejected(String header, byte[] payload, Reason reason) {
        assertThatThrownBy(() -> verifier.verify(header, payload))
                .isInstanceOfSatisfying(WebhookRejectedException.class, e -> assertThat(e.reason()).isEqualTo(reason));
    }
}
