package dev.alaka.yaksha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.http.HttpClient;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * The wire adapter against the real Stripe API in test mode. Runs only when {@code STRIPE_TEST_KEY}
 * holds an {@code sk_test_...} key; it moves no real money ({@code pm_card_visa} is Stripe's test
 * card).
 */
@EnabledIfEnvironmentVariable(named = "STRIPE_TEST_KEY", matches = "sk_test_.+")
class StripeTestModeLiveTest {

    private final StripeHttpPaymentRail rail = new StripeHttpPaymentRail(
            StripeHttpPaymentRail.Config.stripeTestMode(System.getenv("STRIPE_TEST_KEY")), HttpClient.newHttpClient());

    @Test
    void twoStepConfirmationAgainstStripeTestMode() {
        UUID charged = UUID.randomUUID();
        RailPaymentIntent created = rail.createUnconfirmed("create_" + charged, charged, "merchant-live", "USD", 1_234);
        assertThat(created.status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
        assertThat(created.intentId()).isEqualTo(charged);
        assertThat(rail.createUnconfirmed("create_" + charged, charged, "merchant-live", "USD", 1_234).piId())
                .as("Idempotency-Key replay returns the same payment intent").isEqualTo(created.piId());

        RailPaymentIntent confirmed = rail.confirm(created.piId(), "confirm_" + charged);
        assertThat(confirmed.status()).isEqualTo(RailPiStatus.SUCCEEDED);
        assertThat(confirmed.chargedMinor()).isEqualTo(1_234);
        assertThat(rail.retrieve(created.piId()).status()).isEqualTo(RailPiStatus.SUCCEEDED);
        assertThatThrownBy(() -> rail.cancel(created.piId())).isInstanceOfSatisfying(RailException.CancelRejected.class,
                e -> assertThat(e.statusAtRejection()).isEqualTo(RailPiStatus.SUCCEEDED));

        UUID canceled = UUID.randomUUID();
        RailPaymentIntent unconfirmed = rail.createUnconfirmed("create_" + canceled, canceled, "merchant-live", "USD", 500);
        assertThat(rail.cancel(unconfirmed.piId()).status()).isEqualTo(RailPiStatus.CANCELED);
        assertThatThrownBy(() -> rail.confirm(unconfirmed.piId(), "confirm_" + canceled))
                .isInstanceOf(RailException.ConfirmRejected.class);
    }
}
