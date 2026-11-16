package dev.alaka.core.http;

import java.time.Duration;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Configuration of the Alaka gateway ({@code alaka.*}).
 *
 * @param mode runtime mode CLI name: {@code naive}, {@code hardened-pessimistic} or {@code hardened-ssi}
 * @param db runtime database connection; the user must be {@code alaka_app}
 * @param stripe rail and webhook settings
 * @param mudra capability token trust
 * @param recovery recovery grace period and sweeper schedule
 */
@ConfigurationProperties("alaka")
public record AlakaProperties(
        @DefaultValue("hardened-pessimistic") String mode,
        Db db,
        @DefaultValue Stripe stripe,
        Mudra mudra,
        @DefaultValue Recovery recovery) {

    /**
     * @param url JDBC URL
     * @param username database user, which must be {@code alaka_app}
     * @param password password
     * @param poolSize maximum pool size
     */
    public record Db(String url, String username, String password, @DefaultValue("20") int poolSize) {
    }

    /**
     * @param baseUrl Stripe API base URL
     * @param secretKey Stripe secret key
     * @param webhookSecret webhook endpoint signing secret ({@code whsec_...})
     * @param confirmPaymentMethod payment method attached at confirm, or empty
     * @param requestTimeout per-request timeout
     */
    public record Stripe(
            @DefaultValue("https://api.stripe.com") String baseUrl,
            String secretKey,
            String webhookSecret,
            String confirmPaymentMethod,
            @DefaultValue("20s") Duration requestTimeout) {
    }

    /**
     * @param trustedKeys Ed25519 public keys by key id, each base64 of its X.509 SubjectPublicKeyInfo
     */
    public record Mudra(Map<String, String> trustedKeys) {
    }

    /**
     * @param grace how long a request may take before its recovery task falls due
     * @param sweepInterval pause between recovery sweeps; zero disables the in-process sweeper
     */
    public record Recovery(@DefaultValue("30s") Duration grace, @DefaultValue("5s") Duration sweepInterval) {
    }
}
