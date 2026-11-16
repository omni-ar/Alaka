package dev.alaka.core.http;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.core.EngineOptions;
import dev.alaka.core.RuntimeMode;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendEngines;
import dev.alaka.core.SpendGateway;
import dev.alaka.mudra.MudraTokenVerifier;
import dev.alaka.mudra.QuoteDriftEvaluator;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.StripeHttpPaymentRail;
import dev.alaka.yaksha.StripeWebhookHandler;
import dev.alaka.yaksha.StripeWebhookVerifier;
import dev.alaka.yaksha.YakshaRecoverySweeper;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Wires the gateway from {@link AlakaProperties}. */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AlakaProperties.class)
public class AlakaConfiguration {

    /** The only database role the gateway runs as. */
    static final String RUNTIME_ROLE = "alaka_app";

    @Bean(destroyMethod = "close")
    HikariDataSource alakaDataSource(AlakaProperties properties) {
        AlakaProperties.Db db = properties.db();
        if (db == null || !RUNTIME_ROLE.equals(db.username())) {
            throw new IllegalStateException("alaka.db.username must be " + RUNTIME_ROLE
                    + ": the gateway never runs as a migration or superuser role");
        }
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(db.url());
        config.setUsername(db.username());
        config.setPassword(db.password());
        config.setMaximumPoolSize(db.poolSize());
        config.setPoolName("alaka-app");
        return new HikariDataSource(config);
    }

    @Bean
    PaymentRailPort paymentRail(AlakaProperties properties) {
        AlakaProperties.Stripe stripe = properties.stripe();
        String paymentMethod = stripe.confirmPaymentMethod() == null || stripe.confirmPaymentMethod().isBlank()
                ? null : stripe.confirmPaymentMethod();
        return new StripeHttpPaymentRail(
                new StripeHttpPaymentRail.Config(URI.create(stripe.baseUrl()), stripe.secretKey(),
                        stripe.requestTimeout(), paymentMethod),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    @Bean
    SpendEngine spendEngine(AlakaProperties properties, HikariDataSource alakaDataSource, PaymentRailPort paymentRail) {
        return SpendEngines.create(RuntimeMode.fromCliName(properties.mode()), alakaDataSource, paymentRail,
                new EngineOptions(properties.recovery().grace()));
    }

    @Bean
    MudraTokenVerifier mudraTokenVerifier(AlakaProperties properties) throws GeneralSecurityException {
        Map<String, PublicKey> keys = new HashMap<>();
        KeyFactory ed25519 = KeyFactory.getInstance("Ed25519");
        for (Map.Entry<String, String> entry : properties.mudra().trustedKeys().entrySet()) {
            keys.put(entry.getKey(),
                    ed25519.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(entry.getValue()))));
        }
        return new MudraTokenVerifier(keys);
    }

    @Bean
    SpendGateway spendGateway(MudraTokenVerifier mudraTokenVerifier, SpendEngine spendEngine) {
        return new SpendGateway(mudraTokenVerifier, new QuoteDriftEvaluator(Clock.systemUTC()), spendEngine);
    }

    @Bean
    StripeWebhookHandler stripeWebhookHandler(AlakaProperties properties, SpendEngine spendEngine) {
        return new StripeWebhookHandler(new StripeWebhookVerifier(properties.stripe().webhookSecret(),
                StripeWebhookVerifier.DEFAULT_TOLERANCE, Clock.systemUTC()), spendEngine);
    }

    @Bean
    SweeperLoop sweeperLoop(AlakaProperties properties, HikariDataSource alakaDataSource, SpendEngine spendEngine) {
        YakshaRecoverySweeper sweeper = spendEngine.mode() == RuntimeMode.NAIVE
                ? null
                : new YakshaRecoverySweeper(alakaDataSource, spendEngine, YakshaRecoverySweeper.Options.DEFAULTS);
        return new SweeperLoop(sweeper, properties.recovery().sweepInterval());
    }
}
