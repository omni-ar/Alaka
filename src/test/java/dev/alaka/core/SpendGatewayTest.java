package dev.alaka.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.mudra.ApprovedQuote;
import dev.alaka.mudra.MudraException;
import dev.alaka.mudra.MudraMandateClaims;
import dev.alaka.mudra.MudraTokenSigner;
import dev.alaka.mudra.MudraTokenVerifier;
import dev.alaka.mudra.QuoteDriftEvaluator;
import dev.alaka.nidhi.IntentStatus;
import dev.alaka.nidhi.MandateBalances;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.testsupport.NidhiPostgres;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Token verification and quote drift in front of the engine, against PostgreSQL 16. */
class SpendGatewayTest {

    private static final String MERCHANT = "merchant-a";
    private static HikariDataSource dataSource;
    private static KeyPair issuer;

    @BeforeAll
    static void setUp() throws NoSuchAlgorithmException {
        dataSource = NidhiPostgres.shared().newAppDataSource(4);
        issuer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    @AfterAll
    static void tearDown() {
        dataSource.close();
    }

    private final MudraTokenSigner signer = new MudraTokenSigner("kid-gw", issuer.getPrivate());
    private final MudraTokenVerifier verifier = new MudraTokenVerifier(Map.of("kid-gw", issuer.getPublic()));
    private final QuoteDriftEvaluator drift = new QuoteDriftEvaluator(Clock.systemUTC());
    private final String agent = "agent-" + UUID.randomUUID();

    /** notBefore is backdated a minute: the signer's clock may run ahead of the database's NOW(). */
    private MudraMandateClaims claims(UUID mandateId) {
        long now = Instant.now().getEpochSecond();
        return new MudraMandateClaims(mandateId, agent, "USD", 10_000, 5_000, List.of(MERCHANT), now - 60, now + 3_600,
                "kid-gw");
    }

    private static ApprovedQuote quote(long amount) {
        return new ApprovedQuote(MERCHANT, "USD", amount, 100, Instant.now().plusSeconds(300));
    }

    @Test
    void signedMandateIsRegisteredAndSpentWithinItsQuote() {
        SpendEngine engine = SpendEngines.create(RuntimeMode.HARDENED_PESSIMISTIC, dataSource, new SimulatedPaymentRail());
        SpendGateway gateway = new SpendGateway(verifier, drift, engine);
        UUID mandateId = UUID.randomUUID();
        String token = signer.sign(claims(mandateId));

        assertThat(gateway.registerMandate(token)).isEqualTo(mandateId);
        SpendResult result = gateway.execute(token, quote(2_000),
                new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_020));   // +1 % slippage allowed

        assertThat(result.intent().status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(engine.balances(mandateId)).isEqualTo(new MandateBalances(mandateId, 10_000, 7_980, 0, 2_020));
        // The database still enforces the signed terms: the per-tx cap of 5000.
        assertThatThrownBy(() -> gateway.execute(token, quote(5_001),
                new SpendRequest(mandateId, agent, "k2", MERCHANT, "USD", 5_001)))
                .isInstanceOf(NidhiException.BudgetExceeded.class);
    }

    @Test
    void forgedTokensAndDriftedQuotesNeverReachTheEngine() {
        SpendEngine untouchable = (SpendEngine) Proxy.newProxyInstance(SpendEngine.class.getClassLoader(),
                new Class<?>[] {SpendEngine.class}, (proxy, method, args) -> {
                    throw new AssertionError("engine (and so Postgres) was reached via " + method.getName());
                });
        SpendGateway gateway = new SpendGateway(verifier, drift, untouchable);
        UUID mandateId = UUID.randomUUID();
        String token = signer.sign(claims(mandateId));
        SpendRequest request = new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_000);

        String forged = new MudraTokenSigner("kid-gw", ed25519().getPrivate()).sign(claims(mandateId));
        assertThatThrownBy(() -> gateway.registerMandate(forged)).isInstanceOf(MudraException.BadSignature.class);
        assertThatThrownBy(() -> gateway.execute(forged, quote(2_000), request))
                .isInstanceOf(MudraException.BadSignature.class);
        assertThatThrownBy(() -> gateway.execute(token, quote(2_000),
                new SpendRequest(UUID.randomUUID(), agent, "k1", MERCHANT, "USD", 2_000)))
                .isInstanceOf(MudraException.MandateMismatch.class);
        assertThatThrownBy(() -> gateway.execute(token, quote(2_000),
                new SpendRequest(mandateId, "agent-impostor", "k1", MERCHANT, "USD", 2_000)))
                .isInstanceOf(MudraException.MandateMismatch.class);
        assertThatThrownBy(() -> gateway.execute(token, quote(1_000), request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class,
                        e -> assertThat(e.reason()).isEqualTo(MudraException.QuoteDrift.Reason.PRICE));
        assertThatThrownBy(() -> gateway.execute(token,
                new ApprovedQuote(MERCHANT, "USD", 2_000, 0, Instant.now().minusSeconds(1)), request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class,
                        e -> assertThat(e.reason()).isEqualTo(MudraException.QuoteDrift.Reason.QUOTE_EXPIRED));
    }

    private static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
