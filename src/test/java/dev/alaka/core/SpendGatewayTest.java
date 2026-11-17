package dev.alaka.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariDataSource;
import dev.alaka.mudra.MudraException;
import dev.alaka.mudra.MudraException.InvalidQuote.Reason;
import dev.alaka.mudra.MudraMandateClaims;
import dev.alaka.mudra.MudraQuoteClaims;
import dev.alaka.mudra.MudraQuoteSigner;
import dev.alaka.mudra.MudraQuoteVerifier;
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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Mandate tokens, signed quotes and quote drift in front of the engine, against PostgreSQL 16. */
class SpendGatewayTest {

    private static final String MERCHANT = "merchant-a";
    private static HikariDataSource dataSource;
    private static KeyPair issuer;
    private static KeyPair approver;

    @BeforeAll
    static void setUp() {
        dataSource = NidhiPostgres.shared().newAppDataSource(4);
        issuer = ed25519();
        approver = ed25519();
    }

    @AfterAll
    static void tearDown() {
        dataSource.close();
    }

    private final MudraTokenSigner signer = new MudraTokenSigner("kid-gw", issuer.getPrivate());
    private final MudraTokenVerifier verifier = new MudraTokenVerifier(Map.of("kid-gw", issuer.getPublic()));
    private final MudraQuoteSigner quoteSigner = new MudraQuoteSigner("quote-gw", approver.getPrivate());
    private final MudraQuoteVerifier quoteVerifier = new MudraQuoteVerifier(Map.of("quote-gw", approver.getPublic()));
    private final QuoteDriftEvaluator drift = new QuoteDriftEvaluator(Clock.systemUTC());
    private final String agent = "agent-" + UUID.randomUUID();

    /** notBefore is backdated a minute: the signer's clock may run ahead of the database's NOW(). */
    private MudraMandateClaims claims(UUID mandateId) {
        long now = Instant.now().getEpochSecond();
        return new MudraMandateClaims(mandateId, agent, "USD", 10_000, 5_000, List.of(MERCHANT), now - 60, now + 3_600,
                "kid-gw");
    }

    private MudraQuoteClaims quoteClaims(UUID mandateId, String key, long amount, long expiresAtEpochSec) {
        return new MudraQuoteClaims(mandateId, agent, key, MERCHANT, "USD", amount, 100, expiresAtEpochSec, "quote-gw");
    }

    private String quote(UUID mandateId, String key, long amount) {
        return quoteSigner.sign(quoteClaims(mandateId, key, amount, Instant.now().getEpochSecond() + 300));
    }

    @Test
    void signedMandateIsRegisteredAndSpentWithinItsSignedQuote() {
        SpendEngine engine = SpendEngines.create(RuntimeMode.HARDENED_PESSIMISTIC, dataSource, new SimulatedPaymentRail());
        SpendGateway gateway = new SpendGateway(verifier, quoteVerifier, drift, engine);
        UUID mandateId = UUID.randomUUID();
        String token = signer.sign(claims(mandateId));

        assertThat(gateway.registerMandate(token)).isEqualTo(mandateId);
        SpendResult result = gateway.execute(token, quote(mandateId, "k1", 2_000),
                new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_020));   // +1 % slippage allowed

        assertThat(result.intent().status()).isEqualTo(IntentStatus.CAPTURED);
        assertThat(engine.balances(mandateId)).isEqualTo(new MandateBalances(mandateId, 10_000, 7_980, 0, 2_020));
        // The database still enforces the signed mandate terms: the per-tx cap of 5000.
        assertThatThrownBy(() -> gateway.execute(token, quote(mandateId, "k2", 5_001),
                new SpendRequest(mandateId, agent, "k2", MERCHANT, "USD", 5_001)))
                .isInstanceOf(NidhiException.BudgetExceeded.class);
    }

    @Test
    void forgedTokensAndDriftedQuotesNeverReachTheEngine() {
        SpendGateway gateway = new SpendGateway(verifier, quoteVerifier, drift, untouchableEngine());
        UUID mandateId = UUID.randomUUID();
        String token = signer.sign(claims(mandateId));
        SpendRequest request = new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_000);
        String quote = quote(mandateId, "k1", 2_000);

        String forged = new MudraTokenSigner("kid-gw", ed25519().getPrivate()).sign(claims(mandateId));
        assertThatThrownBy(() -> gateway.registerMandate(forged)).isInstanceOf(MudraException.BadSignature.class);
        assertThatThrownBy(() -> gateway.execute(forged, quote, request))
                .isInstanceOf(MudraException.BadSignature.class);
        assertThatThrownBy(() -> gateway.execute(token, quote,
                new SpendRequest(mandateId, "agent-impostor", "k1", MERCHANT, "USD", 2_000)))
                .isInstanceOf(MudraException.MandateMismatch.class);
        assertThatThrownBy(() -> gateway.execute(token, quote(mandateId, "k1", 1_000), request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class,
                        e -> assertThat(e.reason()).isEqualTo(MudraException.QuoteDrift.Reason.PRICE));
        String expired = quoteSigner.sign(quoteClaims(mandateId, "k1", 2_000, Instant.now().getEpochSecond() - 1));
        assertThatThrownBy(() -> gateway.execute(token, expired, request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class,
                        e -> assertThat(e.reason()).isEqualTo(MudraException.QuoteDrift.Reason.QUOTE_EXPIRED));
    }

    @Test
    void fabricatedReplayedOrUntrustedQuotesNeverReachTheEngine() {
        SpendGateway gateway = new SpendGateway(verifier, quoteVerifier, drift, untouchableEngine());
        UUID mandateId = UUID.randomUUID();
        String token = signer.sign(claims(mandateId));
        String approved = quote(mandateId, "k1", 2_000);

        // The agent raises the approved price to cover a drifted challenge, keeping the signature.
        String inflated = withPayload(approved,
                quoteClaims(mandateId, "k1", 9_000, Instant.now().getEpochSecond() + 300).canonicalBytes());
        assertInvalid(gateway, token, inflated, new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 9_000),
                Reason.BAD_SIGNATURE);
        // The agent replays one approval under a fresh idempotency key to spend it twice.
        assertInvalid(gateway, token, approved, new SpendRequest(mandateId, agent, "k2", MERCHANT, "USD", 2_000),
                Reason.MISMATCH);
        // The agent signs its own approval, or uses the mandate issuer's key: neither is a quote key.
        String selfSigned = new MudraQuoteSigner("quote-gw", ed25519().getPrivate())
                .sign(quoteClaims(mandateId, "k1", 2_000, Instant.now().getEpochSecond() + 300));
        assertInvalid(gateway, token, selfSigned, new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_000),
                Reason.BAD_SIGNATURE);
        String issuerSigned = new MudraQuoteSigner("kid-gw", issuer.getPrivate()).sign(new MudraQuoteClaims(
                mandateId, agent, "k1", MERCHANT, "USD", 2_000, 100, Instant.now().getEpochSecond() + 300, "kid-gw"));
        assertInvalid(gateway, token, issuerSigned, new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_000),
                Reason.UNKNOWN_KEY);
        assertInvalid(gateway, token, null, new SpendRequest(mandateId, agent, "k1", MERCHANT, "USD", 2_000),
                Reason.MALFORMED);
    }

    private static void assertInvalid(SpendGateway gateway, String token, String quote, SpendRequest request,
            Reason reason) {
        assertThatThrownBy(() -> gateway.execute(token, quote, request))
                .isInstanceOfSatisfying(MudraException.InvalidQuote.class, e -> assertThat(e.reason()).isEqualTo(reason));
    }

    private static SpendEngine untouchableEngine() {
        return (SpendEngine) Proxy.newProxyInstance(SpendEngine.class.getClassLoader(),
                new Class<?>[] {SpendEngine.class}, (proxy, method, args) -> {
                    throw new AssertionError("engine (and so Postgres) was reached via " + method.getName());
                });
    }

    private static String withPayload(String token, byte[] payload) {
        String[] parts = token.split("\\.");
        return parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload) + "." + parts[2];
    }

    private static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
