package dev.alaka.mudra;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.alaka.core.SpendRequest;
import dev.alaka.mudra.MudraException.QuoteDrift.Reason;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class QuoteDriftEvaluatorTest {

    private static final Instant NOW = Instant.parse("2026-11-16T10:00:00Z");
    private final QuoteDriftEvaluator evaluator = new QuoteDriftEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));

    private static SpendRequest request(String merchant, String currency, long amount) {
        return new SpendRequest(UUID.randomUUID(), "agent", "key", merchant, currency, amount);
    }

    private static ApprovedQuote quote(long amount, int bps, Instant expires) {
        return new ApprovedQuote("merchant-a", "USD", amount, bps, expires);
    }

    @ParameterizedTest(name = "quote {0} + {1} bps: amount {2} accepted={3}")
    @CsvSource({
        "10000, 50, 10050, true",   // exactly at the slippage limit
        "10000, 50, 10051, false",  // one unit beyond it
        "10000, 0, 10000, true",
        "10000, 0, 10001, false",
        "999, 50, 1003, true",      // limit is 1003.995: no rounding up
        "999, 50, 1004, false",
        "10000, 50, 1, true",       // paying less than quoted is never drift
    })
    void slippageBoundaryIsExact(long quoted, int bps, long amount, boolean accepted) {
        ApprovedQuote quote = quote(quoted, bps, NOW.plusSeconds(60));
        SpendRequest request = request("merchant-a", "USD", amount);
        if (accepted) {
            assertThatCode(() -> evaluator.check(quote, request)).doesNotThrowAnyException();
        } else {
            assertThatThrownBy(() -> evaluator.check(quote, request))
                    .isInstanceOfSatisfying(MudraException.QuoteDrift.class, e -> assertReason(e, Reason.PRICE));
        }
    }

    @Test
    void merchantAndCurrencyDriftAreRejected() {
        ApprovedQuote quote = quote(1_000, 100, NOW.plusSeconds(60));
        assertThatThrownBy(() -> evaluator.check(quote, request("merchant-b", "USD", 1_000)))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class, e -> assertReason(e, Reason.MERCHANT));
        assertThatThrownBy(() -> evaluator.check(quote, request("merchant-a", "EUR", 1_000)))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class, e -> assertReason(e, Reason.CURRENCY));
    }

    @Test
    void expiredQuoteIsRejectedFromItsExpiryInstantOn() {
        SpendRequest request = request("merchant-a", "USD", 1_000);
        assertThatCode(() -> evaluator.check(quote(1_000, 0, NOW.plusMillis(1)), request)).doesNotThrowAnyException();
        assertThatThrownBy(() -> evaluator.check(quote(1_000, 0, NOW), request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class, e -> assertReason(e, Reason.QUOTE_EXPIRED));
        assertThatThrownBy(() -> evaluator.check(quote(1_000, 0, NOW.minusSeconds(1)), request))
                .isInstanceOfSatisfying(MudraException.QuoteDrift.class, e -> assertReason(e, Reason.QUOTE_EXPIRED));
    }

    @Test
    void quoteBoundsAreValidated() {
        assertThatThrownBy(() -> quote(0, 0, NOW)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> quote(1, -1, NOW)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> quote(1, 10_001, NOW)).isInstanceOf(IllegalArgumentException.class);
    }

    private static void assertReason(MudraException.QuoteDrift e, Reason expected) {
        org.assertj.core.api.Assertions.assertThat(e.reason()).isEqualTo(expected);
    }
}
