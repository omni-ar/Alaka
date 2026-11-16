package dev.alaka.mudra;

import dev.alaka.core.SpendRequest;
import java.time.Clock;
import java.util.Objects;

/**
 * Quote-to-settlement drift check, run in memory before Phase 1. A spend cap bounds how much an
 * agent may spend in total; it says nothing about whether this payment is the one the user agreed
 * to. This check does: same merchant, same currency, an unexpired quote, and a price no higher
 * than the quote plus the approved slippage.
 *
 * <p>Quote expiry is judged on the injected clock. It is a property of the quote, checked before
 * anything is reserved; the mandate's own validity window is still judged only by PostgreSQL's
 * {@code NOW()} (I4).
 */
public final class QuoteDriftEvaluator {

    private final Clock clock;

    /**
     * Creates an evaluator.
     *
     * @param clock clock used to judge quote expiry
     */
    public QuoteDriftEvaluator(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Rejects a request that drifted from the approved quote.
     *
     * <p>The price limit is {@code quoted * (10000 + maxSlippageBps) / 10000}. It is compared
     * exactly, by cross-multiplication, so there is no rounding: an amount is accepted if and only
     * if {@code amount * 10000 <= quoted * (10000 + maxSlippageBps)}.
     *
     * @param quote the approved quote
     * @param request the spend request
     * @throws MudraException.QuoteDrift if the merchant, currency or price drifted, or the quote
     *     has expired
     */
    public void check(ApprovedQuote quote, SpendRequest request) {
        if (!quote.merchantId().equals(request.merchantId())) {
            throw new MudraException.QuoteDrift(MudraException.QuoteDrift.Reason.MERCHANT,
                    "quote is for merchant " + quote.merchantId() + ", request pays " + request.merchantId());
        }
        if (!quote.currency().equals(request.currency())) {
            throw new MudraException.QuoteDrift(MudraException.QuoteDrift.Reason.CURRENCY,
                    "quote is in " + quote.currency() + ", request in " + request.currency());
        }
        if (!clock.instant().isBefore(quote.quoteExpiresAt())) {
            throw new MudraException.QuoteDrift(MudraException.QuoteDrift.Reason.QUOTE_EXPIRED,
                    "quote expired at " + quote.quoteExpiresAt());
        }
        long scaledAmount = Math.multiplyExact(request.amountMinor(), 10_000L);
        long scaledLimit = Math.multiplyExact(quote.quotedAmountMinor(), 10_000L + quote.maxSlippageBps());
        if (scaledAmount > scaledLimit) {
            throw new MudraException.QuoteDrift(MudraException.QuoteDrift.Reason.PRICE,
                    "amount " + request.amountMinor() + " exceeds quote " + quote.quotedAmountMinor() + " plus "
                            + quote.maxSlippageBps() + " bps slippage");
        }
    }
}
