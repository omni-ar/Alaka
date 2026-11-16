package dev.alaka.core;

import dev.alaka.nidhi.TransactionRunner;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailPaymentIntent;
import java.util.Objects;
import java.util.UUID;

/**
 * Decorates the rail so that calling it while a database transaction is open on the same thread
 * fails immediately. This turns the protocol's central rule (never hold a transaction, connection
 * or row lock across a network call) from a convention into a run-time check.
 */
final class RailCallGuard implements PaymentRailPort {

    private final PaymentRailPort rail;

    RailCallGuard(PaymentRailPort rail) {
        this.rail = Objects.requireNonNull(rail, "rail");
    }

    @Override
    public RailPaymentIntent createUnconfirmed(
            String idempotencyKey, UUID intentId, String merchantId, String currency, long amountMinor) {
        checkNoTransaction("createUnconfirmed");
        return rail.createUnconfirmed(idempotencyKey, intentId, merchantId, currency, amountMinor);
    }

    @Override
    public RailPaymentIntent confirm(String piId, String idempotencyKey) {
        checkNoTransaction("confirm");
        return rail.confirm(piId, idempotencyKey);
    }

    @Override
    public RailPaymentIntent retrieve(String piId) {
        checkNoTransaction("retrieve");
        return rail.retrieve(piId);
    }

    @Override
    public RailPaymentIntent cancel(String piId) {
        checkNoTransaction("cancel");
        return rail.cancel(piId);
    }

    private static void checkNoTransaction(String call) {
        if (TransactionRunner.inTransaction()) {
            throw new IllegalStateException("Rail call " + call + " attempted inside a database transaction");
        }
    }
}
