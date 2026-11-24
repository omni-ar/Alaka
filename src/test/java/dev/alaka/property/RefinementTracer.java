package dev.alaka.property;

import dev.alaka.core.SpendEngine;
import dev.alaka.yaksha.PaymentRailPort;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.RailPaymentIntent;
import dev.alaka.yaksha.RailPiStatus;
import dev.alaka.yaksha.SimulatedPaymentRail;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Records an execution of the engine as a sequence of {@code AlakaInFlight} states, for trace
 * validation by TLC ({@code spec/AlakaInFlightTrace.tla}).
 *
 * <p>A state is recorded after every engine call, after every rail call the engine makes (through
 * {@link #rail}), when a confirm request leaves the gateway, and whenever the test drives a
 * rail-side event and calls {@link #snapshot()}. Runs are sequential, so database and rail are read
 * at a single point in time. Consecutive identical states are recorded once.
 *
 * <p>Refinement mapping, per idempotency key {@code k} of the traced mandate:
 * <ul>
 *   <li>{@code mandate_status}, {@code bal_*}: the {@code spend_mandates} status and the
 *       {@code mandate_balances} row.
 *   <li>{@code intents[k]}: the {@code payment_intents} row ({@code status},
 *       {@code authorized_amount_minor}, {@code captured_amount_minor}); {@code NONE} if there is
 *       none.
 *   <li>{@code rail_pi_state[k]}, {@code rail_charged[k]}: the rail's payment intent, but only once
 *       the intent row has recorded its {@code pi_...}; the spec creates and records in one step
 *       ({@code CreateUnconfirmedPI}). An unrecorded, unconfirmed payment intent cannot charge and
 *       maps to {@code NONE}. A {@code VOIDED} intent that never recorded one maps to
 *       {@code CANCELED}, as in the spec's {@code SafeCancelOnRailAndVoid} from {@code NONE}.
 *   <li>{@code wire_confirm[k]}: {@code IN_FLIGHT} once the engine calls {@code confirm};
 *       {@code DELIVERED} once the rail has processed it (or rejected it), and still
 *       {@code IN_FLIGHT} if the call was lost before the rail applied it.
 *   <li>{@code cancel_resp[k]}: the answer to the last {@code /cancel}: {@code OK} or
 *       {@code REJECTED}.
 * </ul>
 */
public final class RefinementTracer {

    /** One abstract intent. */
    public record AbstractIntent(String state, long amount, long captured) {
    }

    /** One abstract state: the values of the variables of AlakaInFlight, by idempotency key. */
    public record State(
            String mandateStatus,
            long available,
            long held,
            long settled,
            Map<String, AbstractIntent> intents,
            Map<String, String> wire,
            Map<String, String> railState,
            Map<String, Long> railCharged,
            Map<String, String> cancelResp) {
    }

    private final DataSource truth;
    private final SimulatedPaymentRail rail;
    private final Map<UUID, String> wire = new HashMap<>();
    private final Map<UUID, String> cancelResp = new HashMap<>();
    private final List<State> states = new ArrayList<>();
    private UUID mandate;

    /**
     * Creates a tracer.
     *
     * @param truth connections independent of the engine's, for reading the ledger
     * @param rail the simulated rail whose state is read
     */
    public RefinementTracer(DataSource truth, SimulatedPaymentRail rail) {
        this.truth = Objects.requireNonNull(truth, "truth");
        this.rail = Objects.requireNonNull(rail, "rail");
    }

    /**
     * Starts recording for a mandate; records its initial state.
     *
     * @param mandateId the traced mandate
     */
    public void start(UUID mandateId) {
        this.mandate = mandateId;
        snapshot();
    }

    /**
     * Returns the recorded states.
     *
     * @return the trace so far
     */
    public List<State> states() {
        return List.copyOf(states);
    }

    /** Records the current state if it differs from the last one recorded. */
    public void snapshot() {
        if (mandate == null) {
            return;
        }
        State state = read();
        if (states.isEmpty() || !states.get(states.size() - 1).equals(state)) {
            states.add(state);
        }
    }

    /**
     * Returns a view of the engine that records a state after every call.
     *
     * @param engine the engine
     * @return the traced engine
     */
    public SpendEngine engine(SpendEngine engine) {
        return (SpendEngine) Proxy.newProxyInstance(SpendEngine.class.getClassLoader(),
                new Class<?>[] {SpendEngine.class}, (proxy, method, args) -> {
                    try {
                        return method.invoke(engine, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    } finally {
                        snapshot();
                    }
                });
    }

    /**
     * Returns a view of the rail that records confirm and cancel outcomes and a state after every
     * call. Hand it to the engine and use it for test-driven calls.
     *
     * @return the traced rail
     */
    public PaymentRailPort rail() {
        return new PaymentRailPort() {
            @Override
            public RailPaymentIntent createUnconfirmed(
                    String key, UUID intentId, String merchantId, String currency, long amountMinor) {
                try {
                    return rail.createUnconfirmed(key, intentId, merchantId, currency, amountMinor);
                } finally {
                    snapshot();
                }
            }

            @Override
            public RailPaymentIntent confirm(String piId, String key) {
                RailPaymentIntent before = rail.retrieve(piId);
                wire.put(before.intentId(), "IN_FLIGHT");
                snapshot();
                try {
                    RailPaymentIntent after = rail.confirm(piId, key);
                    wire.put(before.intentId(), "DELIVERED");
                    return after;
                } catch (RailException.ConfirmRejected e) {
                    wire.put(before.intentId(), "DELIVERED");
                    throw e;
                } catch (RailException.Timeout e) {
                    if (rail.retrieve(piId).status() != before.status()) {
                        wire.put(before.intentId(), "DELIVERED");   // applied, response lost
                    }
                    throw e;
                } finally {
                    snapshot();
                }
            }

            @Override
            public RailPaymentIntent retrieve(String piId) {
                try {
                    return rail.retrieve(piId);
                } finally {
                    snapshot();
                }
            }

            @Override
            public RailPaymentIntent cancel(String piId) {
                UUID intentId = rail.retrieve(piId).intentId();
                try {
                    RailPaymentIntent canceled = rail.cancel(piId);
                    cancelResp.put(intentId, "OK");
                    return canceled;
                } catch (RailException.CancelRejected e) {
                    cancelResp.put(intentId, "REJECTED");
                    throw e;
                } finally {
                    snapshot();
                }
            }
        };
    }

    private State read() {
        Map<String, AbstractIntent> intents = new TreeMap<>();
        Map<String, String> wires = new TreeMap<>();
        Map<String, String> railStates = new TreeMap<>();
        Map<String, Long> charged = new TreeMap<>();
        Map<String, String> cancels = new TreeMap<>();
        Map<String, RailPaymentIntent> railById = new HashMap<>();
        for (RailPaymentIntent pi : rail.paymentIntents()) {
            railById.put(pi.piId(), pi);
        }
        try (Connection c = truth.getConnection()) {
            String mandateStatus;
            long available;
            long held;
            long settled;
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT m.status::text, b.available_minor, b.held_minor, b.settled_minor"
                            + " FROM spend_mandates m JOIN mandate_balances b USING (mandate_id) WHERE m.mandate_id = ?")) {
                ps.setObject(1, mandate);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    mandateStatus = rs.getString(1);
                    available = rs.getLong(2);
                    held = rs.getLong(3);
                    settled = rs.getLong(4);
                }
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT intent_id, idempotency_key, status::text, authorized_amount_minor, captured_amount_minor,"
                            + " stripe_payment_intent FROM payment_intents WHERE mandate_id = ?")) {
                ps.setObject(1, mandate);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        UUID intentId = rs.getObject(1, UUID.class);
                        String key = rs.getString(2);
                        String status = rs.getString(3);
                        String piId = rs.getString(6);
                        intents.put(key, new AbstractIntent(status, rs.getLong(4), rs.getLong(5)));
                        wires.put(key, wire.getOrDefault(intentId, "NONE"));
                        cancels.put(key, cancelResp.getOrDefault(intentId, "NONE"));
                        RailPaymentIntent pi = piId == null ? null : railById.get(piId);
                        if (pi != null) {
                            railStates.put(key, railState(pi.status()));
                            charged.put(key, pi.status() == RailPiStatus.SUCCEEDED ? pi.chargedMinor() : 0L);
                        } else {
                            railStates.put(key, status.equals("VOIDED") ? "CANCELED" : "NONE");
                            charged.put(key, 0L);
                        }
                    }
                }
            }
            return new State(mandateStatus, available, held, settled, intents, wires, railStates, charged, cancels);
        } catch (SQLException e) {
            throw new IllegalStateException("cannot read the traced state", e);
        }
    }

    private static String railState(RailPiStatus status) {
        return switch (status) {
            case REQUIRES_CONFIRMATION -> "CREATED";
            case PROCESSING -> "PROCESSING";
            case SUCCEEDED -> "SUCCEEDED";
            case CANCELED -> "CANCELED";
        };
    }
}
