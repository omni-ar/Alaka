package dev.alaka.core;

import dev.alaka.nidhi.IntentView;
import java.util.Objects;
import java.util.Optional;

/**
 * Result of {@link SpendEngine#applyRailEvent}.
 *
 * @param disposition what was done with the event
 * @param intent the intent after the event, if the event concerns a known intent
 */
public record RailEventOutcome(Disposition disposition, Optional<IntentView> intent) {

    /** What was done with an event. */
    public enum Disposition {
        /** The event was recorded and applied. */
        APPLIED,
        /** The event id had already been processed; nothing changed. */
        DUPLICATE,
        /** The event was recorded but needs no action (unknown payment intent or event type). */
        IGNORED
    }

    public RailEventOutcome {
        Objects.requireNonNull(disposition, "disposition");
        Objects.requireNonNull(intent, "intent");
    }
}
