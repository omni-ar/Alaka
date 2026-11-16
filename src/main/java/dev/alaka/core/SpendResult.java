package dev.alaka.core;

import dev.alaka.nidhi.IntentView;
import java.util.Objects;

/**
 * Result of {@link SpendEngine#reserve} or {@link SpendEngine#execute}.
 *
 * @param intent the intent as it stands after the call
 * @param replayed {@code true} if the idempotency key had already been used with an identical
 *     payload and the intent had reached a terminal state, so nothing was executed and the stored
 *     outcome is returned
 */
public record SpendResult(IntentView intent, boolean replayed) {

    public SpendResult {
        Objects.requireNonNull(intent, "intent");
    }
}
