package dev.alaka.yaksha;

/**
 * Rail-side state of a payment intent, reduced to the four states the two-step confirmation
 * protocol distinguishes (the same four the TLA+ model {@code AlakaInFlight} uses).
 */
public enum RailPiStatus {

    /** Created with {@code confirm=false}; no money has moved and {@code /cancel} is accepted. */
    REQUIRES_CONFIRMATION,

    /** Confirmed and in flight on the network; {@code /cancel} is rejected until it resolves. */
    PROCESSING,

    /** Terminal: the charge succeeded; {@code /cancel} is rejected. */
    SUCCEEDED,

    /** Terminal: canceled; a late {@code /confirm} is rejected and no money ever moves. */
    CANCELED
}
