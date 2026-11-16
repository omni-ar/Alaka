-- =============================================================================
-- Alaka -- migrations/002_naive_baseline.sql
--
-- DELIBERATELY UNSAFE BENCHMARK BASELINE. NOT PART OF THE NIDHI KERNEL.
--
-- Bookkeeping for --mode=naive, the anti-pattern the hardened modes are
-- measured against: the application reads how much a mandate has spent, checks
-- the budget in application code, charges the rail, and only then appends a
-- row here. Nothing in this table enforces conservation, idempotency or a
-- state machine: no unique key on (agent_id, idempotency_key), no triggers, no
-- link to the ledger. That absence is the point; it lets concurrent requests
-- pass the same check before any of them records its spend, which is exactly
-- how the baseline overspends (I1) and double-charges (I2) under load.
--
-- It touches no Nidhi object: mandate terms are only read from spend_mandates,
-- and the ledger tables, triggers and privileges of 001 are unchanged (the
-- Milestone 1 suites pin those and keep passing with this file applied).
--
-- Run as alaka_migrator, after 001.
-- =============================================================================

DO $$
BEGIN
    IF current_user <> 'alaka_migrator' THEN
        RAISE EXCEPTION '002_naive_baseline.sql must be applied as alaka_migrator, not %', current_user;
    END IF;
END;
$$;

SET search_path = public;

CREATE TABLE naive_spend_log (
    intent_id               UUID PRIMARY KEY,
    mandate_id              UUID NOT NULL REFERENCES spend_mandates (mandate_id),
    agent_id                TEXT NOT NULL,
    idempotency_key         TEXT NOT NULL,
    request_hash            CHAR(64) NOT NULL,
    merchant_id             TEXT NOT NULL,
    currency                CHAR(3) NOT NULL,
    authorized_amount_minor BIGINT NOT NULL,
    captured_amount_minor   BIGINT NOT NULL,
    status                  TEXT NOT NULL,
    rail_payment_intent     TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Lookups only; deliberately not UNIQUE.
CREATE INDEX naive_spend_log_mandate ON naive_spend_log (mandate_id);
CREATE INDEX naive_spend_log_idempotency ON naive_spend_log (agent_id, idempotency_key);

GRANT SELECT, INSERT ON naive_spend_log TO alaka_app;
