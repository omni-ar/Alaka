-- =============================================================================
-- Alaka / nidhi -- 001_init_nidhi_ledger.sql
-- The double-entry PostgreSQL 16 ledger kernel: 3-bucket mandate partition
-- (MANDATE_AVAILABLE / MANDATE_HELD / MANDATE_SETTLED), DEFERRABLE INITIALLY
-- DEFERRED conservation triggers, per-transition bucket routing rules, composite
-- scope foreign keys, and the runtime grants for alaka_app.
--
-- HOW TO APPLY: as alaka_migrator (never a superuser), after 000_roles.sql:
--   psql -v ON_ERROR_STOP=1 --single-transaction -U alaka_migrator -d alaka -f 001_init_nidhi_ledger.sql
-- Not re-runnable (it is a versioned migration); --single-transaction makes a
-- failed apply leave nothing behind. Pure SQL, no psql meta-commands.
--
-- Starting point: CLAUDE.md Artifact B, kept verbatim except for the changes
-- tagged [NIDHI-Dn] below. Every tag is explained where it occurs.
--
--   [NIDHI-D1]  pgcrypto dropped (gen_random_uuid() is core since PG13).
--   [NIDHI-D2]  Preamble: must run as alaka_migrator; objects pinned to public.
--   [NIDHI-D3]  The two trigger functions that write tables the app may not
--               write (ledger_accounts, mandate_balances) are SECURITY DEFINER.
--   [NIDHI-D4]  Every trigger function has a pinned search_path.
--   [NIDHI-D5]  mandate_balances write guard additionally requires the writer
--               to be the table owner (pg_trigger_depth() alone is forgeable
--               by any role that can attach a trigger to a table it owns).
--   [NIDHI-D6]  SG002 is now actually raised (intent currency <> mandate currency).
--   [NIDHI-D7]  HOLE FIX: signed mandate terms allowed_merchants / not_before /
--               expires_at / token_kid are immutable (SG006).
--   [NIDHI-D8]  HOLE FIX: rail idempotency keys immutable, stripe_payment_intent
--               write-once, captured_amount_minor frozen outside the transition
--               into CAPTURED (SG006).
--   [NIDHI-D9]  HOLE FIX: a CAPTURE / VOID ledger transaction is only valid if
--               the intent is in the matching terminal state at COMMIT (SG005).
--   [NIDHI-D10] EXECUTE on trigger functions revoked from PUBLIC; least-privilege
--               GRANTs for alaka_app.
--
-- Custom SQLSTATE codes:
-- SG001: Mandate inactive, expired, or agent mismatch (I4)
-- SG002: Currency or budget mismatch
-- SG003: Mandate per-tx or total budget exceeded (I1)
-- SG004: Illegal state machine transition or initial state (I5)
-- SG005: Unbalanced double-entry transaction or illegal bucket routing (I3)
-- SG006: Immutable audit row mutation attempted
-- SG007: Direct mutation of materialized balance bypassing ledger_postings
-- SG008: Merchant not in mandate allowlist
-- =============================================================================

-- [NIDHI-D2] Ownership is part of the security model: the SECURITY DEFINER
-- functions below run with the privileges of whoever applies this file, so it
-- must be the dedicated non-superuser owner role and nothing else.
DO $preamble$
BEGIN
    IF current_user <> 'alaka_migrator' THEN
        RAISE EXCEPTION '001_init_nidhi_ledger.sql must be applied as role alaka_migrator (current_user is %); apply 000_roles.sql as a superuser first',
            current_user USING ERRCODE = '42501';
    END IF;
END
$preamble$;

SET search_path = public;

-- [NIDHI-D1] No CREATE EXTENSION pgcrypto: gen_random_uuid() is built into
-- PostgreSQL 13+, and the owner role should not need extension privileges.

CREATE TYPE mandate_status AS ENUM ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED', 'CONSUMED');
CREATE TYPE intent_status AS ENUM ('RESERVED', 'CONFIRMING', 'AUTHORIZED', 'CAPTURED', 'VOIDED', 'FAILED');
CREATE TYPE account_bucket AS ENUM ('MANDATE_AVAILABLE', 'MANDATE_HELD', 'MANDATE_SETTLED');
CREATE TYPE entry_direction AS ENUM ('DEBIT', 'CREDIT');

CREATE TABLE spend_mandates (
    mandate_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            TEXT NOT NULL,
    currency            CHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    total_budget_minor  BIGINT NOT NULL CHECK (total_budget_minor > 0),
    max_per_tx_minor    BIGINT NOT NULL CHECK (max_per_tx_minor > 0 AND max_per_tx_minor <= total_budget_minor),
    allowed_merchants   TEXT[] NOT NULL CHECK (cardinality(allowed_merchants) > 0),
    status              mandate_status NOT NULL DEFAULT 'ACTIVE',
    not_before          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    token_kid           TEXT NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (expires_at > not_before),
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
    UNIQUE (mandate_id, currency),
    UNIQUE (mandate_id, currency, total_budget_minor)
);

CREATE TABLE mandate_balances (
    mandate_id          UUID PRIMARY KEY,
    currency            CHAR(3) NOT NULL,
    total_budget_minor  BIGINT NOT NULL CHECK (total_budget_minor > 0),
    available_minor     BIGINT NOT NULL,
    held_minor          BIGINT NOT NULL,
    settled_minor       BIGINT NOT NULL,
    version             BIGINT NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_balance_mandate_exact
        FOREIGN KEY (mandate_id, currency, total_budget_minor)
        REFERENCES spend_mandates (mandate_id, currency, total_budget_minor)
        ON DELETE RESTRICT
);

CREATE TABLE ledger_accounts (
    account_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mandate_id          UUID NOT NULL,
    bucket              account_bucket NOT NULL,
    currency            CHAR(3) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (mandate_id, bucket),
    UNIQUE (account_id, mandate_id, currency),
    CONSTRAINT fk_account_mandate_currency
        FOREIGN KEY (mandate_id, currency)
        REFERENCES spend_mandates (mandate_id, currency)
        ON DELETE RESTRICT
);

CREATE TABLE payment_intents (
    intent_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mandate_id              UUID NOT NULL,
    agent_id                TEXT NOT NULL,
    idempotency_key         TEXT NOT NULL,
    request_hash            CHAR(64) NOT NULL,
    merchant_id             TEXT NOT NULL,
    currency                CHAR(3) NOT NULL,
    authorized_amount_minor BIGINT NOT NULL CHECK (authorized_amount_minor > 0),
    captured_amount_minor   BIGINT NOT NULL DEFAULT 0 CHECK (
        captured_amount_minor >= 0 AND captured_amount_minor <= authorized_amount_minor
    ),
    status                  intent_status NOT NULL DEFAULT 'RESERVED',
    rail_create_idemp_key   TEXT NOT NULL UNIQUE,
    rail_confirm_idemp_key  TEXT NOT NULL UNIQUE,
    stripe_payment_intent   TEXT UNIQUE,
    failure_code            TEXT,
    version                 BIGINT NOT NULL DEFAULT 1,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_agent_idempotency UNIQUE (agent_id, idempotency_key),
    UNIQUE (intent_id, mandate_id, currency),
    CONSTRAINT fk_intent_mandate_currency
        FOREIGN KEY (mandate_id, currency)
        REFERENCES spend_mandates (mandate_id, currency)
        ON DELETE RESTRICT,
    CONSTRAINT chk_captured_amount_state CHECK (
        (status = 'CAPTURED' AND captured_amount_minor > 0) OR
        (status <> 'CAPTURED' AND captured_amount_minor = 0)
    )
);

CREATE TABLE ledger_transactions (
    tx_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    intent_id           UUID NOT NULL,
    mandate_id          UUID NOT NULL,
    currency            CHAR(3) NOT NULL,
    transition_type     TEXT NOT NULL CHECK (transition_type IN ('RESERVE', 'CAPTURE', 'VOID')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (intent_id, transition_type),
    UNIQUE (tx_id, mandate_id, currency),
    CONSTRAINT fk_tx_intent_mandate_currency
        FOREIGN KEY (intent_id, mandate_id, currency)
        REFERENCES payment_intents (intent_id, mandate_id, currency)
        ON DELETE RESTRICT
);

CREATE TABLE ledger_postings (
    posting_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tx_id               UUID NOT NULL,
    mandate_id          UUID NOT NULL,
    account_id          UUID NOT NULL,
    currency            CHAR(3) NOT NULL,
    direction           entry_direction NOT NULL,
    amount_minor        BIGINT NOT NULL CHECK (amount_minor > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tx_id, account_id),
    CONSTRAINT fk_posting_tx_scope
        FOREIGN KEY (tx_id, mandate_id, currency)
        REFERENCES ledger_transactions (tx_id, mandate_id, currency)
        ON DELETE RESTRICT,
    CONSTRAINT fk_posting_account_scope
        FOREIGN KEY (account_id, mandate_id, currency)
        REFERENCES ledger_accounts (account_id, mandate_id, currency)
        ON DELETE RESTRICT
);

CREATE TABLE outbox_tasks (
    task_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    intent_id           UUID NOT NULL UNIQUE REFERENCES payment_intents(intent_id) ON DELETE RESTRICT,
    status              TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'DEAD_LETTER')),
    attempts            INT NOT NULL DEFAULT 0,
    next_attempt_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until        TIMESTAMPTZ,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE processed_webhooks (
    provider_event_id   TEXT PRIMARY KEY,
    intent_id           UUID REFERENCES payment_intents(intent_id),
    event_type          TEXT NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- Mandate initialisation: 3 bucket accounts + the materialised balance row.
-- [NIDHI-D3] SECURITY DEFINER: alaka_app has no INSERT on ledger_accounts or
-- mandate_balances, so this is the only way those rows can come into existence
-- for a mandate the app creates. Runs as the owner (alaka_migrator).
-- [NIDHI-D4] search_path pinned so no caller-controlled schema can shadow a
-- table or operator inside a definer-rights body (pg_temp is searched last).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_init_mandate_ledger()
RETURNS TRIGGER LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO ledger_accounts (mandate_id, bucket, currency) VALUES
        (NEW.mandate_id, 'MANDATE_AVAILABLE', NEW.currency),
        (NEW.mandate_id, 'MANDATE_HELD', NEW.currency),
        (NEW.mandate_id, 'MANDATE_SETTLED', NEW.currency);

    INSERT INTO mandate_balances (
        mandate_id, currency, total_budget_minor, available_minor, held_minor, settled_minor
    ) VALUES (
        NEW.mandate_id, NEW.currency, NEW.total_budget_minor, NEW.total_budget_minor, 0, 0
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER after_mandate_insert_init
AFTER INSERT ON spend_mandates
FOR EACH ROW EXECUTE FUNCTION trg_init_mandate_ledger();

CREATE OR REPLACE FUNCTION trg_enforce_mandate_fsm()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- [NIDHI-D7] HOLE FIX. The baseline froze only agent / currency / budget /
    -- per-tx cap. The merchant allowlist, the validity window and the signing
    -- key id are equally part of the Ed25519-signed capability, and leaving
    -- them mutable let a plain UPDATE defeat SG008 (widen the allowlist) and
    -- I4 (push expires_at forward on a lapsed mandate). All signed terms are
    -- now immutable; only status / revoked_at / revocation_reason may change.
    IF OLD.agent_id <> NEW.agent_id
       OR OLD.currency <> NEW.currency
       OR OLD.total_budget_minor <> NEW.total_budget_minor
       OR OLD.max_per_tx_minor <> NEW.max_per_tx_minor
       OR OLD.allowed_merchants <> NEW.allowed_merchants
       OR OLD.not_before <> NEW.not_before
       OR OLD.expires_at <> NEW.expires_at
       OR OLD.token_kid <> NEW.token_kid THEN
        RAISE EXCEPTION 'IMMUTABLE_MANDATE_TERMS: Cannot alter core financial bounds on mandate %', OLD.mandate_id
            USING ERRCODE = 'SG006';
    END IF;

    IF OLD.status IN ('REVOKED', 'EXPIRED', 'CONSUMED') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'I4_I5_VIOLATION: Cannot transition mandate % out of terminal state % to %',
            OLD.mandate_id, OLD.status, NEW.status
            USING ERRCODE = 'SG004';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_mandate_state_machine
BEFORE UPDATE ON spend_mandates
FOR EACH ROW EXECUTE FUNCTION trg_enforce_mandate_fsm();

-- -----------------------------------------------------------------------------
-- mandate_balances write guard (defence in depth behind the privilege system).
-- Deliberately SECURITY INVOKER: current_user must reflect the caller's context.
-- [NIDHI-D5] pg_trigger_depth() > 1 only proves "some trigger is on the stack".
-- Any role that owns a table (a temporary one is enough) can put its own
-- trigger there. The legitimate writers are the two SECURITY DEFINER functions
-- in this file, which execute as the table owner, so the guard now also
-- requires current_user to be the owner of mandate_balances. For a deployment
-- where one role owns the schema and runs the app this degrades to exactly the
-- baseline check.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_guard_mandate_balances_direct_write()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF pg_trigger_depth() <= 1
       OR current_user::text IS DISTINCT FROM
          (SELECT pg_catalog.pg_get_userbyid(c.relowner)::text FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID) THEN
        RAISE EXCEPTION 'DIRECT_BALANCE_MUTATION_FORBIDDEN: mandate_balances is derived strictly from ledger_postings'
            USING ERRCODE = 'SG007';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER guard_mandate_balances_write
BEFORE INSERT OR UPDATE ON mandate_balances
FOR EACH ROW EXECUTE FUNCTION trg_guard_mandate_balances_direct_write();

CREATE OR REPLACE FUNCTION trg_forbid_mutation()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_TABLE: Operation % forbidden on %', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'SG006';
END;
$$;

CREATE TRIGGER forbid_mandate_balances_delete BEFORE DELETE ON mandate_balances FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
CREATE TRIGGER forbid_mandates_delete BEFORE DELETE ON spend_mandates FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
CREATE TRIGGER forbid_postings_mutation BEFORE UPDATE OR DELETE ON ledger_postings FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
CREATE TRIGGER forbid_transactions_mutation BEFORE UPDATE OR DELETE ON ledger_transactions FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
CREATE TRIGGER forbid_accounts_mutation BEFORE UPDATE OR DELETE ON ledger_accounts FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
CREATE TRIGGER forbid_intents_delete BEFORE DELETE ON payment_intents FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();

CREATE OR REPLACE FUNCTION trg_verify_intent_on_insert()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_mandate spend_mandates%ROWTYPE;
BEGIN
    IF NEW.status <> 'RESERVED' THEN
        RAISE EXCEPTION 'I5_VIOLATION: New payment_intent must start in RESERVED state, got %', NEW.status
            USING ERRCODE = 'SG004';
    END IF;

    SELECT * INTO v_mandate
      FROM spend_mandates
     WHERE mandate_id = NEW.mandate_id
       FOR SHARE;

    IF v_mandate.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'I4_VIOLATION: Mandate % is % (not ACTIVE)', NEW.mandate_id, v_mandate.status
            USING ERRCODE = 'SG001';
    END IF;

    IF NOW() < v_mandate.not_before OR NOW() >= v_mandate.expires_at THEN
        RAISE EXCEPTION 'I4_VIOLATION: Mandate % outside valid time window', NEW.mandate_id
            USING ERRCODE = 'SG001';
    END IF;

    IF NEW.agent_id <> v_mandate.agent_id THEN
        RAISE EXCEPTION 'AGENT_MISMATCH: Intent agent % != Mandate agent %', NEW.agent_id, v_mandate.agent_id
            USING ERRCODE = 'SG001';
    END IF;

    -- [NIDHI-D6] SG002 was declared by the baseline but never raised: an intent
    -- in the wrong currency only surfaced as a generic 23503 from
    -- fk_intent_mandate_currency. Name it here, ahead of the FK. (Postings are
    -- untouched: a cross-currency / cross-mandate *posting* is still a
    -- composite-FK violation, 23503.)
    IF NEW.currency <> v_mandate.currency THEN
        RAISE EXCEPTION 'CURRENCY_MISMATCH: Intent currency % != Mandate % currency %',
            NEW.currency, NEW.mandate_id, v_mandate.currency
            USING ERRCODE = 'SG002';
    END IF;

    IF NOT (NEW.merchant_id = ANY(v_mandate.allowed_merchants)) THEN
        RAISE EXCEPTION 'MERCHANT_NOT_ALLOWED: Merchant % is not in mandate % allowlist',
            NEW.merchant_id, NEW.mandate_id
            USING ERRCODE = 'SG008';
    END IF;

    IF NEW.authorized_amount_minor > v_mandate.max_per_tx_minor THEN
        RAISE EXCEPTION 'I1_VIOLATION: Intent amount % exceeds per-tx cap %',
            NEW.authorized_amount_minor, v_mandate.max_per_tx_minor
            USING ERRCODE = 'SG003';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_intent_insert_rules
BEFORE INSERT ON payment_intents
FOR EACH ROW EXECUTE FUNCTION trg_verify_intent_on_insert();

CREATE OR REPLACE FUNCTION trg_enforce_intent_fsm()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    -- [NIDHI-D8] HOLE FIX, last four predicates. In the baseline a same-status
    -- UPDATE returned early with no checks beyond the first seven columns, so:
    --   * captured_amount_minor of a CAPTURED intent could be rewritten after
    --     its CAPTURE postings were verified (intent and ledger then disagree);
    --   * stripe_payment_intent could be nulled or swapped on a CONFIRMING
    --     intent, defeating the "CONFIRMING requires a recorded pi_" rule that
    --     crash recovery (Trap 1) depends on;
    --   * the deterministic rail idempotency keys could be replaced (I2).
    -- The rail keys are now immutable, stripe_payment_intent is write-once, and
    -- captured_amount_minor may change only in the transition into CAPTURED.
    IF OLD.mandate_id <> NEW.mandate_id
       OR OLD.agent_id <> NEW.agent_id
       OR OLD.idempotency_key <> NEW.idempotency_key
       OR OLD.request_hash <> NEW.request_hash
       OR OLD.merchant_id <> NEW.merchant_id
       OR OLD.currency <> NEW.currency
       OR OLD.authorized_amount_minor <> NEW.authorized_amount_minor
       OR OLD.rail_create_idemp_key <> NEW.rail_create_idemp_key
       OR OLD.rail_confirm_idemp_key <> NEW.rail_confirm_idemp_key
       OR (OLD.stripe_payment_intent IS NOT NULL
           AND NEW.stripe_payment_intent IS DISTINCT FROM OLD.stripe_payment_intent)
       OR (OLD.status = NEW.status
           AND OLD.captured_amount_minor <> NEW.captured_amount_minor) THEN
        RAISE EXCEPTION 'IMMUTABLE_INTENT_FIELDS: Cannot modify core fields on intent %', OLD.intent_id
            USING ERRCODE = 'SG006';
    END IF;

    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF OLD.status IN ('CAPTURED', 'VOIDED', 'FAILED') THEN
        RAISE EXCEPTION 'I5_VIOLATION: Illegal transition from terminal state % to %', OLD.status, NEW.status
            USING ERRCODE = 'SG004';
    END IF;

    IF (OLD.status = 'CONFIRMING' AND NEW.status = 'RESERVED')
       OR (OLD.status = 'AUTHORIZED' AND NEW.status IN ('RESERVED', 'CONFIRMING')) THEN
        RAISE EXCEPTION 'I5_VIOLATION: Backward state transition % -> %', OLD.status, NEW.status
            USING ERRCODE = 'SG004';
    END IF;

    IF NEW.status IN ('CONFIRMING', 'AUTHORIZED', 'CAPTURED') AND NEW.stripe_payment_intent IS NULL THEN
        RAISE EXCEPTION 'I2_VIOLATION: State % requires stripe_payment_intent to be recorded on intent %',
            NEW.status, OLD.intent_id USING ERRCODE = 'SG004';
    END IF;

    NEW.version := OLD.version + 1;
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_intent_state_machine
BEFORE UPDATE ON payment_intents
FOR EACH ROW EXECUTE FUNCTION trg_enforce_intent_fsm();

-- -----------------------------------------------------------------------------
-- The only sanctioned writer of mandate_balances after initialisation.
-- [NIDHI-D3] SECURITY DEFINER (alaka_app holds no usable UPDATE on the table).
-- [NIDHI-D4] pinned search_path.
-- The UPDATE below fires guard_mandate_balances_write at pg_trigger_depth() = 2
-- with current_user = the table owner, which is exactly what the guard admits.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_apply_posting_to_mandate_balance()
RETURNS TRIGGER LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_bucket account_bucket;
    v_delta  BIGINT;
BEGIN
    SELECT bucket INTO v_bucket FROM ledger_accounts WHERE account_id = NEW.account_id;
    v_delta := CASE WHEN NEW.direction = 'CREDIT' THEN NEW.amount_minor ELSE -NEW.amount_minor END;

    IF v_bucket = 'MANDATE_AVAILABLE' THEN
        UPDATE mandate_balances SET available_minor = available_minor + v_delta, version = version + 1, updated_at = NOW()
         WHERE mandate_id = NEW.mandate_id;
    ELSIF v_bucket = 'MANDATE_HELD' THEN
        UPDATE mandate_balances SET held_minor = held_minor + v_delta, version = version + 1, updated_at = NOW()
         WHERE mandate_id = NEW.mandate_id;
    ELSIF v_bucket = 'MANDATE_SETTLED' THEN
        UPDATE mandate_balances SET settled_minor = settled_minor + v_delta, version = version + 1, updated_at = NOW()
         WHERE mandate_id = NEW.mandate_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER apply_posting_to_balance
AFTER INSERT ON ledger_postings
FOR EACH ROW EXECUTE FUNCTION trg_apply_posting_to_mandate_balance();

CREATE OR REPLACE FUNCTION trg_verify_tx_and_mandate_integrity()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_tx             ledger_transactions%ROWTYPE;
    v_intent         payment_intents%ROWTYPE;
    v_debits         BIGINT;
    v_credits        BIGINT;
    v_count          INT;
    v_avail_debit    BIGINT;
    v_avail_credit   BIGINT;
    v_held_debit     BIGINT;
    v_held_credit    BIGINT;
    v_settled_debit  BIGINT;
    v_settled_credit BIGINT;
    v_bal            mandate_balances%ROWTYPE;
    v_net_avail_diff BIGINT;
    v_net_held       BIGINT;
    v_net_settled    BIGINT;
BEGIN
    SELECT * INTO v_tx FROM ledger_transactions WHERE tx_id = NEW.tx_id;
    SELECT * INTO v_intent FROM payment_intents WHERE intent_id = v_tx.intent_id;

    SELECT
        COALESCE(SUM(CASE WHEN p.direction = 'DEBIT'  THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0),
        COUNT(*),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_AVAILABLE' AND p.direction = 'DEBIT'  THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_AVAILABLE' AND p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_HELD'      AND p.direction = 'DEBIT'  THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_HELD'      AND p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_SETTLED'   AND p.direction = 'DEBIT'  THEN p.amount_minor ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_SETTLED'   AND p.direction = 'CREDIT' THEN p.amount_minor ELSE 0 END), 0)
    INTO
        v_debits, v_credits, v_count,
        v_avail_debit, v_avail_credit,
        v_held_debit, v_held_credit,
        v_settled_debit, v_settled_credit
    FROM ledger_postings p
    JOIN ledger_accounts a ON a.account_id = p.account_id
    WHERE p.tx_id = NEW.tx_id;

    IF v_count < 2 OR v_debits <> v_credits OR v_debits = 0 THEN
        RAISE EXCEPTION 'I3_VIOLATION: Unbalanced ledger_transaction % (debits=%, credits=%, postings=%)',
            NEW.tx_id, v_debits, v_credits, v_count USING ERRCODE = 'SG005';
    END IF;

    -- [NIDHI-D9] HOLE FIX. The baseline coupled state -> ledger (an intent
    -- cannot become CAPTURED / VOIDED without the ledger transaction) but not
    -- ledger -> state. A balanced "CAPTURE" (DEBIT HELD, CREDIT AVAILABLE, which
    -- matches the CAPTURE pattern while captured_amount_minor is still 0) or a
    -- "VOID" could therefore be committed against an intent left in RESERVED /
    -- CONFIRMING: the hold was released while the intent stayed chargeable on
    -- the rail, and the freed budget could be reserved again (I1 overspend).
    -- A CAPTURE / VOID ledger transaction is now valid only if, at COMMIT, the
    -- intent is in the matching terminal state. Terminal states never change,
    -- so this stays true whenever the transaction is re-verified later.
    IF (v_tx.transition_type = 'CAPTURE' AND v_intent.status IS DISTINCT FROM 'CAPTURED'::intent_status)
       OR (v_tx.transition_type = 'VOID'
           AND (v_intent.status IS NULL OR v_intent.status NOT IN ('VOIDED', 'FAILED'))) THEN
        RAISE EXCEPTION 'I3_COUPLING_VIOLATION: % ledger_transaction % requires intent % to be in the matching terminal state (found %)',
            v_tx.transition_type, NEW.tx_id, v_tx.intent_id, v_intent.status USING ERRCODE = 'SG005';
    END IF;

    IF v_tx.transition_type = 'RESERVE' THEN
        IF v_count <> 2 OR v_avail_debit <> v_intent.authorized_amount_minor OR v_held_credit <> v_intent.authorized_amount_minor THEN
            RAISE EXCEPTION 'I3_PATTERN_VIOLATION: RESERVE tx % must DEBIT AVAILABLE and CREDIT HELD by %',
                NEW.tx_id, v_intent.authorized_amount_minor USING ERRCODE = 'SG005';
        END IF;
    ELSIF v_tx.transition_type = 'VOID' THEN
        IF v_count <> 2 OR v_held_debit <> v_intent.authorized_amount_minor OR v_avail_credit <> v_intent.authorized_amount_minor THEN
            RAISE EXCEPTION 'I3_PATTERN_VIOLATION: VOID tx % must DEBIT HELD and CREDIT AVAILABLE by %',
                NEW.tx_id, v_intent.authorized_amount_minor USING ERRCODE = 'SG005';
        END IF;
    ELSIF v_tx.transition_type = 'CAPTURE' THEN
        IF v_held_debit <> v_intent.authorized_amount_minor
           OR v_settled_credit <> v_intent.captured_amount_minor
           OR v_avail_credit <> (v_intent.authorized_amount_minor - v_intent.captured_amount_minor)
           OR v_avail_debit <> 0 OR v_held_credit <> 0 OR v_settled_debit <> 0 THEN
            RAISE EXCEPTION 'I3_PATTERN_VIOLATION: CAPTURE tx % postings do not match authorized/captured amounts',
                NEW.tx_id USING ERRCODE = 'SG005';
        END IF;
    END IF;

    SELECT * INTO v_bal FROM mandate_balances WHERE mandate_id = NEW.mandate_id FOR SHARE;

    IF v_bal.available_minor < 0 OR v_bal.held_minor < 0 OR v_bal.settled_minor < 0 THEN
        RAISE EXCEPTION 'I1_VIOLATION: Negative bucket balance on mandate % (avail=%, held=%, settled=%)',
            NEW.mandate_id, v_bal.available_minor, v_bal.held_minor, v_bal.settled_minor USING ERRCODE = 'SG003';
    END IF;

    IF (v_bal.available_minor + v_bal.held_minor + v_bal.settled_minor) <> v_bal.total_budget_minor THEN
        RAISE EXCEPTION 'I3_VIOLATION: Mandate % conservation broken (avail+held+settled != total)',
            NEW.mandate_id USING ERRCODE = 'SG005';
    END IF;

    SELECT
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_AVAILABLE'
                          THEN (CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END)
                          ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_HELD'
                          THEN (CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END)
                          ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_SETTLED'
                          THEN (CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END)
                          ELSE 0 END), 0)
    INTO v_net_avail_diff, v_net_held, v_net_settled
    FROM ledger_postings p
    JOIN ledger_accounts a ON a.account_id = p.account_id
    WHERE p.mandate_id = NEW.mandate_id;

    IF v_bal.available_minor <> (v_bal.total_budget_minor + v_net_avail_diff)
       OR v_bal.held_minor <> v_net_held
       OR v_bal.settled_minor <> v_net_settled THEN
        RAISE EXCEPTION 'I3_DRIFT_VIOLATION: Materialized balance out of sync with postings for mandate %',
            NEW.mandate_id USING ERRCODE = 'SG005';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER enforce_tx_balanced_on_tx_insert
AFTER INSERT ON ledger_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION trg_verify_tx_and_mandate_integrity();

CREATE CONSTRAINT TRIGGER enforce_tx_balanced_on_posting_insert
AFTER INSERT ON ledger_postings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION trg_verify_tx_and_mandate_integrity();

CREATE OR REPLACE FUNCTION trg_verify_intent_has_ledger_entries()
RETURNS TRIGGER LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
    v_has_reserve BOOLEAN;
    v_has_capture BOOLEAN;
    v_has_void    BOOLEAN;
BEGIN
    SELECT
        EXISTS (SELECT 1 FROM ledger_transactions WHERE intent_id = NEW.intent_id AND transition_type = 'RESERVE'),
        EXISTS (SELECT 1 FROM ledger_transactions WHERE intent_id = NEW.intent_id AND transition_type = 'CAPTURE'),
        EXISTS (SELECT 1 FROM ledger_transactions WHERE intent_id = NEW.intent_id AND transition_type = 'VOID')
    INTO v_has_reserve, v_has_capture, v_has_void;

    IF NEW.status IN ('RESERVED', 'CONFIRMING', 'AUTHORIZED') AND (NOT v_has_reserve OR v_has_capture OR v_has_void) THEN
        RAISE EXCEPTION 'I3_VIOLATION: Intent % in state % must have only RESERVE ledger transaction', NEW.intent_id, NEW.status
            USING ERRCODE = 'SG005';
    END IF;

    IF NEW.status = 'CAPTURED' AND (NOT v_has_reserve OR NOT v_has_capture OR v_has_void) THEN
        RAISE EXCEPTION 'I3_VIOLATION: Intent % in CAPTURED state missing RESERVE+CAPTURE ledger transactions', NEW.intent_id
            USING ERRCODE = 'SG005';
    END IF;

    IF NEW.status IN ('VOIDED', 'FAILED') AND (NOT v_has_reserve OR NOT v_has_void OR v_has_capture) THEN
        RAISE EXCEPTION 'I3_VIOLATION: Intent % in % state missing RESERVE+VOID ledger transactions', NEW.intent_id, NEW.status
            USING ERRCODE = 'SG005';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER enforce_intent_ledger_coupling
AFTER INSERT OR UPDATE ON payment_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION trg_verify_intent_has_ledger_entries();

-- =============================================================================
-- [NIDHI-D10] Least-privilege grants for the runtime role.
--
-- alaka_app owns nothing above, so without a GRANT it can do nothing; PostgreSQL
-- reserves ALTER / DROP / DISABLE TRIGGER / CREATE OR REPLACE for the owner, and
-- TRUNCATE / DELETE / TRIGGER / REFERENCES are simply never granted.
--
--   table                 app privileges        why
--   --------------------  --------------------  -----------------------------------------
--   spend_mandates        SELECT INSERT UPDATE  UPDATE = status changes (revoke/suspend/
--                                               expire); every other column is frozen by
--                                               trg_enforce_mandate_fsm (SG006/SG004).
--                                               UPDATE is also what permits FOR SHARE.
--   payment_intents       SELECT INSERT UPDATE  UPDATE = FSM transitions, guarded by
--                                               trg_enforce_intent_fsm (SG004/SG006).
--   ledger_transactions   SELECT INSERT         append-only
--   ledger_postings       SELECT INSERT         append-only
--   ledger_accounts       SELECT                created only by trg_init_mandate_ledger
--   mandate_balances      SELECT, UPDATE(version) only
--                                               never written by the app. PostgreSQL needs
--                                               UPDATE on at least one column before it
--                                               allows SELECT ... FOR UPDATE / FOR SHARE,
--                                               which Phase 1 (hardened-pessimistic) and
--                                               the deferred integrity trigger both take.
--                                               The grant is a row-lock capability only:
--                                               an actual UPDATE of version is rejected by
--                                               guard_mandate_balances_write (SG007); any
--                                               other column, INSERT and DELETE are 42501.
--   outbox_tasks          SELECT INSERT UPDATE  work queue
--   processed_webhooks    SELECT INSERT         append-only dedup log
-- =============================================================================
-- (Freshly created tables carry no privileges for PUBLIC or alaka_app, so there
-- is nothing to REVOKE first; the grants below are the complete set.)
GRANT SELECT, INSERT, UPDATE ON spend_mandates      TO alaka_app;
GRANT SELECT, INSERT, UPDATE ON payment_intents     TO alaka_app;
GRANT SELECT, INSERT         ON ledger_transactions TO alaka_app;
GRANT SELECT, INSERT         ON ledger_postings     TO alaka_app;
GRANT SELECT                 ON ledger_accounts     TO alaka_app;
GRANT SELECT                 ON mandate_balances    TO alaka_app;
GRANT UPDATE (version)       ON mandate_balances    TO alaka_app;
GRANT SELECT, INSERT, UPDATE ON outbox_tasks        TO alaka_app;
GRANT SELECT, INSERT         ON processed_webhooks  TO alaka_app;

-- Trigger functions are only ever invoked by the trigger machinery (which does
-- not consult EXECUTE at fire time). Nobody needs to hold EXECUTE on them.
REVOKE ALL ON FUNCTION trg_init_mandate_ledger()                  FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_enforce_mandate_fsm()                  FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_guard_mandate_balances_direct_write()  FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_forbid_mutation()                      FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_verify_intent_on_insert()              FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_enforce_intent_fsm()                   FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_apply_posting_to_mandate_balance()     FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_verify_tx_and_mandate_integrity()      FROM PUBLIC;
REVOKE ALL ON FUNCTION trg_verify_intent_has_ledger_entries()     FROM PUBLIC;
