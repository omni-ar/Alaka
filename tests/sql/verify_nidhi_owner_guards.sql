-- =============================================================================
-- Alaka / nidhi -- tests/sql/verify_nidhi_owner_guards.sql
-- Companion to verify_nidhi_attacks.sql: proves the trigger guards that the
-- privilege system shadows for alaka_app, i.e. the second layer that would
-- still stand if a grant were ever widened by mistake.
--
-- RUN AS alaka_migrator (the owner). For the owner no privilege check stands
-- in front of the triggers, so the SQLSTATE asserted here is the trigger's own:
--
--   docker exec -i alaka-postgres psql -X -v ON_ERROR_STOP=1 -U alaka_migrator -d alaka \
--       < tests/sql/verify_nidhi_owner_guards.sql
--
-- LEAVES NOTHING BEHIND: the whole file is one transaction that ends in
-- ROLLBACK (each attack is undone with ROLLBACK TO SAVEPOINT). That includes
-- the two cases that DISABLE the balance guard to prove the COMMIT-time
-- cross-check catches tampering even when the guard is gone -- the ALTER TABLE
-- is rolled back with everything else, and case O18 re-asserts that all 15
-- triggers are enabled afterwards.
--
-- Same assertion discipline as the main suite: one statement per attack runs
-- with ON_ERROR_STOP off, its :SQLSTATE is stored, and after the ROLLBACK every
-- stored code is compared explicitly (no WHEN OTHERS; a mismatch aborts psql
-- with a non-zero status). Assertions run after the ROLLBACK because the pass
-- counter is a session setting and would be rolled back with the transaction.
-- =============================================================================
\set ON_ERROR_STOP 1
\set QUIET on
\pset pager off
\pset format unaligned
\pset tuples_only on
\set SHOW_CONTEXT never

\set expected_total 20

SET nidhi_t.pass = '0';

PREPARE nidhi_assert(text, text, text) AS
SELECT CASE
    WHEN $3 IS NOT DISTINCT FROM $2 THEN
        'PASS  [' || $2 || ']  ' || $1
        || left(set_config('nidhi_t.pass', (current_setting('nidhi_t.pass')::int + 1)::text, false), 0)
    ELSE
        format('ASSERTION FAILED -- %s -- expected [%s], got [%s]', $1, $2, $3)::integer::text
END;

\echo '=== NIDHI OWNER-SIDE GUARD SUITE (stderr ERROR lines are the expected rejections) ==='

SELECT current_user::text AS got \gset
EXECUTE nidhi_assert('O00 suite runs as the owner role alaka_migrator', 'alaka_migrator', :'got');

SELECT replace(gen_random_uuid()::text, '-', '') AS run \gset
SELECT 'owner-agent-' || :'run' AS agent, repeat('b', 64) AS rh,
       gen_random_uuid() AS om, gen_random_uuid() AS oi, gen_random_uuid() AS ot,
       gen_random_uuid() AS oi2, gen_random_uuid() AS ot2 \gset

BEGIN;

-- Setup (all rolled back at the end): a mandate of 1000 with one valid RESERVE of 400.
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, expires_at, token_kid)
VALUES (:'om', :'agent', 'USD', 1000, 1000, ARRAY['merchant-a'], NOW() + INTERVAL '1 day', 'kid-owner-suite');
SELECT max(account_id::text) FILTER (WHERE bucket = 'MANDATE_AVAILABLE') AS om_av,
       max(account_id::text) FILTER (WHERE bucket = 'MANDATE_HELD')      AS om_he
  FROM ledger_accounts WHERE mandate_id = :'om' \gset
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'oi', :'om', :'agent', 'idem-oi', :'rh', 'merchant-a', 'USD', 400, 'create_' || :'oi', 'confirm_' || :'oi');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'ot', :'oi', :'om', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)
VALUES (:'ot', :'om', :'om_av', 'USD', 'DEBIT', 400), (:'ot', :'om', :'om_he', 'USD', 'CREDIT', 400);
SET CONSTRAINTS ALL IMMEDIATE;   -- the setup itself is a valid, fully verified reserve
SET CONSTRAINTS ALL DEFERRED;
SELECT COALESCE((SELECT format('%s/%s/%s', available_minor, held_minor, settled_minor) FROM mandate_balances WHERE mandate_id = :'om'), 'NO_ROW') AS setup_bal \gset

-- ---- SG007: the balance guard itself (Trap 2 #3) ---------------------------
SAVEPOINT s;
\set ON_ERROR_STOP 0
UPDATE mandate_balances SET available_minor = available_minor + 1000000 WHERE mandate_id = :'om';
\set o01 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
INSERT INTO mandate_balances (mandate_id, currency, total_budget_minor, available_minor, held_minor, settled_minor)
VALUES (:'om', 'USD', 1000, 1000, 0, 0);
\set o02 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

-- ---- SG006: immutable audit rows -------------------------------------------
SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM mandate_balances WHERE mandate_id = :'om';
\set o03 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
UPDATE ledger_postings SET amount_minor = 1 WHERE tx_id = :'ot';
\set o04 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM ledger_postings WHERE tx_id = :'ot';
\set o05 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
UPDATE ledger_transactions SET transition_type = 'VOID' WHERE tx_id = :'ot';
\set o06 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM ledger_transactions WHERE tx_id = :'ot';
\set o07 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
UPDATE ledger_accounts SET bucket = 'MANDATE_AVAILABLE' WHERE account_id = :'om_he';
\set o08 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM ledger_accounts WHERE account_id = :'om_he';
\set o09 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM payment_intents WHERE intent_id = :'oi';
\set o10 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
DELETE FROM spend_mandates WHERE mandate_id = :'om';
\set o11 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

-- ---- no 4th bucket, not even for the owner (Trap 2 #4) ----------------------
SAVEPOINT s;
\set ON_ERROR_STOP 0
INSERT INTO ledger_accounts (mandate_id, bucket, currency) VALUES (:'om', 'MANDATE_SETTLED', 'USD');
\set o12 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

SAVEPOINT s;
\set ON_ERROR_STOP 0
INSERT INTO ledger_accounts (mandate_id, bucket, currency) VALUES (:'om', 'EXTERNAL_RAIL_CLEARING', 'USD');
\set o13 :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

-- ---- COMMIT-time cross-check against the raw SUM of postings (Trap 2 #3) ----
-- Take the guard away (transactionally), tamper in a way that KEEPS
-- avail+held+settled = total, then run a perfectly valid reserve. The deferred
-- integrity trigger must still refuse: the materialised row no longer equals
-- the postings.
SAVEPOINT s;
ALTER TABLE mandate_balances DISABLE TRIGGER guard_mandate_balances_write;
UPDATE mandate_balances SET available_minor = available_minor - 100, settled_minor = settled_minor + 100 WHERE mandate_id = :'om';
ALTER TABLE mandate_balances ENABLE TRIGGER guard_mandate_balances_write;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'oi2', :'om', :'agent', 'idem-oi2', :'rh', 'merchant-a', 'USD', 100, 'create_' || :'oi2', 'confirm_' || :'oi2');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'ot2', :'oi2', :'om', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)
VALUES (:'ot2', :'om', :'om_av', 'USD', 'DEBIT', 100), (:'ot2', :'om', :'om_he', 'USD', 'CREDIT', 100);
\set ON_ERROR_STOP 0
SET CONSTRAINTS ALL IMMEDIATE;
\set o14 :SQLSTATE
\set o14m :LAST_ERROR_MESSAGE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

-- Same, but the tampering mints budget (conservation itself breaks).
SAVEPOINT s;
ALTER TABLE mandate_balances DISABLE TRIGGER guard_mandate_balances_write;
UPDATE mandate_balances SET available_minor = available_minor + 1000000 WHERE mandate_id = :'om';
ALTER TABLE mandate_balances ENABLE TRIGGER guard_mandate_balances_write;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'oi2', :'om', :'agent', 'idem-oi2', :'rh', 'merchant-a', 'USD', 100, 'create_' || :'oi2', 'confirm_' || :'oi2');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'ot2', :'oi2', :'om', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)
VALUES (:'ot2', :'om', :'om_av', 'USD', 'DEBIT', 100), (:'ot2', :'om', :'om_he', 'USD', 'CREDIT', 100);
\set ON_ERROR_STOP 0
SET CONSTRAINTS ALL IMMEDIATE;
\set o15 :SQLSTATE
\set o15m :LAST_ERROR_MESSAGE
\set ON_ERROR_STOP 1
ROLLBACK TO SAVEPOINT s;

ROLLBACK;

-- =============================================================================
-- Assertions (after the ROLLBACK, see header)
-- =============================================================================
EXECUTE nidhi_assert('O00b setup inside the transaction was a valid, verified RESERVE 400 of 1000', '600/400/0', :'setup_bal');
EXECUTE nidhi_assert('O01 owner direct UPDATE of mandate_balances (pg_trigger_depth() = 1) hits the trigger guard', 'SG007', :'o01');
EXECUTE nidhi_assert('O02 owner direct INSERT into mandate_balances hits the trigger guard', 'SG007', :'o02');
EXECUTE nidhi_assert('O03 owner DELETE from mandate_balances', 'SG006', :'o03');
EXECUTE nidhi_assert('O04 owner UPDATE of a ledger_postings row', 'SG006', :'o04');
EXECUTE nidhi_assert('O05 owner DELETE of ledger_postings rows', 'SG006', :'o05');
EXECUTE nidhi_assert('O06 owner UPDATE of a ledger_transactions row', 'SG006', :'o06');
EXECUTE nidhi_assert('O07 owner DELETE of a ledger_transactions row', 'SG006', :'o07');
EXECUTE nidhi_assert('O08 owner UPDATE of a ledger_accounts row (re-bucket)', 'SG006', :'o08');
EXECUTE nidhi_assert('O09 owner DELETE of a ledger_accounts row', 'SG006', :'o09');
EXECUTE nidhi_assert('O10 owner DELETE of a payment_intents row', 'SG006', :'o10');
EXECUTE nidhi_assert('O11 owner DELETE of a spend_mandates row', 'SG006', :'o11');
EXECUTE nidhi_assert('O12 owner INSERT of a second account for an existing bucket', '23505', :'o12');
EXECUTE nidhi_assert('O13 owner INSERT of a 4th bucket (EXTERNAL_RAIL_CLEARING)', '22P02', :'o13');
EXECUTE nidhi_assert('O14 guard disabled + conserving tamper (AVAILABLE -100, SETTLED +100): next valid reserve refused by the deferred cross-check', 'SG005', :'o14');
SELECT (position('I3_DRIFT_VIOLATION' IN :'o14m') > 0)::text AS got \gset
EXECUTE nidhi_assert('O15 ...and the refusal is specifically the balance-vs-SUM(postings) drift check', 'true', :'got');
EXECUTE nidhi_assert('O16 guard disabled + minting tamper (AVAILABLE +1,000,000): next valid reserve refused by the deferred conservation check', 'SG005', :'o15');
SELECT (position('conservation broken' IN :'o15m') > 0)::text AS got \gset
EXECUTE nidhi_assert('O17 ...and the refusal is specifically avail+held+settled != total', 'true', :'got');

SELECT (SELECT count(*) FILTER (WHERE tgenabled = 'O') || '/' || count(*)
          FROM pg_trigger
         WHERE NOT tgisinternal
           AND tgrelid IN ('public.spend_mandates'::regclass, 'public.mandate_balances'::regclass, 'public.ledger_accounts'::regclass,
                           'public.payment_intents'::regclass, 'public.ledger_transactions'::regclass, 'public.ledger_postings'::regclass))
       || ' residue=' || (SELECT count(*) FROM spend_mandates WHERE mandate_id = :'om' OR agent_id = :'agent') AS got \gset
EXECUTE nidhi_assert('O18 after ROLLBACK all 15 triggers are enabled and no row of this file exists', '15/15 residue=0', :'got');

SELECT current_setting('nidhi_t.pass') AS npass \gset
SELECT CASE WHEN :'npass' = :'expected_total'
    THEN format('NIDHI OWNER GUARD SUITE: %s/%s cases PASSED, 0 failed  (role=%s, db=%s)',
                :'npass', :'expected_total', current_user, current_database())
    ELSE format('ASSERTION FAILED -- pass counter %s does not equal the declared total %s', :'npass', :'expected_total')::integer::text
END;
