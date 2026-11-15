-- =============================================================================
-- Alaka / nidhi -- tests/sql/verify_nidhi_attacks.sql
-- Self-asserting adversarial suite for the double-entry ledger kernel.
--
-- RUN AS alaka_app (the least-privilege runtime role), never as a superuser or
-- as alaka_migrator -- least privilege is part of what is being proven:
--
--   docker exec -i alaka-postgres psql -X -v ON_ERROR_STOP=1 -U alaka_app -d alaka \
--       < tests/sql/verify_nidhi_attacks.sql
--
-- Exit status 0 = every case passed. Any failed assertion aborts psql with a
-- non-zero status (3). The file also sets ON_ERROR_STOP itself, so forgetting
-- the -v flag cannot turn a failure into a pass.
--
-- HOW A CASE WORKS
--   * Setup statements run with ON_ERROR_STOP on: a broken setup stops the
--     suite, it can never masquerade as "the attack was rejected".
--   * Exactly ONE statement -- the attack, or the top-level COMMIT for guards
--     that are DEFERRABLE INITIALLY DEFERRED -- runs with ON_ERROR_STOP off.
--     psql's :SQLSTATE of that statement is captured into :got.
--   * nidhi_assert(case, expected, got) compares the two strings explicitly.
--     An attack that SUCCEEDS yields got = 00000 and fails the case; an attack
--     rejected with a DIFFERENT code fails the case. There is no WHEN OTHERS
--     anywhere in this file.
--   * On mismatch nidhi_assert raises (it casts the failure message to integer,
--     the only way to raise from plain SQL without owning a function -- and
--     alaka_app, by design, cannot create one). ON_ERROR_STOP then ends the run.
--
-- The "ERROR:" lines psql prints on stderr are the expected rejections; each is
-- followed on stdout by the PASS line that asserted its SQLSTATE.
--
-- Re-runnable: every run uses fresh UUIDs and a fresh agent id. Ledger rows are
-- immutable by design, so earlier runs' rows stay; nothing here depends on an
-- empty database.
--
-- Companion file verify_nidhi_owner_guards.sql (run as alaka_migrator) proves
-- the trigger guards that privileges shadow for alaka_app (SG007 on INSERT,
-- SG006 on ledger-row UPDATE/DELETE, the COMMIT-time drift cross-check).
-- =============================================================================
\set ON_ERROR_STOP 1
\set QUIET on
\pset pager off
\pset format unaligned
\pset tuples_only on
\set SHOW_CONTEXT never

-- Number of nidhi_assert cases below. The summary refuses to print unless the
-- pass counter equals it, so a silently skipped section cannot go unnoticed.
\set expected_total 137

SET nidhi_t.pass = '0';

PREPARE nidhi_assert(text, text, text) AS
SELECT CASE
    WHEN $3 IS NOT DISTINCT FROM $2 THEN
        'PASS  [' || $2 || ']  ' || $1
        || left(set_config('nidhi_t.pass', (current_setting('nidhi_t.pass')::int + 1)::text, false), 0)
    ELSE
        format('ASSERTION FAILED -- %s -- expected [%s], got [%s]', $1, $2, $3)::integer::text
END;

\echo '=== NIDHI ATTACK SUITE (stderr ERROR lines are the expected rejections) ==='

-- -----------------------------------------------------------------------------
-- Per-run identifiers
-- -----------------------------------------------------------------------------
SELECT replace(gen_random_uuid()::text, '-', '') AS run \gset
SELECT 'agent-' || :'run' AS agent, 'intruder-' || :'run' AS agent2,
       encode(sha256(convert_to('nidhi-suite-' || :'run', 'UTF8')), 'hex') AS rh \gset
SELECT gen_random_uuid() AS m1, gen_random_uuid() AS m2, gen_random_uuid() AS m3,
       gen_random_uuid() AS m4, gen_random_uuid() AS m5, gen_random_uuid() AS m6 \gset
SELECT gen_random_uuid() AS i1, gen_random_uuid() AS i2, gen_random_uuid() AS i3,
       gen_random_uuid() AS i4, gen_random_uuid() AS i5, gen_random_uuid() AS i6 \gset
SELECT gen_random_uuid() AS t1r, gen_random_uuid() AS t1c, gen_random_uuid() AS t2r, gen_random_uuid() AS t2v,
       gen_random_uuid() AS t3r, gen_random_uuid() AS t3c, gen_random_uuid() AS t4r, gen_random_uuid() AS t5r,
       gen_random_uuid() AS t6r \gset

-- Reusable "what does mandate_balances say" queries (always return one row).
\set q_m1 'SELECT COALESCE((SELECT format(''%s/%s/%s v%s'', available_minor, held_minor, settled_minor, version) FROM mandate_balances WHERE mandate_id = ''' :m1 '''), ''NO_ROW'') AS got'
\set q_m2 'SELECT COALESCE((SELECT format(''%s/%s/%s v%s'', available_minor, held_minor, settled_minor, version) FROM mandate_balances WHERE mandate_id = ''' :m2 '''), ''NO_ROW'') AS got'

-- =============================================================================
-- S. The session really is the least-privilege runtime role
-- =============================================================================
SELECT session_user::text || '/' || current_user::text AS got \gset
EXECUTE nidhi_assert('S01 suite runs as alaka_app (session_user/current_user)', 'alaka_app/alaka_app', :'got');

SELECT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)::text AS got
  FROM pg_roles WHERE rolname = current_user \gset
EXECUTE nidhi_assert('S02 alaka_app has no elevated role attribute (super/createrole/createdb/replication/bypassrls)', 'false', :'got');

SELECT (SELECT count(*) FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user))::text AS got \gset
EXECUTE nidhi_assert('S03 alaka_app is a member of no other role', '0', :'got');

SELECT ((SELECT count(*) FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user))
      + (SELECT count(*) FROM pg_proc  WHERE proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user))
      + (SELECT count(*) FROM pg_type  WHERE typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)))::text AS got \gset
EXECUTE nidhi_assert('S04 alaka_app owns no relation, function or type', '0', :'got');

SELECT (has_database_privilege(current_database(), 'CREATE')
     OR has_database_privilege(current_database(), 'TEMPORARY')
     OR has_schema_privilege('public', 'CREATE'))::text AS got \gset
EXECUTE nidhi_assert('S05 alaka_app cannot create schemas, temp objects or objects in public', 'false', :'got');

SELECT string_agg(format('%s=%s', t.tbl,
           COALESCE((SELECT string_agg(p, ',' ORDER BY p)
                       FROM unnest(ARRAY['DELETE','INSERT','REFERENCES','SELECT','TRIGGER','TRUNCATE','UPDATE']) p
                      WHERE has_table_privilege(('public.' || t.tbl)::regclass, p)), 'none')), ' ' ORDER BY t.tbl) AS got
  FROM unnest(ARRAY['spend_mandates','mandate_balances','ledger_accounts','payment_intents',
                    'ledger_transactions','ledger_postings','outbox_tasks','processed_webhooks']) t(tbl) \gset
EXECUTE nidhi_assert('S06 exact table-privilege matrix of alaka_app',
    'ledger_accounts=SELECT ledger_postings=INSERT,SELECT ledger_transactions=INSERT,SELECT mandate_balances=SELECT outbox_tasks=INSERT,SELECT,UPDATE payment_intents=INSERT,SELECT,UPDATE processed_webhooks=INSERT,SELECT spend_mandates=INSERT,SELECT,UPDATE',
    :'got');

SELECT COALESCE(string_agg(attname, ',' ORDER BY attnum), 'none') AS got
  FROM pg_attribute
 WHERE attrelid = 'public.mandate_balances'::regclass AND attnum > 0 AND NOT attisdropped
   AND (has_column_privilege(attrelid, attname, 'UPDATE') OR has_column_privilege(attrelid, attname, 'INSERT')) \gset
EXECUTE nidhi_assert('S07 on mandate_balances the app holds a write privilege on the row-lock column only', 'version', :'got');

SELECT count(*) FILTER (WHERE tgenabled = 'O') || '/' || count(*) AS got
  FROM pg_trigger
 WHERE NOT tgisinternal
   AND tgrelid IN ('public.spend_mandates'::regclass, 'public.mandate_balances'::regclass, 'public.ledger_accounts'::regclass,
                   'public.payment_intents'::regclass, 'public.ledger_transactions'::regclass, 'public.ledger_postings'::regclass) \gset
EXECUTE nidhi_assert('S08 all 15 nidhi triggers exist and are enabled', '15/15', :'got');

SELECT count(*)::text AS got FROM pg_proc
 WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'trg\_%' AND prosrc ~ 'P000[0-9]' \gset
EXECUTE nidhi_assert('S09 no trigger function uses the P000x SQLSTATE class (Trap 2 #8)', '0', :'got');

-- =============================================================================
-- P. Positive controls: the valid lifecycle commits, balances asserted exactly
-- =============================================================================
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, expires_at, token_kid)
VALUES (:'m1', :'agent', 'USD', 10000, 5000, ARRAY['merchant-a', 'merchant-b'], NOW() + INTERVAL '1 day', 'kid-suite');

:q_m1 \gset
EXECUTE nidhi_assert('P01 app creates a mandate; init trigger materialises avail/held/settled', '10000/0/0 v1', :'got');

SELECT string_agg(bucket::text, ',' ORDER BY bucket) AS got FROM ledger_accounts WHERE mandate_id = :'m1' \gset
EXECUTE nidhi_assert('P02 exactly the 3 bucket accounts were created for the mandate',
    'MANDATE_AVAILABLE,MANDATE_HELD,MANDATE_SETTLED', :'got');

SELECT max(account_id::text) FILTER (WHERE bucket = 'MANDATE_AVAILABLE') AS m1_av,
       max(account_id::text) FILTER (WHERE bucket = 'MANDATE_HELD')      AS m1_he,
       max(account_id::text) FILTER (WHERE bucket = 'MANDATE_SETTLED')   AS m1_se
  FROM ledger_accounts WHERE mandate_id = :'m1' \gset

-- P03-P05: the Phase 1 RESERVE, exactly as alaka-core issues it, postings one row
-- at a time. Between the two postings the balance row is non-conserving; that is
-- legal because conservation is a DEFERRED constraint (Trap 2 #1).
BEGIN;
SELECT count(*)::text AS got FROM (SELECT 1 FROM spend_mandates   WHERE mandate_id = :'m1' FOR SHARE)  s \gset
SELECT :'got' || '+' || count(*)::text AS got FROM (SELECT 1 FROM mandate_balances WHERE mandate_id = :'m1' FOR UPDATE) s \gset
EXECUTE nidhi_assert('P03 app can take the canonical locks (mandate FOR SHARE, mandate_balances FOR UPDATE)', '1+1', :'got');
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i1', :'m1', :'agent', 'idem-i1', :'rh', 'merchant-a', 'USD', 4000, 'create_' || :'i1', 'confirm_' || :'i1');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t1r', :'i1', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t1r', :'m1', :'m1_av', 'USD', 'DEBIT', 4000);
:q_m1 \gset
EXECUTE nidhi_assert('P04 mid-transaction (DEBIT AVAILABLE only) the row is non-conserving and still accepted', '6000/0/0 v2', :'got');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t1r', :'m1', :'m1_he', 'USD', 'CREDIT', 4000);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('P05 valid RESERVE 4000 commits at top-level COMMIT: avail/held/settled', '6000/4000/0 v3', :'got');

SELECT COALESCE((SELECT format('%s v%s cap=%s', status, version, captured_amount_minor) FROM payment_intents WHERE intent_id = :'i1'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('P06 intent i1 is RESERVED', 'RESERVED v1 cap=0', :'got');

-- RESERVED -> CONFIRMING (Phase 2A): records the pi_, moves no money.
UPDATE payment_intents SET status = 'CONFIRMING', stripe_payment_intent = 'pi_' || :'run' || '_1' WHERE intent_id = :'i1';
SELECT COALESCE((SELECT format('%s v%s', status, version) FROM payment_intents WHERE intent_id = :'i1'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('P07 RESERVED -> CONFIRMING with pi_ recorded', 'CONFIRMING v2', :'got');
:q_m1 \gset
EXECUTE nidhi_assert('P08 CONFIRMING moved no money', '6000/4000/0 v3', :'got');

-- CONFIRMING -> CAPTURED, partial capture 2500 of 4000: remainder 1500 back to AVAILABLE.
BEGIN;
UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = 2500 WHERE intent_id = :'i1';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t1c', :'i1', :'m1', 'USD', 'CAPTURE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t1c', :'m1', :'m1_he', 'USD', 'DEBIT', 4000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t1c', :'m1', :'m1_se', 'USD', 'CREDIT', 2500);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t1c', :'m1', :'m1_av', 'USD', 'CREDIT', 1500);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('P09 partial CAPTURE 2500/4000 settles 2500 and releases 1500 to AVAILABLE', '7500/0/2500 v6', :'got');
SELECT COALESCE((SELECT format('%s v%s cap=%s', status, version, captured_amount_minor) FROM payment_intents WHERE intent_id = :'i1'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('P10 intent i1 is CAPTURED with captured_amount_minor 2500', 'CAPTURED v3 cap=2500', :'got');

-- RESERVE 3000 then RESERVED -> VOIDED.
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i2', :'m1', :'agent', 'idem-i2', :'rh', 'merchant-b', 'USD', 3000, 'create_' || :'i2', 'confirm_' || :'i2');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t2r', :'i2', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t2r', :'m1', :'m1_av', 'USD', 'DEBIT', 3000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t2r', :'m1', :'m1_he', 'USD', 'CREDIT', 3000);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('P11 second RESERVE 3000', '4500/3000/2500 v8', :'got');
BEGIN;
UPDATE payment_intents SET status = 'VOIDED' WHERE intent_id = :'i2';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t2v', :'i2', :'m1', 'USD', 'VOID');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t2v', :'m1', :'m1_he', 'USD', 'DEBIT', 3000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t2v', :'m1', :'m1_av', 'USD', 'CREDIT', 3000);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('P12 RESERVED -> VOIDED returns the full hold to AVAILABLE', '7500/0/2500 v10', :'got');

-- RESERVE 1000 -> CONFIRMING -> AUTHORIZED -> CAPTURED in full (two postings).
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i3', :'m1', :'agent', 'idem-i3', :'rh', 'merchant-a', 'USD', 1000, 'create_' || :'i3', 'confirm_' || :'i3');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t3r', :'i3', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t3r', :'m1', :'m1_av', 'USD', 'DEBIT', 1000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t3r', :'m1', :'m1_he', 'USD', 'CREDIT', 1000);
COMMIT;
UPDATE payment_intents SET status = 'CONFIRMING', stripe_payment_intent = 'pi_' || :'run' || '_3' WHERE intent_id = :'i3';
UPDATE payment_intents SET status = 'AUTHORIZED' WHERE intent_id = :'i3';
BEGIN;
UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = 1000 WHERE intent_id = :'i3';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t3c', :'i3', :'m1', 'USD', 'CAPTURE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t3c', :'m1', :'m1_he', 'USD', 'DEBIT', 1000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t3c', :'m1', :'m1_se', 'USD', 'CREDIT', 1000);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('P13 RESERVE -> CONFIRMING -> AUTHORIZED -> full CAPTURE 1000', '6500/0/3500 v14', :'got');
SELECT COALESCE((SELECT format('%s v%s cap=%s', status, version, captured_amount_minor) FROM payment_intents WHERE intent_id = :'i3'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('P14 intent i3 is CAPTURED in full', 'CAPTURED v4 cap=1000', :'got');

-- Two in-flight holds that the attacks below will target: i4 RESERVED 2000, i5 CONFIRMING 1500.
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i4', :'m1', :'agent', 'idem-i4', :'rh', 'merchant-a', 'USD', 2000, 'create_' || :'i4', 'confirm_' || :'i4');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t4r', :'i4', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)
VALUES (:'t4r', :'m1', :'m1_av', 'USD', 'DEBIT', 2000), (:'t4r', :'m1', :'m1_he', 'USD', 'CREDIT', 2000);
COMMIT;
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i5', :'m1', :'agent', 'idem-i5', :'rh', 'merchant-b', 'USD', 1500, 'create_' || :'i5', 'confirm_' || :'i5');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t5r', :'i5', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor)
VALUES (:'t5r', :'m1', :'m1_av', 'USD', 'DEBIT', 1500), (:'t5r', :'m1', :'m1_he', 'USD', 'CREDIT', 1500);
COMMIT;
UPDATE payment_intents SET status = 'CONFIRMING', stripe_payment_intent = 'pi_' || :'run' || '_5' WHERE intent_id = :'i5';
:q_m1 \gset
EXECUTE nidhi_assert('P15 two in-flight holds (i4 RESERVED 2000, i5 CONFIRMING 1500); attack baseline', '3000/3500/3500 v18', :'got');

-- Other mandates used by the attacks.
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, expires_at, token_kid)
VALUES (:'m2', :'agent', 'EUR', 5000, 5000, ARRAY['merchant-a'], NOW() + INTERVAL '1 day', 'kid-suite');
SELECT max(account_id::text) FILTER (WHERE bucket = 'MANDATE_AVAILABLE') AS m2_av,
       max(account_id::text) FILTER (WHERE bucket = 'MANDATE_HELD')      AS m2_he
  FROM ledger_accounts WHERE mandate_id = :'m2' \gset
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, expires_at, token_kid)
VALUES (:'m3', :'agent', 'USD', 5000, 5000, ARRAY['merchant-a'], NOW() + INTERVAL '1 day', 'kid-suite');
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, status, expires_at, token_kid)
VALUES (:'m4', :'agent', 'USD', 5000, 5000, ARRAY['merchant-a'], 'SUSPENDED', NOW() + INTERVAL '1 day', 'kid-suite');
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, not_before, expires_at, token_kid)
VALUES (:'m5', :'agent', 'USD', 5000, 5000, ARRAY['merchant-a'], NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', 'kid-suite');
INSERT INTO spend_mandates (mandate_id, agent_id, currency, total_budget_minor, max_per_tx_minor, allowed_merchants, not_before, expires_at, token_kid)
VALUES (:'m6', :'agent', 'USD', 5000, 5000, ARRAY['merchant-a'], NOW() + INTERVAL '1 day', NOW() + INTERVAL '2 days', 'kid-suite');

-- =============================================================================
-- A1. Trap 2 #1 -- unbalanced / one-sided transactions die at COMMIT (SG005)
-- =============================================================================
\set c 'A1a one-sided RESERVE (DEBIT AVAILABLE only) rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 500);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A1b unbalanced RESERVE (DEBIT 500 / CREDIT 400) rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 500);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'CREDIT', 400);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A1c ledger_transaction with zero postings rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A1d same one-sided RESERVE: the deferred guard also fires when forced by SET CONSTRAINTS ALL IMMEDIATE'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 500);
\set ON_ERROR_STOP 0
SET CONSTRAINTS ALL IMMEDIATE;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

:q_m1 \gset
EXECUTE nidhi_assert('A1e after A1a-d the balance row is untouched (failed COMMITs rolled everything back)', '3000/3500/3500 v18', :'got');

-- =============================================================================
-- A2. Trap 2 #2 -- lone posting appended to an ALREADY-COMMITTED transaction
-- =============================================================================
\set c 'A2a lone CREDIT SETTLED appended to committed RESERVE tx of i4 rejected at top-level COMMIT'
BEGIN;
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t4r', :'m1', :'m1_se', 'USD', 'CREDIT', 1);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A2b lone CREDIT AVAILABLE appended to committed full-CAPTURE tx of i3 rejected at top-level COMMIT'
BEGIN;
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t3c', :'m1', :'m1_av', 'USD', 'CREDIT', 1000);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A2c lone DEBIT SETTLED appended to committed VOID tx of i2 rejected at top-level COMMIT'
BEGIN;
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t2v', :'m1', :'m1_se', 'USD', 'DEBIT', 2500);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A2d second posting on an account already used by a committed tx (replay of the DEBIT) rejected'
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t4r', :'m1', :'m1_av', 'USD', 'CREDIT', 2000);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23505', :'got');

:q_m1 \gset
EXECUTE nidhi_assert('A2e after A2a-d the balance row is untouched', '3000/3500/3500 v18', :'got');

-- =============================================================================
-- A3. Trap 2 #3 -- direct tampering with mandate_balances
--     Privilege layer answers first (42501) for everything except the one
--     row-lock column, where the trigger guard itself answers (SG007).
-- =============================================================================
\set c 'A3a direct UPDATE of available_minor (mint 1,000,000) denied by privilege'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE mandate_balances SET available_minor = available_minor + 1000000 WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'A3b direct UPDATE of held_minor/settled_minor denied by privilege'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE mandate_balances SET held_minor = 0, settled_minor = 0 WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'A3c direct UPDATE of the one column the app holds UPDATE on (version) rejected by the trigger guard'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE mandate_balances SET version = version + 1 WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG007', :'got');

\set c 'A3d direct INSERT into mandate_balances denied by privilege'
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO mandate_balances (mandate_id, currency, total_budget_minor, available_minor, held_minor, settled_minor)
VALUES (:'m1', 'USD', 10000, 10000, 0, 0);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'A3e direct DELETE from mandate_balances denied by privilege'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM mandate_balances WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

:q_m1 \gset
EXECUTE nidhi_assert('A3f after A3a-e the balance row is untouched', '3000/3500/3500 v18', :'got');

-- =============================================================================
-- A4. Trap 2 #4 -- balanced but illegally routed; no 4th bucket can exist
-- =============================================================================
\set c 'A4a balanced RESERVE routed AVAILABLE -> SETTLED rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 500);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_se', 'USD', 'CREDIT', 500);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A4b balanced RESERVE for the wrong amount (intent 500, postings 400/400) rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 400);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'CREDIT', 400);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A4c CAPTURE pattern mismatch (captured 1000 of 1500 but SETTLED credited 1500, remainder not released) rejected at COMMIT'
SELECT gen_random_uuid() AS tx \gset
BEGIN;
UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = 1000 WHERE intent_id = :'i5';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'i5', :'m1', 'USD', 'CAPTURE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'DEBIT', 1500);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_se', 'USD', 'CREDIT', 1500);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A4d partial CAPTURE that leaks the remainder (DEBIT HELD 1000 / CREDIT SETTLED 1000 on a 1500 hold) rejected at COMMIT'
SELECT gen_random_uuid() AS tx \gset
BEGIN;
UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = 1000 WHERE intent_id = :'i5';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'i5', :'m1', 'USD', 'CAPTURE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'DEBIT', 1000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_se', 'USD', 'CREDIT', 1000);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A4e balanced VOID routed HELD -> SETTLED rejected at top-level COMMIT'
SELECT gen_random_uuid() AS tx \gset
BEGIN;
UPDATE payment_intents SET status = 'VOIDED' WHERE intent_id = :'i4';
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'i4', :'m1', 'USD', 'VOID');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'DEBIT', 2000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_se', 'USD', 'CREDIT', 2000);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A4f a 4th bucket (EXTERNAL_RAIL_CLEARING) is not a member of account_bucket'
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO ledger_accounts (mandate_id, bucket, currency) VALUES (:'m1', 'EXTERNAL_RAIL_CLEARING', 'USD');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '22P02', :'got');

\set c 'A4g app cannot add a 4th bucket to the enum (ALTER TYPE ... ADD VALUE)'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TYPE account_bucket ADD VALUE 'EXTERNAL_RAIL_CLEARING';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'A4h app cannot create an extra ledger account (even with a legal bucket)'
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO ledger_accounts (mandate_id, bucket, currency) VALUES (:'m1', 'MANDATE_SETTLED', 'USD');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'A4i posting to a fabricated account id (off-ledger sink) is a composite-FK violation'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
\set ON_ERROR_STOP 0
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', gen_random_uuid(), 'USD', 'CREDIT', 500);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

:q_m1 \gset
EXECUTE nidhi_assert('A4j after A4a-i the balance row is untouched', '3000/3500/3500 v18', :'got');

-- =============================================================================
-- A5. Trap 2 #5 -- cross-mandate / cross-currency postings (composite FKs, 23503)
-- =============================================================================
\set c 'A5a posting on an M1 (USD) tx that debits M2''s AVAILABLE account'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
\set ON_ERROR_STOP 0
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m2_av', 'USD', 'DEBIT', 500);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

\set c 'A5b posting on an M1 (USD) tx declared in EUR'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
\set ON_ERROR_STOP 0
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'EUR', 'DEBIT', 500);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

\set c 'A5c posting on an M1 tx that claims mandate M2 / EUR with M2''s own account (drain M2 through M1''s tx)'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
\set ON_ERROR_STOP 0
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m2', :'m2_av', 'EUR', 'DEBIT', 500);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

\set c 'A5d ledger_transaction that binds an M1 intent to mandate M2'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set ON_ERROR_STOP 0
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m2', 'EUR', 'RESERVE');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

\set c 'A5e intent against a mandate that does not exist'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', gen_random_uuid(), :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23503', :'got');

:q_m1 \gset
EXECUTE nidhi_assert('A5f after A5a-e M1 is untouched', '3000/3500/3500 v18', :'got');
:q_m2 \gset
EXECUTE nidhi_assert('A5g after A5a-e M2 is untouched', '5000/0/0 v1', :'got');

-- =============================================================================
-- A6. Trap 2 #6 -- intent state machine and state <-> ledger coupling
-- =============================================================================
\set c 'A6a direct INSERT of a payment_intent already in CAPTURED'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, captured_amount_minor, status, stripe_payment_intent, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 500, 'CAPTURED', 'pi_forged_' || :'x', 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A6b direct INSERT of a payment_intent already in CONFIRMING'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, status, stripe_payment_intent, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'CONFIRMING', 'pi_forged_' || :'x', 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A6c RESERVED intent with no RESERVE ledger transaction rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A6d CONFIRMING -> CAPTURED with no CAPTURE ledger transaction rejected at top-level COMMIT'
BEGIN;
UPDATE payment_intents SET status = 'CAPTURED', captured_amount_minor = 1500 WHERE intent_id = :'i5';
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A6e RESERVED -> VOIDED with no VOID ledger transaction rejected at top-level COMMIT'
BEGIN;
UPDATE payment_intents SET status = 'VOIDED' WHERE intent_id = :'i4';
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A6f RESERVED -> FAILED with no VOID ledger transaction rejected at top-level COMMIT'
BEGIN;
UPDATE payment_intents SET status = 'FAILED', failure_code = 'card_declined' WHERE intent_id = :'i4';
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

-- REGRESSION [NIDHI-D9]: ledger -> state coupling. In the Artifact B baseline both
-- of these COMMITs succeeded and led to an I1 overspend (140 committed on a
-- budget of 100 in the recorded probe).
\set c 'A6g [REGRESSION D9] "CAPTURE" ledger tx that releases i4''s hold while i4 stays RESERVED rejected at COMMIT'
SELECT gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'i4', :'m1', 'USD', 'CAPTURE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'DEBIT', 2000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'CREDIT', 2000);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A6h [REGRESSION D9] VOID ledger tx that releases i5''s hold while i5 stays CONFIRMING rejected at COMMIT'
SELECT gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'i5', :'m1', 'USD', 'VOID');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'DEBIT', 1500);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'CREDIT', 1500);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG005', :'got');

\set c 'A6i second RESERVE ledger tx for the same intent (double hold / replay)'
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO ledger_transactions (intent_id, mandate_id, currency, transition_type) VALUES (:'i4', :'m1', 'USD', 'RESERVE');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23505', :'got');

\set c 'A6j terminal CAPTURED -> VOIDED'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET status = 'VOIDED', captured_amount_minor = 0 WHERE intent_id = :'i1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A6k terminal VOIDED -> RESERVED (resurrect a voided intent)'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET status = 'RESERVED' WHERE intent_id = :'i2';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A6l backward CONFIRMING -> RESERVED'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET status = 'RESERVED' WHERE intent_id = :'i5';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A6m RESERVED -> CONFIRMING without a recorded stripe_payment_intent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET status = 'CONFIRMING' WHERE intent_id = :'i4';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

-- REGRESSION [NIDHI-D8]: all four succeeded against the Artifact B baseline.
\set c 'A6n [REGRESSION D8] rewriting captured_amount_minor on an already CAPTURED intent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET captured_amount_minor = 1 WHERE intent_id = :'i1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6o [REGRESSION D8] nulling stripe_payment_intent on a CONFIRMING intent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET stripe_payment_intent = NULL WHERE intent_id = :'i5';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6p [REGRESSION D8] swapping stripe_payment_intent on a CONFIRMING intent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET stripe_payment_intent = 'pi_swapped_' || :'run' WHERE intent_id = :'i5';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6q [REGRESSION D8] replacing the deterministic rail idempotency key'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET rail_confirm_idemp_key = 'confirm_second_attempt_' || :'run' WHERE intent_id = :'i5';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6r mutating authorized_amount_minor of an existing intent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET authorized_amount_minor = 1 WHERE intent_id = :'i4';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6s re-pointing an existing intent to another merchant'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE payment_intents SET merchant_id = 'evil-merchant' WHERE intent_id = :'i4';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A6t replaying an idempotency key for the same agent (I2 unique gate)'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-i4', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '23505', :'got');

SELECT string_agg(format('%s:%s v%s cap=%s', k, status, version, captured_amount_minor), ' ' ORDER BY k) AS got
  FROM (VALUES ('i1', :'i1'::uuid), ('i2', :'i2'::uuid), ('i4', :'i4'::uuid), ('i5', :'i5'::uuid)) v(k, id)
  JOIN payment_intents p ON p.intent_id = v.id \gset
EXECUTE nidhi_assert('A6u after A6a-t the targeted intents are exactly as before',
    'i1:CAPTURED v3 cap=2500 i2:VOIDED v2 cap=0 i4:RESERVED v1 cap=0 i5:CONFIRMING v2 cap=0', :'got');
:q_m1 \gset
EXECUTE nidhi_assert('A6v after A6a-t the balance row is untouched', '3000/3500/3500 v18', :'got');

-- =============================================================================
-- A7. Trap 2 #7 -- terminal mandate states are irreversible
-- =============================================================================
UPDATE spend_mandates SET status = 'REVOKED', revoked_at = NOW(), revocation_reason = 'suite: user revoked' WHERE mandate_id = :'m3';
SELECT COALESCE((SELECT status::text FROM spend_mandates WHERE mandate_id = :'m3'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('A7a (control) app may revoke an ACTIVE mandate', 'REVOKED', :'got');

\set c 'A7b un-revoking a REVOKED mandate (REVOKED -> ACTIVE)'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET status = 'ACTIVE', revoked_at = NULL, revocation_reason = NULL WHERE mandate_id = :'m3';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

\set c 'A7c REVOKED -> SUSPENDED (sideways out of a terminal state)'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET status = 'SUSPENDED', revoked_at = NULL WHERE mandate_id = :'m3';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG004', :'got');

-- =============================================================================
-- A8. The remaining custom codes: SG001, SG002, SG003, SG006, SG008
-- =============================================================================
\set c 'A8a intent against a REVOKED mandate'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m3', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG001', :'got');

\set c 'A8b intent against a SUSPENDED mandate'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m4', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG001', :'got');

\set c 'A8c intent against a mandate whose window has lapsed (status still ACTIVE, expires_at < NOW())'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m5', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG001', :'got');

\set c 'A8d intent against a mandate that is not yet valid (not_before > NOW())'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m6', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG001', :'got');

\set c 'A8e intent by a different agent on someone else''s mandate'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent2', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG001', :'got');

\set c 'A8f intent in EUR against a USD mandate (currency mismatch, raised ahead of the FK)'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'EUR', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG002', :'got');

\set c 'A8g intent for a merchant outside the mandate allowlist'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'evil-merchant', 'USD', 500, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG008', :'got');

\set c 'A8h intent above the per-transaction cap (5001 > 5000)'
SELECT gen_random_uuid() AS x \gset
BEGIN;
\set ON_ERROR_STOP 0
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 5001, 'create_' || :'x', 'confirm_' || :'x');
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG003', :'got');

\set c 'A8i mutating total_budget_minor of a mandate'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET total_budget_minor = 100000000 WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A8j mutating max_per_tx_minor of a mandate'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET max_per_tx_minor = 10000 WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A8k handing a mandate to another agent'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET agent_id = :'agent2' WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

-- REGRESSION [NIDHI-D7]: both succeeded against the Artifact B baseline, after
-- which a lapsed mandate accepted a reserve at the injected merchant.
\set c 'A8l [REGRESSION D7] widening allowed_merchants of a mandate'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET allowed_merchants = array_append(allowed_merchants, 'evil-merchant') WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A8m [REGRESSION D7] extending expires_at of a lapsed mandate'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET expires_at = NOW() + INTERVAL '10 years' WHERE mandate_id = :'m5';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A8n [REGRESSION D7] pulling not_before of a not-yet-valid mandate into the past'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET not_before = NOW() - INTERVAL '1 hour' WHERE mandate_id = :'m6';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

\set c 'A8o mutating the currency of a mandate'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE spend_mandates SET currency = 'EUR' WHERE mandate_id = :'m1';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', 'SG006', :'got');

-- Total-budget overdraw is a DEFERRED check: only the COMMIT can reject it.
\set c 'A8p RESERVE 3001 when only 3000 is available (total budget overdraw) rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 3001, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 3001);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'CREDIT', 3001);
:q_m1 \gset
\set pre :got
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
-- (asserted after the COMMIT on purpose: the pass counter is a session setting,
--  and a setting changed inside a transaction that aborts is rolled back with it)
EXECUTE nidhi_assert('A8p-pre inside that transaction AVAILABLE really was negative before COMMIT (every statement succeeded; only the COMMIT can refuse)', '-1/6501/3500 v20', :'pre');
EXECUTE nidhi_assert(:'c', 'SG003', :'got');
:q_m1 \gset
EXECUTE nidhi_assert('A8q the rejected overdraw left the balance row untouched', '3000/3500/3500 v18', :'got');

-- Boundary: exactly the remaining budget is fine, one minor unit more is not.
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'i6', :'m1', :'agent', 'idem-i6', :'rh', 'merchant-a', 'USD', 3000, 'create_' || :'i6', 'confirm_' || :'i6');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'t6r', :'i6', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t6r', :'m1', :'m1_av', 'USD', 'DEBIT', 3000);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'t6r', :'m1', :'m1_he', 'USD', 'CREDIT', 3000);
COMMIT;
:q_m1 \gset
EXECUTE nidhi_assert('A8r (control) RESERVE of exactly the remaining 3000 commits: budget fully committed', '0/6500/3500 v20', :'got');

\set c 'A8s RESERVE of 1 minor unit on an exhausted mandate rejected at top-level COMMIT'
SELECT gen_random_uuid() AS x, gen_random_uuid() AS tx \gset
BEGIN;
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'x', :'m1', :'agent', 'idem-' || :'x', :'rh', 'merchant-a', 'USD', 1, 'create_' || :'x', 'confirm_' || :'x');
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tx', :'x', :'m1', 'USD', 'RESERVE');
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_av', 'USD', 'DEBIT', 1);
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tx', :'m1', :'m1_he', 'USD', 'CREDIT', 1);
\set ON_ERROR_STOP 0
COMMIT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
EXECUTE nidhi_assert(:'c', 'SG003', :'got');

-- =============================================================================
-- LP. Least privilege: what alaka_app cannot do to the kernel itself
-- =============================================================================
\set c 'LP01 TRUNCATE ledger_postings'
BEGIN;
\set ON_ERROR_STOP 0
TRUNCATE ledger_postings;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP02 TRUNCATE mandate_balances'
BEGIN;
\set ON_ERROR_STOP 0
TRUNCATE mandate_balances;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP03 TRUNCATE spend_mandates CASCADE (wipe the whole ledger)'
BEGIN;
\set ON_ERROR_STOP 0
TRUNCATE spend_mandates CASCADE;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP04 ALTER TABLE mandate_balances DISABLE TRIGGER guard_mandate_balances_write'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TABLE mandate_balances DISABLE TRIGGER guard_mandate_balances_write;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP05 ALTER TABLE ledger_postings DISABLE TRIGGER ALL'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TABLE ledger_postings DISABLE TRIGGER ALL;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP06 ALTER TABLE payment_intents DISABLE TRIGGER USER'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TABLE payment_intents DISABLE TRIGGER USER;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP07 SET session_replication_role = replica (the global "triggers off" switch)'
BEGIN;
\set ON_ERROR_STOP 0
SET session_replication_role = replica;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP08 DROP TRIGGER enforce_tx_balanced_on_posting_insert'
BEGIN;
\set ON_ERROR_STOP 0
DROP TRIGGER enforce_tx_balanced_on_posting_insert ON ledger_postings;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP09 DROP TABLE ledger_postings CASCADE'
BEGIN;
\set ON_ERROR_STOP 0
DROP TABLE ledger_postings CASCADE;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP10 DROP FUNCTION trg_guard_mandate_balances_direct_write() CASCADE'
BEGIN;
\set ON_ERROR_STOP 0
DROP FUNCTION trg_guard_mandate_balances_direct_write() CASCADE;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP11 CREATE OR REPLACE of a guard function with a no-op body'
BEGIN;
\set ON_ERROR_STOP 0
CREATE OR REPLACE FUNCTION trg_guard_mandate_balances_direct_write() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP12 ALTER FUNCTION trg_verify_tx_and_mandate_integrity() (re-own / re-configure a guard)'
BEGIN;
\set ON_ERROR_STOP 0
ALTER FUNCTION trg_verify_tx_and_mandate_integrity() OWNER TO alaka_app;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP13 ALTER TABLE spend_mandates ADD COLUMN'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TABLE spend_mandates ADD COLUMN backdoor TEXT;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP14 ALTER TABLE mandate_balances OWNER TO alaka_app'
BEGIN;
\set ON_ERROR_STOP 0
ALTER TABLE mandate_balances OWNER TO alaka_app;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP15 CREATE TRIGGER on ledger_postings (attach own code to a ledger table)'
BEGIN;
\set ON_ERROR_STOP 0
CREATE TRIGGER nidhi_suite_evil BEFORE INSERT ON ledger_postings FOR EACH ROW EXECUTE FUNCTION trg_forbid_mutation();
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP16 CREATE TEMP TABLE (a table the app would own, i.e. a place to hang its own trigger)'
BEGIN;
\set ON_ERROR_STOP 0
CREATE TEMP TABLE nidhi_suite_probe (x INT);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP17 CREATE TABLE in schema public'
BEGIN;
\set ON_ERROR_STOP 0
CREATE TABLE public.nidhi_suite_probe (x INT);
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP18 CREATE SCHEMA'
BEGIN;
\set ON_ERROR_STOP 0
CREATE SCHEMA nidhi_suite_probe;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP19 SET ROLE alaka_migrator (become the owner)'
BEGIN;
\set ON_ERROR_STOP 0
SET ROLE alaka_migrator;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP20 calling a SECURITY DEFINER trigger function directly'
BEGIN;
\set ON_ERROR_STOP 0
SELECT trg_apply_posting_to_mandate_balance();
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP21 UPDATE of a committed ledger_postings row'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE ledger_postings SET amount_minor = 1 WHERE tx_id = :'t1r';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP22 DELETE of committed ledger_postings rows'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM ledger_postings WHERE tx_id = :'t1r';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP23 UPDATE of a committed ledger_transactions row (relabel RESERVE as VOID)'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE ledger_transactions SET transition_type = 'VOID' WHERE tx_id = :'t4r';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP24 DELETE of a committed ledger_transactions row'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM ledger_transactions WHERE tx_id = :'t4r';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP25 UPDATE of a ledger_accounts row (re-bucket HELD as AVAILABLE)'
BEGIN;
\set ON_ERROR_STOP 0
UPDATE ledger_accounts SET bucket = 'MANDATE_AVAILABLE' WHERE account_id = :'m1_he';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP26 DELETE of a payment_intents row'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM payment_intents WHERE intent_id = :'i4';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP27 DELETE of a spend_mandates row'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM spend_mandates WHERE mandate_id = :'m2';
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

\set c 'LP28 DELETE from processed_webhooks (un-dedupe a webhook so it can be replayed)'
BEGIN;
\set ON_ERROR_STOP 0
DELETE FROM processed_webhooks;
\set got :SQLSTATE
\set ON_ERROR_STOP 1
ROLLBACK;
EXECUTE nidhi_assert(:'c', '42501', :'got');

-- =============================================================================
-- F. Final state: nothing an attack did survived
-- =============================================================================
:q_m1 \gset
EXECUTE nidhi_assert('F01 M1 final balance: only the 6 valid reserves, 2 captures and 1 void are reflected', '0/6500/3500 v20', :'got');

SELECT format('RESERVE=%s CAPTURE=%s VOID=%s postings=%s',
              count(*) FILTER (WHERE transition_type = 'RESERVE'),
              count(*) FILTER (WHERE transition_type = 'CAPTURE'),
              count(*) FILTER (WHERE transition_type = 'VOID'),
              (SELECT count(*) FROM ledger_postings WHERE mandate_id = :'m1')) AS got
  FROM ledger_transactions WHERE mandate_id = :'m1' \gset
EXECUTE nidhi_assert('F02 M1 ledger holds exactly the valid transactions (no attack row survived)', 'RESERVE=6 CAPTURE=2 VOID=1 postings=19', :'got');

SELECT COALESCE(string_agg(status || '=' || n, ' ' ORDER BY status), 'none') AS got
  FROM (SELECT status::text, count(*) AS n FROM payment_intents WHERE agent_id IN (:'agent', :'agent2') GROUP BY status) s \gset
EXECUTE nidhi_assert('F03 this run''s intents are exactly the 6 valid ones', 'CAPTURED=2 CONFIRMING=1 RESERVED=2 VOIDED=1', :'got');

SELECT string_agg(format('%s:%s/%s/%s v%s', v.k, b.available_minor, b.held_minor, b.settled_minor, b.version), ' ' ORDER BY v.k) AS got
  FROM (VALUES ('m2', :'m2'::uuid), ('m3', :'m3'::uuid), ('m4', :'m4'::uuid), ('m5', :'m5'::uuid), ('m6', :'m6'::uuid)) v(k, id)
  JOIN mandate_balances b ON b.mandate_id = v.id \gset
EXECUTE nidhi_assert('F04 the five other mandates were never moved',
    'm2:5000/0/0 v1 m3:5000/0/0 v1 m4:5000/0/0 v1 m5:5000/0/0 v1 m6:5000/0/0 v1', :'got');

SELECT COALESCE((SELECT format('%s %s %s/%s %s kid=%s agent_ok=%s', status, currency, total_budget_minor, max_per_tx_minor,
                                array_to_string(allowed_merchants, '+'), token_kid, (agent_id = :'agent')::text)
                   FROM spend_mandates WHERE mandate_id = :'m1'), 'NO_ROW')
       || ' | m3=' || COALESCE((SELECT status::text FROM spend_mandates WHERE mandate_id = :'m3'), 'NO_ROW')
       || ' | m5_lapsed=' || COALESCE((SELECT (expires_at < NOW())::text FROM spend_mandates WHERE mandate_id = :'m5'), 'NO_ROW')
       || ' | m6_future=' || COALESCE((SELECT (not_before > NOW())::text FROM spend_mandates WHERE mandate_id = :'m6'), 'NO_ROW') AS got \gset
EXECUTE nidhi_assert('F05 mandate terms are exactly as created (m1 terms, m3 still REVOKED, m5 still lapsed, m6 still not yet valid)',
    'ACTIVE USD 10000/5000 merchant-a+merchant-b kid=kid-suite agent_ok=true | m3=REVOKED | m5_lapsed=true | m6_future=true', :'got');

-- I3 over EVERY mandate in the database (this run and all earlier runs):
-- non-negative buckets, avail+held+settled = total, and the materialised row
-- equals the raw SUM of ledger_postings.
SELECT count(*)::text AS got
  FROM mandate_balances b
  LEFT JOIN LATERAL (
        SELECT COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_AVAILABLE' THEN CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END END), 0) AS d_av,
               COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_HELD'      THEN CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END END), 0) AS d_he,
               COALESCE(SUM(CASE WHEN a.bucket = 'MANDATE_SETTLED'   THEN CASE WHEN p.direction = 'CREDIT' THEN p.amount_minor ELSE -p.amount_minor END END), 0) AS d_se
          FROM ledger_postings p JOIN ledger_accounts a ON a.account_id = p.account_id
         WHERE p.mandate_id = b.mandate_id) d ON TRUE
 WHERE b.available_minor < 0 OR b.held_minor < 0 OR b.settled_minor < 0
    OR b.available_minor + b.held_minor + b.settled_minor <> b.total_budget_minor
    OR b.available_minor <> b.total_budget_minor + d.d_av
    OR b.held_minor <> d.d_he
    OR b.settled_minor <> d.d_se \gset
EXECUTE nidhi_assert('F06 I3 holds for every mandate in the database (conservation, non-negativity, balance == SUM(postings))', '0', :'got');

SELECT count(*)::text AS got
  FROM ledger_transactions t
  LEFT JOIN LATERAL (
        SELECT COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'DEBIT'), 0)  AS dr,
               COALESCE(SUM(amount_minor) FILTER (WHERE direction = 'CREDIT'), 0) AS cr,
               count(*) AS n
          FROM ledger_postings p WHERE p.tx_id = t.tx_id) s ON TRUE
 WHERE s.dr <> s.cr OR s.n < 2 \gset
EXECUTE nidhi_assert('F07 every ledger_transaction in the database is balanced (SUM(DEBIT) == SUM(CREDIT), >= 2 postings)', '0', :'got');

-- =============================================================================
-- Summary
-- =============================================================================
SELECT current_setting('nidhi_t.pass') AS npass \gset
SELECT CASE WHEN :'npass' = :'expected_total'
    THEN format('NIDHI ATTACK SUITE: %s/%s cases PASSED, 0 failed  (role=%s, db=%s, run=%s)',
                :'npass', :'expected_total', current_user, current_database(), :'run')
    ELSE format('ASSERTION FAILED -- pass counter %s does not equal the declared total %s (a section was skipped or the total is stale)',
                :'npass', :'expected_total')::integer::text
END;
