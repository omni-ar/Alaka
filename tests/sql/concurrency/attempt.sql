-- =============================================================================
-- Alaka / nidhi -- tests/sql/concurrency/attempt.sql
-- One reservation attempt = ONE transaction (the Phase 1 RESERVE):
--   [SELECT ... FROM mandate_balances FOR UPDATE]      (lockmode = update only)
--   INSERT payment_intents (RESERVED)
--   INSERT ledger_transactions (RESERVE)
--   INSERT ledger_postings DEBIT  MANDATE_AVAILABLE
--   INSERT ledger_postings CREDIT MANDATE_HELD
--   COMMIT                                             (deferred SG003 / SG005 fire here)
--
-- Included by worker.sql; includes ITSELF again to retry (psql has no loops).
-- The first statement that fails is recorded (step name + exact SQLSTATE) and
-- every later step of the attempt is skipped; the transaction is rolled back.
-- =============================================================================
SELECT :attempt + 1                                        AS attempt,
       gen_random_uuid()                                   AS iid,
       gen_random_uuid()                                   AS tid,
       (:'gate_begin'::boolean       AND :attempt = 0)     AS gate_begin_now,
       (:'gate_pre_posting'::boolean AND :attempt = 0)     AS gate_pp_now \gset

\set failed false
\set intx true
\set st 00000
\set at none
\set w_lock -1
\set w_p1 -1
\set w_commit -1
\set w_fail -1

BEGIN ISOLATION LEVEL :iso;
-- First statement of the transaction. Under SERIALIZABLE this is where the
-- snapshot is taken, i.e. BEFORE the in-transaction barrier below.
SELECT extract(epoch FROM clock_timestamp()) AS t0 \gset
\set ta :t0

\if :gate_begin_now
SELECT pg_advisory_xact_lock_shared(:k, :g2) \gset junk_
\endif

-- ---- canonical upfront lock (hardened-pessimistic) ---------------------------
\if :do_lock
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
SELECT 1 AS locked FROM mandate_balances WHERE mandate_id = :'m' FOR UPDATE \gset junk_
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at lock
\else
SELECT round((extract(epoch FROM clock_timestamp()) - :ta) * 1000) AS w_lock \gset
\endif
\endif

-- ---- intent ------------------------------------------------------------------
\if :failed
\else
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
INSERT INTO payment_intents (intent_id, mandate_id, agent_id, idempotency_key, request_hash, merchant_id, currency, authorized_amount_minor, rail_create_idemp_key, rail_confirm_idemp_key)
VALUES (:'iid', :'m', :'agent', 'idem-' || :'tag' || '-' || :'sid', :'rh', 'merchant-a', 'USD', :amount, 'create_' || :'iid', 'confirm_' || :'iid');
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at intent
\endif
\endif

-- ---- ledger transaction ------------------------------------------------------
\if :failed
\else
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
INSERT INTO ledger_transactions (tx_id, intent_id, mandate_id, currency, transition_type) VALUES (:'tid', :'iid', :'m', 'USD', 'RESERVE');
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at ledger_tx
\endif
\endif

\if :failed
\else
\if :sleep_after_intent
SELECT pg_sleep(:sleep_s) \gset junk_
\endif
\if :gate_pp_now
SELECT pg_advisory_xact_lock_shared(:k, :g2) \gset junk_
\endif
\endif

-- ---- posting 1: DEBIT MANDATE_AVAILABLE --------------------------------------
-- (its AFTER trigger UPDATEs the mandate_balances row)
\if :failed
\else
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tid', :'m', :'av', 'USD', 'DEBIT', :amount);
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at posting1
\else
SELECT round((extract(epoch FROM clock_timestamp()) - :ta) * 1000) AS w_p1 \gset
\endif
\endif

\if :failed
\else
\if :sleep_between_postings
SELECT pg_sleep(:sleep_s) \gset junk_
\endif
\endif

-- ---- posting 2: CREDIT MANDATE_HELD ------------------------------------------
\if :failed
\else
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
INSERT INTO ledger_postings (tx_id, mandate_id, account_id, currency, direction, amount_minor) VALUES (:'tid', :'m', :'he', 'USD', 'CREDIT', :amount);
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at posting2
\endif
\endif

\if :failed
\else
\if :sleep_before_commit
SELECT pg_sleep(:sleep_s) \gset junk_
\endif
\endif

-- ---- COMMIT: the DEFERRED constraint triggers run here -----------------------
\if :failed
\else
SELECT extract(epoch FROM clock_timestamp()) AS ta \gset
COMMIT;
\if :ERROR
\set failed true
\set st :SQLSTATE
\set at commit
\endif
-- a COMMIT that raised has already rolled the transaction back
\set intx false
\endif

\if :intx
ROLLBACK;
\endif

SELECT extract(epoch FROM clock_timestamp())                               AS t1,
       round((extract(epoch FROM clock_timestamp()) - :ta) * 1000)         AS w_last,
       (:retry = 1 AND :'st' IN ('40001', '40P01') AND :attempt < :max_attempts) AS again \gset
\if :failed
\set w_fail :w_last
\else
\set w_commit :w_last
\endif

\echo ATT|:sid|:attempt|:st|:at|:t0|:t1|:w_lock|:w_p1|:w_commit|:w_fail

\if :again
-- exponential backoff with full jitter: sleep U(0, min(cap, base * 2^(attempt-1)))
SELECT pg_sleep(random() * least(:backoff_cap_ms, :backoff_base_ms * power(2, :attempt - 1)) / 1000.0) \gset junk_
\ir attempt.sql
\endif
