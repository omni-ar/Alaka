-- =============================================================================
-- Alaka / nidhi -- tests/sql/concurrency/worker.sql
-- One reservation session of a concurrency wave. Runs as alaka_app.
--
-- psql variables (all required, supplied by driver.sh):
--   sid          session label (01..N)
--   m            mandate_id            agent   agent_id of the mandate
--   av / he      account_id of the mandate's MANDATE_AVAILABLE / MANDATE_HELD
--   rh           64-hex request hash   tag     unique wave tag (idempotency keys)
--   amount       amount to reserve (minor units)
--   iso          READ COMMITTED | SERIALIZABLE
--   lockmode     update  -> canonical upfront SELECT ... FOR UPDATE on mandate_balances
--                none    -> no upfront lock at all
--   gate2_at     none | begin | pre_posting   where the in-transaction barrier sits
--   sleep_at     none | after_intent | between_postings | before_commit
--   sleep_s      seconds to pg_sleep at sleep_at (widens the race window)
--   k, g1, g2    advisory barrier ids (see coordinator.sql)
--   retry        1 -> retry on 40001 / 40P01 with exponential backoff + full jitter
--   max_attempts retry budget
--
-- Output: one line per attempt, written by attempt.sql:
--   ATT|sid|attempt|sqlstate|failed_at|t0|t1|w_lock_ms|w_posting1_ms|w_commit_ms|w_fail_ms
-- sqlstate 00000 = that attempt COMMITTED. The last ATT line of a session is
-- its final outcome. Nothing in here swallows an error: every statement's
-- SQLSTATE is captured from psql (:SQLSTATE) right after it ran.
-- =============================================================================
\set QUIET on
\pset pager off
\pset format unaligned
\pset tuples_only on

SELECT (:'lockmode' = 'update')            AS do_lock,
       (:'gate2_at' = 'begin')             AS gate_begin,
       (:'gate2_at' = 'pre_posting')       AS gate_pre_posting,
       (:'sleep_at' = 'after_intent')      AS sleep_after_intent,
       (:'sleep_at' = 'between_postings')  AS sleep_between_postings,
       (:'sleep_at' = 'before_commit')     AS sleep_before_commit \gset

\set attempt 0

-- Barrier 1 (before BEGIN): park until the coordinator has seen all N sessions
-- connected and waiting, then start together.
SELECT pg_advisory_lock_shared(:k, :g1) \gset junk_
SELECT pg_advisory_unlock_shared(:k, :g1) \gset junk_

\ir attempt.sql
