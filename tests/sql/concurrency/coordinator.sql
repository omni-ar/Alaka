-- =============================================================================
-- Alaka / nidhi -- tests/sql/concurrency/coordinator.sql
-- Barrier coordinator + lock sampler for one wave of N concurrent sessions.
-- Runs as alaka_app in its own session, started BEFORE the workers.
--
-- psql variables (all required):
--   k        advisory-lock namespace of this run (int4 > 0)
--   g1       gate 1 id: every worker blocks on it BEFORE its BEGIN
--   g2       gate 2 id: every worker blocks on it INSIDE its first transaction
--   use_g2   true | false
--   n        number of workers to wait for at each gate
--   prefix   application_name prefix shared by exactly this wave's workers
--
-- What it does
--   1. takes both gates exclusively (workers ask for them in shared mode);
--   2. waits until pg_locks shows n ungranted requests on gate 1, releases it;
--   3. if use_g2: waits until n sessions wait on gate 2 -- at that instant all
--      n transactions are open at the same time -- records how many of them
--      already hold a real transaction id (i.e. have written), releases it;
--   4. samples pg_locks / pg_stat_activity every ~5 ms until every worker has
--      disconnected, recording the peak number of simultaneously open write
--      transactions, the peak number of row-lock waiters, and a histogram of
--      WHICH statement was blocked on WHICH lock type.
--   5. prints one line:  COORD|key=value|...
--
-- A barrier that does not fill within nidhi_c.timeout_s raises NC001; with
-- ON_ERROR_STOP the coordinator then exits non-zero and the driver fails the
-- wave (its session-level gates vanish with the session, so workers never hang).
-- =============================================================================
\set ON_ERROR_STOP 1
\set QUIET on
\pset pager off
\pset format unaligned
\pset tuples_only on

SELECT set_config('nidhi_c.timeout_s', '60', false) AS a,
       set_config('nidhi_c.prefix', :'prefix', false) AS b \gset junk_

SELECT pg_advisory_lock(:k, :g1) \gset junk_
\if :use_g2
SELECT pg_advisory_lock(:k, :g2) \gset junk_
\endif
\echo COORD_READY

-- ---- gate 1: all n sessions connected and blocked before BEGIN ---------------
SELECT set_config('nidhi_c.cond',
    format('SELECT count(*) >= %s FROM pg_locks WHERE locktype = ''advisory'' AND classid = %s AND objid = %s AND objsubid = 2 AND NOT granted',
           :n, :k, :g1), false) \gset junk_
\ir wait_until.sql
SELECT count(*) AS gate1_waiters FROM pg_locks
 WHERE locktype = 'advisory' AND classid = :k AND objid = :g1 AND objsubid = 2 AND NOT granted \gset
SELECT pg_advisory_unlock(:k, :g1) \gset junk_

-- ---- gate 2: all n transactions open at the same instant ---------------------
\set gate2_waiters -1
\set gate2_xids -1
\if :use_g2
SELECT set_config('nidhi_c.cond',
    format('SELECT count(*) >= %s FROM pg_locks WHERE locktype = ''advisory'' AND classid = %s AND objid = %s AND objsubid = 2 AND NOT granted',
           :n, :k, :g2), false) \gset junk_
\ir wait_until.sql
SELECT pg_stat_clear_snapshot() \gset junk_
SELECT count(*) AS gate2_waiters,
       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM pg_locks x
                                       WHERE x.pid = l.pid AND x.locktype = 'transactionid' AND x.granted)) AS gate2_xids
  FROM pg_locks l
  JOIN pg_stat_activity a ON a.pid = l.pid
 WHERE l.locktype = 'advisory' AND l.classid = :k AND l.objid = :g2 AND l.objsubid = 2 AND NOT l.granted
   AND starts_with(a.application_name, :'prefix')
   AND a.xact_start IS NOT NULL \gset
SELECT pg_advisory_unlock(:k, :g2) \gset junk_
\endif

-- ---- sampler -----------------------------------------------------------------
DO $nidhi_sampler$
DECLARE
    v_prefix    text := current_setting('nidhi_c.prefix');
    v_alive     int;
    v_xids      int;
    v_waiters   int;
    v_peak_xids int := 0;
    v_peak_wait int := 0;
    v_samples   int := 0;
    v_hist      jsonb := '{}'::jsonb;
    v_out       text;
    r           record;
    v_deadline  timestamptz := clock_timestamp() + interval '150 seconds';
BEGIN
    LOOP
        PERFORM pg_stat_clear_snapshot();
        v_samples := v_samples + 1;

        SELECT count(*) INTO v_alive
          FROM pg_stat_activity a
         WHERE starts_with(a.application_name, v_prefix);

        -- sessions of this wave that hold a real xid right now = open write transactions
        SELECT count(DISTINCT l.pid) INTO v_xids
          FROM pg_locks l
          JOIN pg_stat_activity a ON a.pid = l.pid
         WHERE starts_with(a.application_name, v_prefix)
           AND l.locktype = 'transactionid' AND l.granted;
        v_peak_xids := greatest(v_peak_xids, v_xids);

        v_waiters := 0;
        FOR r IN
            SELECT CASE
                       WHEN a.query LIKE '%FOR UPDATE%'                       THEN 'balance_for_update'
                       WHEN a.query LIKE 'INSERT INTO payment_intents%'       THEN 'intent_insert'
                       WHEN a.query LIKE 'INSERT INTO ledger_transactions%'   THEN 'ledger_tx_insert'
                       WHEN a.query LIKE 'INSERT INTO ledger_postings%DEBIT%' THEN 'posting1_insert'
                       WHEN a.query LIKE 'INSERT INTO ledger_postings%CREDIT%' THEN 'posting2_insert'
                       WHEN a.query LIKE 'COMMIT%'                            THEN 'commit'
                       ELSE 'other'
                   END || ':' || l.locktype AS key,
                   count(*) AS c
              FROM pg_locks l
              JOIN pg_stat_activity a ON a.pid = l.pid
             WHERE starts_with(a.application_name, v_prefix)
               AND NOT l.granted
               AND l.locktype <> 'advisory'
             GROUP BY 1
        LOOP
            v_waiters := v_waiters + r.c;
            v_hist := jsonb_set(v_hist, ARRAY[r.key], to_jsonb(COALESCE((v_hist ->> r.key)::int, 0) + r.c));
        END LOOP;
        v_peak_wait := greatest(v_peak_wait, v_waiters);

        EXIT WHEN v_alive = 0;
        IF clock_timestamp() > v_deadline THEN
            RAISE EXCEPTION 'NIDHI_CONC_TIMEOUT: % worker session(s) still connected after 150 s', v_alive
                USING ERRCODE = 'NC001';
        END IF;
        PERFORM pg_sleep(0.004);
    END LOOP;

    SELECT COALESCE(string_agg(key || '=' || value, ',' ORDER BY key), 'none') INTO v_out
      FROM jsonb_each_text(v_hist);

    PERFORM set_config('nidhi_c.peak_xids', v_peak_xids::text, false),
            set_config('nidhi_c.peak_wait', v_peak_wait::text, false),
            set_config('nidhi_c.samples',   v_samples::text,   false),
            set_config('nidhi_c.blocked',   v_out,             false);
END
$nidhi_sampler$;

SELECT format('COORD|gate1_waiters=%s|gate2_waiters=%s|gate2_xids=%s|peak_xids=%s|peak_lock_waiters=%s|samples=%s|blocked=%s',
              :gate1_waiters, :gate2_waiters, :gate2_xids,
              current_setting('nidhi_c.peak_xids'), current_setting('nidhi_c.peak_wait'),
              current_setting('nidhi_c.samples'), current_setting('nidhi_c.blocked'));
