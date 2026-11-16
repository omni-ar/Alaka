-- =============================================================================
-- Alaka / nidhi -- tests/sql/concurrency/wait_until.sql
-- Poll helper for the coordinator / controller sessions (\ir wait_until.sql).
--
-- Blocks until the boolean query stored in the session setting nidhi_c.cond
-- returns true, polling every 5 ms. Raises (SQLSTATE NC001) after
-- nidhi_c.timeout_s seconds, so a barrier that never fills fails the run
-- instead of hanging it or silently releasing a half-full barrier.
--
-- pg_locks is read live from shared memory; pg_stat_activity is cached per
-- transaction, hence pg_stat_clear_snapshot() on every iteration.
-- alaka_app owns nothing and cannot CREATE FUNCTION; an anonymous DO block is
-- the only loop available to it.
-- =============================================================================
DO $nidhi_wait$
DECLARE
    v_ok       boolean;
    v_deadline timestamptz := clock_timestamp()
                              + make_interval(secs => current_setting('nidhi_c.timeout_s')::double precision);
BEGIN
    LOOP
        PERFORM pg_stat_clear_snapshot();
        EXECUTE current_setting('nidhi_c.cond') INTO v_ok;
        EXIT WHEN v_ok;
        IF clock_timestamp() > v_deadline THEN
            RAISE EXCEPTION 'NIDHI_CONC_TIMEOUT after % s waiting for: %',
                current_setting('nidhi_c.timeout_s'), current_setting('nidhi_c.cond')
                USING ERRCODE = 'NC001';
        END IF;
        PERFORM pg_sleep(0.005);
    END LOOP;
END
$nidhi_wait$;
