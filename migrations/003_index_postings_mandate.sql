-- =============================================================================
-- Alaka / nidhi -- migrations/003_index_postings_mandate.sql
--
-- Index ledger_postings by mandate.
--
-- The deferred integrity trigger trg_verify_tx_and_mandate_integrity (001) runs,
-- at COMMIT of every money-moving transaction,
--     SELECT SUM(...) FROM ledger_postings p JOIN ledger_accounts a ...
--      WHERE p.mandate_id = NEW.mandate_id
-- to cross-check the materialised balance against the raw postings. 001 has no
-- index leading on ledger_postings.mandate_id (its indexes lead on posting_id
-- and tx_id), so that query is a sequential scan of the whole table:
--   * every commit costs O(all postings of all mandates), growing forever;
--   * under SERIALIZABLE a sequential scan takes a relation-level SIREAD
--     predicate lock, so every concurrent writer of ledger_postings conflicts
--     with every other -- writers on unrelated mandates abort each other with
--     40001. Measured before this migration (ConcurrencyStormTest, 10 mandates
--     x 5 threads): 1,093-1,121 serialization failures, more than 50 threads on
--     ONE mandate produce (853-865).
-- With this index the predicate lock covers the scanned index range instead.
--
-- Run as alaka_migrator, after 002. Plain CREATE INDEX (not CONCURRENTLY): it
-- runs inside the migration's single transaction, on a table that is small
-- wherever this migration is applied for the first time.
-- =============================================================================

DO $$
BEGIN
    IF current_user <> 'alaka_migrator' THEN
        RAISE EXCEPTION '003_index_postings_mandate.sql must be applied as alaka_migrator, not %', current_user;
    END IF;
END;
$$;

SET search_path = public;

CREATE INDEX ledger_postings_mandate_idx ON ledger_postings (mandate_id);
