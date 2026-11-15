-- =============================================================================
-- Alaka / nidhi -- 000_roles.sql
-- Least-privilege role separation for the double-entry ledger kernel.
--
--   alaka_migrator : owns every nidhi schema object and is the only role that
--                    runs DDL (migrations/001_init_nidhi_ledger.sql onwards).
--   alaka_app      : the runtime role used by alaka-core / yaksha. It gets only
--                    the DML granted at the bottom of 001. It owns nothing, so
--                    it cannot ALTER / DROP / TRUNCATE tables, disable or drop
--                    triggers, replace trigger functions, or create objects
--                    (not even temporary ones) in this database.
--
-- HOW TO APPLY: as a superuser, connected to the target database, e.g.
--   psql -v ON_ERROR_STOP=1 --single-transaction -U postgres -d alaka -f 000_roles.sql
--
-- Idempotent: safe to re-run at any time (before or after 001).
-- Pure SQL on purpose (no psql meta-commands) so any client can apply it.
--
-- !!! DEV-ONLY PASSWORDS !!!  The two passwords below exist for local Docker
-- development and CI only. Any shared / staging / production environment must
-- override them out-of-band (ALTER ROLE ... PASSWORD from a secret store) and
-- must never reuse these literals.
-- =============================================================================

-- 1. Roles (CREATE ROLE has no IF NOT EXISTS; guard it so re-runs are no-ops).
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'alaka_migrator') THEN
        CREATE ROLE alaka_migrator;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'alaka_app') THEN
        CREATE ROLE alaka_app;
    END IF;
END
$roles$;

-- 2. Pin the role attributes on every run (also repairs drift on re-run).
--    Neither role is a superuser, can create roles/databases, replicate, or
--    bypass row security. NOINHERIT: no privilege ever arrives implicitly.
ALTER ROLE alaka_migrator WITH
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD 'alaka_migrator_dev_only';   -- DEV-ONLY, see header

ALTER ROLE alaka_app WITH
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD 'alaka_app_dev_only';        -- DEV-ONLY, see header

-- 3. Database-level privileges (database name resolved at run time so the same
--    file works for the dev database and for throw-away test databases).
--    PUBLIC loses CREATE (schemas) and TEMPORARY: the runtime role must not be
--    able to own *any* relation, because a role that owns a table can attach a
--    trigger to it and reach pg_trigger_depth() > 1 on its own terms.
DO $db$
BEGIN
    EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM alaka_app', current_database());
    EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM alaka_migrator', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO alaka_migrator, alaka_app', current_database());
END
$db$;

-- 4. Schema-level privileges. The migrator may create (and therefore own)
--    objects in public; the app may only look names up.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;          -- already the PG15+ default; explicit on purpose
REVOKE ALL    ON SCHEMA public FROM alaka_app;
GRANT  USAGE  ON SCHEMA public TO alaka_app;
GRANT  USAGE, CREATE ON SCHEMA public TO alaka_migrator;

-- 5. Invariants of the separation itself. Fail loudly if someone has widened
--    the runtime role (membership in the owner role would silently hand it
--    every DDL right this file exists to withhold).
DO $verify$
DECLARE
    v_bad TEXT;
BEGIN
    SELECT string_agg(r.rolname, ', ')
      INTO v_bad
      FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
      JOIN pg_catalog.pg_roles g ON g.oid = m.member
     WHERE g.rolname = 'alaka_app';

    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'LEAST_PRIVILEGE_VIOLATION: alaka_app must not be a member of any role (member of: %)', v_bad
            USING ERRCODE = '42501';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
         WHERE rolname IN ('alaka_app', 'alaka_migrator')
           AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'LEAST_PRIVILEGE_VIOLATION: alaka_app / alaka_migrator carry an elevated role attribute'
            USING ERRCODE = '42501';
    END IF;

    IF has_database_privilege('alaka_app', current_database(), 'CREATE')
       OR has_database_privilege('alaka_app', current_database(), 'TEMPORARY')
       OR has_schema_privilege('alaka_app', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'LEAST_PRIVILEGE_VIOLATION: alaka_app can still create objects in database %', current_database()
            USING ERRCODE = '42501';
    END IF;
END
$verify$;
