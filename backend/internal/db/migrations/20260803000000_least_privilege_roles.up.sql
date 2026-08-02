-- Least-privilege database roles (ticket E8).
--
-- Every binary currently connects as the same role, which the Postgres image
-- makes a superuser and the database owner. The exposure that matters is not
-- DDL — it is that `cmd/mcpserver`, which runs inside an agent's own process
-- tree, holds credentials permitting:
--
--     INSERT INTO grants (subject, kind, depth, expires_at) VALUES (...);
--     INSERT INTO grant_scopes (grant_id, scope) VALUES (...);
--
-- i.e. an agent can grant itself every scope, with no approval, and write a
-- matching audit_log row so it reads as legitimate. That is the project's
-- premise defeated in two statements. Schema mutation is trivial beside it.
--
-- What this buys, in the trust boundary's terms (AGENTS.md §3.0): it converts
-- *ambient reach* (credentials sitting in the process's environment) into an
-- *attack-shaped action* (reaching the database some other way). It does not
-- prevent a determined caller — on a single-user host `docker exec` still
-- yields a superuser shell — and it is not claimed to. Detection of that is
-- ticket E4.
--
-- Roles are created NOLOGIN and without passwords: a credential belongs to a
-- deployment, not to a migration in a public repository. Granting LOGIN and
-- setting a password is an operator step (docs/operations.md). Until that
-- happens the roles exist but are unused, and `apiserver`/`mcpserver` log a
-- warning saying so, rather than this migration quietly implying a protection
-- nothing has adopted.

-- Roles are cluster-global, so "create it if absent" is not safe on its own: a
-- role of the same name may already exist from another Chuvar database in this
-- cluster — quite possibly with LOGIN, a password, and other members. Adopting
-- it silently would hand this database's data to every principal that already
-- holds it, with no provisioning step and nothing to notice.
--
-- So each role is stamped with a COMMENT naming the database that created it,
-- and adoption is verified rather than assumed:
--   * absent            -> create and stamp
--   * stamped for us    -> reuse (a re-run after a rollback)
--   * anything else     -> refuse, loudly, and name the collision
--
-- Refusing is the right failure: sharing a role across databases is a decision
-- with cross-deployment consequences, and it should be made by a person who
-- knows both, not by whichever migration happened to run second.
DO $$
DECLARE
    r          text;
    stamp      text := 'chuvar-role for database ' || current_database();
    existing   text;
BEGIN
    FOREACH r IN ARRAY ARRAY['chuvar_app', 'chuvar_agent'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
            EXECUTE format('COMMENT ON ROLE %I IS %L', r, stamp);
        ELSE
            SELECT pg_catalog.shobj_description(oid, 'pg_authid') INTO existing
            FROM pg_roles WHERE rolname = r;

            IF existing IS DISTINCT FROM stamp THEN
                RAISE EXCEPTION
                    'role % already exists in this cluster and was not created for database % (comment: %). Refusing to grant it access: it may belong to another Chuvar deployment, and adopting it would share this database with every principal that already holds it. Either drop it, or run this deployment in its own cluster. See docs/operations.md.',
                    r, current_database(), coalesce(existing, '(none)');
            END IF;
        END IF;
    END LOOP;
END $$;

GRANT USAGE ON SCHEMA public TO chuvar_app, chuvar_agent;

-- chuvar_app — apiserver's runtime role. Full DML, no DDL. Permanent: this
-- survives ticket E3, because apiserver should not be able to reshape the
-- schema at request-handling time regardless of what mcpserver holds.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO chuvar_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO chuvar_app;

-- chuvar_agent — mcpserver's role, derived from what the code actually calls
-- (ListGrants, GrantedScopeDepths, SearchFacts, ProposeDiff, RequestGrant,
-- LogAudit) rather than from what seemed plausible.
--
GRANT SELECT ON grants, grant_scopes, facts, fact_scopes TO chuvar_agent;

-- staged_diffs and grant_requests get INSERT plus *column-level* SELECT on only
-- the three columns the database generates.
--
-- Postgres requires SELECT on every column a RETURNING clause reads, and those
-- two inserts used to return the whole row — which forced a table-wide SELECT
-- grant, and with it the ability to read every other subject's proposed content
-- and stated justifications. That is a cross-subject read in a system whose
-- entire premise is that subjects see only what they are granted.
--
-- The fix was to stop echoing the caller's own input back: InsertStagedDiff and
-- InsertGrantRequest now return `id, status, created_at`, and the store rebuilds
-- the rest from what it just sent. The privilege narrows to match. An agent can
-- now write a proposal and learn its id, and read nothing else.
GRANT INSERT ON staged_diffs, grant_requests TO chuvar_agent;
GRANT SELECT (id, status, created_at) ON staged_diffs TO chuvar_agent;
GRANT SELECT (id, status, created_at) ON grant_requests TO chuvar_agent;

-- audit_log is INSERT without SELECT, and that asymmetry is deliberate.
-- InsertAuditLog has no RETURNING clause, so nothing breaks — and it means an
-- agent can append to the audit trail but never read it back. Append-only from
-- the agent's side (CLAUDE.md principle 12), and it cannot enumerate what it
-- or anyone else has done.
GRANT INSERT ON audit_log TO chuvar_agent;

-- Deliberately absent from every grant above: reviewer_tokens and data_keys.
-- mcpserver touches neither, so it gets neither — not even SELECT. Their
-- contents are already hashed or sealed, so this is defence in depth rather
-- than the primary control, but there is no reason to hand an agent-side
-- process the ciphertext and wrapped keys it has no use for.

-- Future tables: chuvar_app is granted automatically, chuvar_agent is NOT.
-- New tables should default to invisible to the agent and be widened only on
-- purpose — a table added six months from now should not silently become
-- agent-readable because someone forgot this file exists.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chuvar_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO chuvar_app;

-- schema_migrations is golang-migrate's bookkeeping, not application data, so
-- narrow it back after the blanket grant above swept it up.
--
-- Both services read it at boot (db.CheckSchema verifies the schema is current
-- without holding authority to change it), so both need SELECT. Neither may
-- write it: a service that can forge a version or clear the dirty flag can talk
-- its way past the very check that stops it running against a schema it does not
-- understand. Only cmd/migrate, connecting as the owner, writes this table.
--
-- Found by running mcpserver under chuvar_agent rather than by the privilege
-- tests, which had been exercising CheckSchema on the admin pool and so never
-- noticed the missing grant.
REVOKE ALL ON schema_migrations FROM chuvar_app, chuvar_agent;
GRANT SELECT ON schema_migrations TO chuvar_app, chuvar_agent;
