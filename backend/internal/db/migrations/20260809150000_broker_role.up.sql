-- chuvar_broker: brokerd's own least-privilege role (AGENTS.md §3.6 — "before
-- adding a binary or moving work between them, place it on this table").
-- brokerd is a new, distinctly-trusted binary: it holds decrypted signing
-- key material in process memory (a root of trust apiserver/mcpserver don't
-- carry), so it gets its own role rather than reusing chuvar_app's full-DML
-- grant or chuvar_agent's memory-shaped one — neither is the right shape.
--
-- Same stamped-role pattern as chuvar_app/chuvar_agent
-- (20260803000000_least_privilege_roles.up.sql): NOLOGIN and passwordless by
-- default (a credential belongs to a deployment, not a public repository),
-- refuses to adopt a same-named role from a different Chuvar database, and
-- provisioning (GRANT LOGIN + password) is an operator step, documented in
-- docs/operations.md.
DO $$
DECLARE
    stamp    text := 'chuvar-role for database ' || current_database();
    existing text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chuvar_broker') THEN
        EXECUTE 'CREATE ROLE chuvar_broker NOLOGIN';
        EXECUTE format('COMMENT ON ROLE chuvar_broker IS %L', stamp);
    ELSE
        SELECT pg_catalog.shobj_description(oid, 'pg_authid') INTO existing
        FROM pg_roles WHERE rolname = 'chuvar_broker';

        IF existing IS DISTINCT FROM stamp THEN
            RAISE EXCEPTION
                'role chuvar_broker already exists in this cluster and was not created for database % (comment: %). Refusing to grant it access: it may belong to another Chuvar deployment. Either drop it, or run this deployment in its own cluster. See docs/operations.md.',
                current_database(), coalesce(existing, '(none)');
        END IF;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO chuvar_broker;

-- Read-only over exactly the consent-plane tables brokerd's grant cache
-- loads at boot and on each revocation-watch refresh (internal/broker/cache.go)
-- — grants/grant_scopes for the base grant shape (kind='capability' rows
-- only, enforced in the query, not the grant), plus the two tables this
-- migration's sibling added for signing-specific content.
--
-- Deliberately absent: facts, fact_scopes, staged_diffs, reviewer_tokens,
-- data_keys. brokerd never touches the facts path (capability-broker.md's
-- architecture diagram: "brokerd never reads facts") — granting SELECT on
-- tables the code never queries is exactly the ambient-authority-by-omission
-- AGENTS.md §3.6 exists to prevent ("a table added six months from now
-- should not silently become [over-broad] because someone forgot this file
-- exists" — the same discipline applies to a new role as to a new table).
GRANT SELECT ON grants, grant_scopes, capability_grant_identities, capability_grant_tokens TO chuvar_broker;

-- Append-only, same posture and same reasoning as chuvar_agent's audit_log
-- grant: brokerd can attest what it signed but can never read the trail back
-- (including its own past entries) or enumerate other subjects' history.
GRANT INSERT ON audit_log TO chuvar_broker;

-- schema_migrations: SELECT only, matching chuvar_app/chuvar_agent — brokerd
-- calls db.CheckSchema (verify, never migrate) exactly like mcpserver does.
GRANT SELECT ON schema_migrations TO chuvar_broker;

-- New tables default to invisible to chuvar_broker too, same as
-- chuvar_agent — widening is always a deliberate, separate act. (No
-- `ALTER DEFAULT PRIVILEGES ... TO chuvar_broker` line here, on purpose;
-- that absence *is* the policy, mirroring how chuvar_agent's grant in
-- 20260803000000 also adds no default-privilege line for it.)
