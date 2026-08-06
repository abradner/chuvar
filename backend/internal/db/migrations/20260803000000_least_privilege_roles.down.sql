-- Reverses this database's grants. It deliberately does NOT drop the roles.
--
-- Roles are cluster-global but DROP OWNED BY only clears dependencies in the
-- current database, so if these roles hold privileges in another Chuvar database
-- the subsequent DROP ROLE fails — and because each database's rollback runs in
-- its own transaction, there is no ordering that clears every dependency first.
-- The rollback would then fail partway and leave this database's grants intact,
-- which is a worse outcome than leaving two unused roles behind.
--
-- So: revoke everything this database granted, and stop. A leftover NOLOGIN role
-- with no privileges is inert. Dropping it is a cluster-level operator action,
-- not a per-database migration step (docs/operations.md).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM chuvar_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM chuvar_app;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM chuvar_app, chuvar_agent;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM chuvar_app, chuvar_agent;
REVOKE USAGE ON SCHEMA public FROM chuvar_app, chuvar_agent;
