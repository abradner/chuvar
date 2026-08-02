-- Reverses the least-privilege roles.
--
-- DROP OWNED BY before DROP ROLE: a role cannot be dropped while any privilege
-- still references it, and these roles hold grants (plus default-privilege
-- entries) rather than owning objects. DROP OWNED clears both, and because they
-- own nothing it destroys no data.
--
-- Roles are cluster-wide. If another database in this cluster also ran this
-- migration, dropping the role here revokes its privileges there too — which is
-- why this is a deliberate rollback step, not a routine one.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM chuvar_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE, SELECT ON SEQUENCES FROM chuvar_app;

DROP OWNED BY chuvar_app, chuvar_agent;

DROP ROLE IF EXISTS chuvar_app;
DROP ROLE IF EXISTS chuvar_agent;
