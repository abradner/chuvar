-- Mirrors 20260803000000_least_privilege_roles.down.sql: revoke everything
-- this database granted and stop. Does not DROP ROLE — a NOLOGIN role with no
-- privileges is inert, and dropping a cluster-global role is an operator
-- action (docs/operations.md), not a per-database migration step.
REVOKE SELECT ON schema_migrations FROM chuvar_broker;
REVOKE INSERT ON audit_log FROM chuvar_broker;
REVOKE SELECT ON grants, grant_scopes, capability_grant_identities, capability_grant_tokens FROM chuvar_broker;
REVOKE USAGE ON SCHEMA public FROM chuvar_broker;
