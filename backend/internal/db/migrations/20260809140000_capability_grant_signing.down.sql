DROP TRIGGER IF EXISTS grants_notify_revoked ON grants;
DROP FUNCTION IF EXISTS chuvar_notify_grant_revoked();
DROP TABLE IF EXISTS capability_grant_tokens;
DROP TABLE IF EXISTS capability_grant_identities;
