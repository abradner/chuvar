-- Found in review (Copilot): requested_ttl_seconds had no lower bound, so a
-- negative value would produce an already-expired grant at approval time.
-- NULL already means "no expiry requested" (grant_requests.go's doc comment
-- on RequestGrant/ApproveGrantRequest), so there's no ambiguity a negative
-- value could usefully represent — mcptools/request_grant.go now also rejects
-- a negative ttl_seconds at the MCP boundary rather than silently treating it
-- as "omitted"; this constraint is the same rule enforced at the schema level
-- for any future write path.
ALTER TABLE grant_requests ADD CONSTRAINT grant_requests_ttl_positive CHECK (requested_ttl_seconds IS NULL OR requested_ttl_seconds > 0);
