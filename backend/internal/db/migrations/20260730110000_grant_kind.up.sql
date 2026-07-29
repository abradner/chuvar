-- Generalises the consent primitive (grants/grant_requests) beyond memory. The
-- Agent Capability Broker workstream (Notion) reuses these same tables for a
-- different noun entirely — capabilities (git commit signing first) rather than
-- facts — on the stated principle "same grants/grant_scopes/audit_log schema,
-- different noun." depth (summary/facts/full) is meaningful only for memory
-- grants; a capability grant has no equivalent concept, so rather than force a
-- vocabulary mismatch or stand up a second, parallel grants table, this adds a
-- `kind` discriminator and makes depth conditionally required.
--
-- Postgres CHECK constraints pass on NULL (the expression evaluates to UNKNOWN,
-- which satisfies a CHECK) unless a constraint explicitly tests IS NOT NULL — so
-- the original `CHECK (depth IN (...))` from the init migration already permits
-- NULL once NOT NULL is dropped; it doesn't need to be redefined here. The new
-- pairing constraint is what actually enforces the invariant: memory grants must
-- have a depth, nothing else may.
ALTER TABLE grants ADD COLUMN kind TEXT NOT NULL DEFAULT 'memory' CHECK (kind IN ('memory', 'capability'));
ALTER TABLE grants ALTER COLUMN depth DROP NOT NULL;
ALTER TABLE grants ALTER COLUMN depth DROP DEFAULT;
ALTER TABLE grants ADD CONSTRAINT grants_kind_depth_pairing CHECK ((kind = 'memory') = (depth IS NOT NULL));

ALTER TABLE grant_requests ADD COLUMN kind TEXT NOT NULL DEFAULT 'memory' CHECK (kind IN ('memory', 'capability'));
ALTER TABLE grant_requests ALTER COLUMN depth DROP NOT NULL;
ALTER TABLE grant_requests ALTER COLUMN depth DROP DEFAULT;
ALTER TABLE grant_requests ADD CONSTRAINT grant_requests_kind_depth_pairing CHECK ((kind = 'memory') = (depth IS NOT NULL));
