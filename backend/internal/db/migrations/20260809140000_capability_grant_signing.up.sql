-- Capability grant content specific to git commit signing (issues #95, #79) and
-- the socket-authorization primitive that guards it (issue #77's spike).
--
-- ## Identity: "the grant names the (committer email, signing key) pair it
-- authorizes" (capability-broker.md, "Agent identity is grant content, not
-- broker structure", 2026-08-09).
--
-- A side table, not new columns on `grants` paired via a CHECK constraint the
-- way kind/depth are (grants_kind_depth_pairing) — deliberately. That pairing
-- works because depth has exactly one meaning for the one kind that needs it
-- (memory). committer_email is specific to one *operation class* within the
-- 'capability' kind (git.sign), not to the kind as a whole: a future
-- capability (e.g. fs.write) has no use for a committer email at all, so a
-- table-wide "capability kind implies committer_email is set" constraint
-- would force a vocabulary onto operations that don't need it. brokerd
-- enforces the pairing it actually needs (a git.sign grant with no identity
-- row is simply unusable) at the boundary that knows the operation — this
-- isn't the closed-vocabulary case AGENTS.md §6 asks for DB-level enforcement
-- of, it's optional, operation-specific content.
CREATE TABLE capability_grant_identities (
    grant_id        UUID PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE,
    committer_email TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ## Socket authorization: the #77 spike's per-grant pre-shared token.
--
-- Empirical finding that drives this: SO_PEERCRED's uid is real and
-- kernel-enforced, but "everything runs as the operator's own OS user"
-- (chuvar's actual deployment shape) means uid alone authenticates nothing —
-- the confused/injected agent chuvar's whole threat model is built around
-- (CLAUDE.md principle 2) shares the legitimate caller's uid by
-- construction. /proc/<pid>/exe and friends are live, attacker-influenceable
-- state after the one instant SO_PEERCRED is trustworthy (TOCTOU, reproduced
-- live in the spike) and must never be an authorization input.
--
-- So: a per-grant secret, minted at grant time (out of scope here — grant
-- *creation* is #96), presented on every socket connection and checked
-- synchronously alongside the uid gate, before the payload or the grant's
-- authorization state is touched. Hashed the same way reviewer_tokens are
-- (crypto/sha256, see store.HashToken) — brokerd never stores or logs the
-- plaintext, only ever compares hashes.
CREATE TABLE capability_grant_tokens (
    grant_id    UUID PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Active-token lookup is brokerd's hot path (every socket request) — same
-- reasoning as reviewer_tokens_active_hash_idx.
CREATE INDEX capability_grant_tokens_hash_idx ON capability_grant_tokens (token_hash);

-- ## Revocation watch (issue #95's open "LISTEN/NOTIFY or SSE" choice —
-- picked LISTEN/NOTIFY; see the brokerd commit message for the full
-- rationale). A trigger function, not application code: only cmd/migrate
-- holds DDL (AGENTS.md §3.6), and NOTIFY has to fire on every revocation
-- regardless of which role performs it (apiserver's revoke path today,
-- anything else later) — a trigger is the one chokepoint every future writer
-- inherits for free, rather than something each write path has to remember.
--
-- Fires only on revocation (OLD.revoked_at IS NULL, NEW.revoked_at IS NOT
-- NULL), not on every grants UPDATE: expiry is enforced by brokerd comparing
-- expires_at against wall-clock time on every request regardless of any
-- watch, so it needs no push notification; revocation is the one state
-- change that must reach an already-open cache proactively (success
-- criterion 4: "revoking stops signing within seconds").
CREATE OR REPLACE FUNCTION chuvar_notify_grant_revoked() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('chuvar_grant_revoked', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER grants_notify_revoked
    AFTER UPDATE OF revoked_at ON grants
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION chuvar_notify_grant_revoked();

-- No explicit GRANTs here for chuvar_app: AGENTS.md §3.6's "new tables are
-- granted to chuvar_app automatically (ALTER DEFAULT PRIVILEGES)" already
-- covers these two tables. chuvar_agent gets nothing, also automatically —
-- mcpserver has no business anywhere near capability grants. brokerd's own
-- role and its (narrower still) grants are a separate migration, since this
-- one is schema-only and the role-creation migration follows the existing
-- stamped-role pattern (20260803000000_least_privilege_roles.up.sql).
