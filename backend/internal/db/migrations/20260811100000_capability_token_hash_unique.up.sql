-- Round-2 review finding (P2): the non-unique index on
-- capability_grant_tokens (token_hash), added by
-- 20260809140000_capability_grant_signing.up.sql, does not stop two
-- different grants from sharing the same token_hash. broker/cache.go's
-- Cache.apply keys byToken by hash and stores exactly one Entry per key,
-- and the load query (internal/broker/store.go's loadCapabilityGrants) has
-- no ORDER BY — so a duplicate hash binds the shared plaintext token to
-- whichever grant's row the query happens to return last, nondeterministically.
-- An agent presenting that token could sign under a different grant's
-- committer_email than the one whose scope it was actually vetted against,
-- and audit_log would attribute the signature to the wrong grant_id — a
-- direct hit on principle 6 (everything is attributable). Direct SQL is the
-- documented provisioning path today (no capability-grant creation surface
-- exists yet — issue #96), so this is reachable, not theoretical.
--
-- This closes it with UNIQUE(token_hash) across the WHOLE table, not a
-- partial index scoped to active (non-revoked) grants the way
-- 20260726030000_reviewer_tokens_partial_unique.up.sql scopes
-- reviewer_tokens_active_hash_idx. That precedent doesn't transfer
-- directly: reviewer_tokens carries its OWN revoked_at column, so a partial
-- index there can mean "unique among rows not yet revoked," and reissuing a
-- revoked token's hash is safe because revocation there is understood to
-- retire the plaintext. capability_grant_tokens has no revoked_at column of
-- its own — revocation state lives on grants.revoked_at, a different table
-- a partial index predicate cannot reference — and reusing a token_hash
-- across a revoked grant and a later active one would let whoever still
-- holds the revoked grant's plaintext token (a leaked credential, an agent
-- that logged it before revocation landed) authenticate as the NEW grant.
-- A global constraint is the stricter, correct bar here, not a shortcut
-- standing in for the partial-index idiom.
--
-- ## Pre-existing duplicates
--
-- capability_grant_tokens is new — this migration follows
-- 20260809140000_capability_grant_signing by two days — and nothing in
-- this codebase creates capability grants except direct SQL fixtures, so
-- on every deployment this migration is expected to touch, the
-- duplicate-detection block below finds nothing and the index swap at the
-- bottom is the only consequential statement. It is still written
-- defensively, for the same reason
-- 20260726030000_reviewer_tokens_partial_unique.down.sql carries its own
-- duplicate-data guard: a migration that adds a uniqueness constraint must
-- not crash opaquely against production data it didn't anticipate.
--
-- A duplicate token_hash is not a state this migration can safely resolve
-- by guessing which grant was the "real" one — that is exactly the
-- ambiguity the bug lets happen, and silently picking a winner would just
-- relocate the ambiguity into the migration itself rather than remove it.
-- So it refuses, naming the colliding grants, and stops.
--
-- It deliberately does NOT auto-resolve by revoking the grants and deleting
-- the surplus token rows. Revoking a grant is an exercise of authority, and
-- "humans approve; agents request" (principle 4) does not carve out an
-- exception for schema migrations; deleting the surplus rows would erase the
-- evidence of what the ambiguous provisioning actually was, against "history
-- is append-only — the past is evidence" (principle 12). Refusing loudly and
-- making the operator resolve it deliberately is also the established
-- precedent in this schema: 20260802000000_seal_totp_secret.up.sql refuses
-- rather than drop enrolled TOTP secrets, and both role migrations refuse
-- rather than adopt a pre-existing role. Fail closed, loudly (principle 5).
DO $$
DECLARE
    colliding uuid[];
BEGIN
    SELECT array_agg(DISTINCT grant_id)
    INTO colliding
    FROM capability_grant_tokens
    WHERE token_hash IN (
        SELECT token_hash
        FROM capability_grant_tokens
        GROUP BY token_hash
        HAVING count(*) > 1
    );

    IF colliding IS NOT NULL THEN
        RAISE EXCEPTION
            'refusing to add the UNIQUE token-hash index: capability grants % share a token hash, so one credential currently derives more than one grant and its scope, committer identity and audit attribution are already ambiguous. Resolving this automatically would mean revoking grants and deleting token rows — an authority decision and an erasure of evidence, neither of which belongs in a migration (principles 4 and 12). Revoke the grants you did not intend and delete their token rows deliberately, then re-run. See docs/operations.md, "Duplicate capability token hashes".',
            colliding;
    END IF;
END $$;

DROP INDEX IF EXISTS capability_grant_tokens_hash_idx;
CREATE UNIQUE INDEX capability_grant_tokens_hash_idx ON capability_grant_tokens (token_hash);
