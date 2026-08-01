-- Seals reviewer TOTP secrets at rest, and introduces the envelope that will
-- hold every other sealed value (ticket E6; the sealed-vault pass, E7, reuses
-- this table for fact content).
--
-- Why this exists: the reviewer_totp migration stored the base32 secret as
-- plaintext TEXT, and its own comment claimed a TOTP code is "a factor shell
-- access to the server environment alone cannot produce." That claim did not
-- hold. Postgres binds loopback next to the API with a checked-in password, so
-- anything that could read CHUVAR_API_TOKEN could equally SELECT totp_secret,
-- mint a valid code, and approve its own grant request — the confused-deputy
-- collapse the second factor exists to prevent. Sealing the column breaks that
-- chain for an attacker who reaches the database but not the master key.
-- See the 2026-08-01 trust-boundary decision (Notion, Agent Capability Broker).

-- data_keys holds wrapped data-encryption keys, one per purpose. The wrapping
-- key (the master key) is supplied by internal/custody at service boot and is
-- never written here: a row in this table is useless without it, which is what
-- makes it safe to store beside the data it protects. Rotating the master key
-- rewraps these rows and re-encrypts nothing.
--
-- purpose is deliberately open TEXT rather than a CHECK'd enum, matching the
-- scope taxonomy's stance (AGENTS.md §3.4) — 'secrets' today, 'vault' when E7
-- lands, and no migration needed to add the second.
CREATE TABLE data_keys (
    purpose     TEXT PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ
);

-- This migration destroys plaintext secrets rather than converting them:
-- conversion needs the app-layer master key, which Postgres deliberately never
-- sees (keys must not transit SQL, logs, or pg_stat_activity — AGENTS.md §3.5).
--
-- Dropping a *populated* totp_secret would do something worse than lose data.
-- CountEverEnrolledReviewerTokens counts rows with a secret, and that count is
-- the only thing stopping a stolen bearer token from minting a fresh token and
-- self-enrolling: revoke every device, watch the count fall to zero, walk
-- through the reopened gate. The count is monotonic precisely so nothing
-- reachable over the API can lower it — but a migration is not reachable over
-- the API, and would lower it silently.
--
-- So: refuse, loudly, and make re-enrollment a deliberate operator act. The
-- recovery path is in docs/operations.md.
DO $$
DECLARE
    enrolled bigint;
BEGIN
    SELECT count(*) INTO enrolled FROM reviewer_tokens WHERE totp_secret IS NOT NULL;
    IF enrolled > 0 THEN
        RAISE EXCEPTION
            'refusing to drop % plaintext TOTP secret(s): this would reset the ever-enrolled count to zero and reopen the token-enrollment gate. Re-enroll deliberately instead — see docs/operations.md, "Migrating to sealed TOTP secrets".',
            enrolled;
    END IF;
END $$;

ALTER TABLE reviewer_tokens DROP COLUMN totp_secret;

-- BYTEA, not TEXT: this holds nonce||ciphertext||tag from internal/custody,
-- not an encoding of the secret. The _enc suffix is deliberate — it makes a
-- regression back to plaintext visible in a diff rather than a type change
-- nobody notices.
ALTER TABLE reviewer_tokens ADD COLUMN totp_secret_enc BYTEA;
