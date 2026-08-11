-- Passkey (WebAuthn) reviewer authentication, additive alongside TOTP (decided
-- 2026-08-09, docs/decisions.md — TOTP keeps working, this is a second
-- enrollable factor; TOTP retirement is a later decision, nothing about the
-- reviewer_totp/seal_totp_secret migrations is touched here). Closes the gap
-- those migrations' own comments flagged:
-- "Full WebAuthn needs its own design pass ... and isn't attempted here."
--
-- Two tables:
--
--   webauthn_credentials — one row per registered authenticator, bound to the
--   reviewer_tokens row that enrolled it via reviewer_token_id, never via a
--   request-supplied identity (AGENTS.md §6, "actor identity derives from the
--   authenticated credential"). public_key and sign_count are plaintext
--   deliberately: AGENTS.md §3.5's sealing rule covers plaintext-*secret*
--   surfaces, and a WebAuthn public key is exactly that — public — while the
--   sign counter is a monotonic integer, not a credential. Nothing on this
--   table is a bearer secret the way totp_secret_enc is, so there is no new
--   plaintext-secret surface here to seal.
--
--   webauthn_challenges — server-side ceremony state per the design spec's
--   explicit requirement: single-use (consumed via DELETE ... RETURNING in
--   internal/store, never re-readable after) and short-lived (expires_at,
--   checked at consume time). One row per (reviewer, purpose): starting a new
--   ceremony overwrites any prior pending one for that reviewer/purpose
--   rather than accumulating abandoned challenges nothing will ever consume.
--   session_data holds the go-webauthn library's own SessionData (challenge,
--   allowed credential IDs, user verification requirement) as JSONB — none of
--   it is secret; a session's challenge is a single-use nonce whose only job
--   is to be echoed back inside a signature the server itself verifies.
CREATE TABLE webauthn_credentials (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    reviewer_token_id UUID NOT NULL REFERENCES reviewer_tokens(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    credential_id     BYTEA NOT NULL,
    public_key        BYTEA NOT NULL,
    attestation_type  TEXT NOT NULL,
    transports        TEXT[] NOT NULL DEFAULT '{}',
    aaguid            BYTEA NOT NULL DEFAULT '',
    sign_count        BIGINT NOT NULL DEFAULT 0,
    -- Recorded at registration and re-checked on every subsequent assertion
    -- (go-webauthn's login.go: "Backup Eligible flag inconsistency detected"
    -- is a hard failure if it doesn't match what was stored here) — a synced
    -- platform passkey (iCloud Keychain, a password manager) reports
    -- backup_eligible=true from the moment it's created, and that must stay
    -- consistent across the credential's lifetime, not just be read once and
    -- discarded. backup_state is stored alongside for the same round-trip
    -- reason even though the library doesn't re-check it for consistency —
    -- carrying the whole Flags struct through storage is one property to
    -- reason about, not a "which fields does this specific library version
    -- currently check" list to keep in sync by hand.
    backup_eligible   BOOLEAN NOT NULL DEFAULT false,
    backup_state      BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at      TIMESTAMPTZ,
    -- Set the moment a stored sign counter is observed to regress (equal or
    -- lower than last time) instead of increasing — treated as a
    -- cloned-authenticator signal and a fail-closed tripwire, per the
    -- 2026-08-09 decision (docs/decisions.md): the credential is revoked in
    -- the same statement that sets this, never just flagged and left live.
    clone_warning_at  TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ
);

-- credential_id is the authenticator-chosen handle a login assertion arrives
-- keyed by; two *live* rows sharing one would make "whose credential is this"
-- ambiguous. Partial (WHERE revoked_at IS NULL), matching
-- reviewer_tokens_active_hash_idx's reasoning: a revoked credential must not
-- permanently block re-registering the same physical authenticator.
CREATE UNIQUE INDEX webauthn_credentials_active_credential_id_idx
    ON webauthn_credentials (credential_id) WHERE revoked_at IS NULL;

-- Every lookup in internal/store is "this reviewer's credentials" (building
-- allowCredentials/excludeCredentials lists, listing for the tokens page) —
-- never a global scan, so this is the one index that matters for this table.
CREATE INDEX webauthn_credentials_reviewer_token_id_idx
    ON webauthn_credentials (reviewer_token_id);

CREATE TABLE webauthn_challenges (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    reviewer_token_id UUID NOT NULL REFERENCES reviewer_tokens(id) ON DELETE CASCADE,
    purpose           TEXT NOT NULL CHECK (purpose IN ('registration', 'assertion')),
    session_data      JSONB NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (reviewer_token_id, purpose)
);
