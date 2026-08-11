-- Durable append-only enrollment latch (principle 12: history is append-only —
-- "the enrollment gate counts ever-enrolled"). It closes a gap the token
-- self-mint gate (createToken, internal/api/tokens.go) could not close on its
-- own: that gate demands a second factor once any factor has *ever* been
-- enrolled, but it read "ever" from the factor rows themselves
-- (CountEverEnrolledReviewerTokens over totp_secret_enc, plus the passkey
-- count). Those rows are mutable. The documented break-glass recovery
-- (docs/operations.md) deliberately clears totp_secret_enc and deletes
-- webauthn_credentials to reopen enrollment for the operator who has lost every
-- device — after which both counts return to zero, and any still-active stolen
-- bearer token (or a fresh factorless bootstrap token) could race the operator
-- through the reopened gate and self-enroll with NO second factor.
--
-- The latch makes the "a factor was once enrolled here" signal survive that
-- reset. It is set the first time any second factor of either kind is enrolled
-- (store.CreateReviewerToken with a TOTP secret, store.CreateWebAuthnCredential
-- for a passkey — both set it in the same transaction as the insert, so the
-- durable signal can never lag the row that justifies it), and recovery does
-- NOT clear it as a side effect: the recovery SQL touches only reviewer_tokens
-- and webauthn_credentials. createToken's gate becomes "latch set OR live
-- counts > 0", so once latched the deployment stays gated across any number of
-- factor resets. Resetting the latch is therefore a *separate, deliberate*
-- operator action (DELETE FROM enrollment_latch), documented on its own in
-- docs/operations.md and never a byproduct of the factor-reset flow — exactly
-- the "supersede, never erase; the past is evidence" stance principle 12 asks
-- for.
--
-- Single-row by construction: the primary key is a boolean pinned to true by a
-- CHECK, so at most one row can ever exist and it is always the same row. Set
-- once via INSERT ... ON CONFLICT DO NOTHING (store.SetEnrollmentLatch), which
-- is idempotent — every subsequent enrollment is a no-op, never a second row
-- and never a re-stamp of latched_at. chuvar_app (apiserver's role) picks up
-- SELECT/INSERT here automatically via the ALTER DEFAULT PRIVILEGES set in the
-- least_privilege_roles migration; chuvar_agent (mcpserver) is granted nothing,
-- matching every other reviewer-factor table.
CREATE TABLE enrollment_latch (
    id         BOOLEAN PRIMARY KEY DEFAULT true,
    latched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT enrollment_latch_singleton CHECK (id = true)
);
