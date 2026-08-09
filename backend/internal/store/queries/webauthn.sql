-- name: InsertWebAuthnCredential :one
INSERT INTO webauthn_credentials
    (reviewer_token_id, label, credential_id, public_key, attestation_type, transports, aaguid, sign_count,
     backup_eligible, backup_state)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, reviewer_token_id, label, credential_id, public_key, attestation_type, transports, aaguid,
    sign_count, backup_eligible, backup_state, created_at, last_used_at, clone_warning_at, revoked_at;

-- name: ListWebAuthnCredentialsForReviewer :many
-- Returns every credential (active and revoked) owned by one reviewer token,
-- oldest first — mirrors ListReviewerTokens's "show history, not just the
-- live set" stance. Callers that need only live credentials (building a
-- ceremony's allow/exclude list) filter revoked_at in Go rather than a second
-- near-identical query — one source of truth for "what does this reviewer
-- have" that both the ceremony and the listing endpoint read.
SELECT id, reviewer_token_id, label, credential_id, public_key, attestation_type, transports, aaguid,
    sign_count, backup_eligible, backup_state, created_at, last_used_at, clone_warning_at, revoked_at
FROM webauthn_credentials
WHERE reviewer_token_id = $1
ORDER BY created_at ASC;

-- name: CountEverEnrolledWebAuthnCredentials :one
-- Deliberately NOT filtered on revoked_at, mirroring
-- CountEverEnrolledReviewerTokens (reviewer_tokens.sql) exactly and for the
-- same reason: this feeds createToken's monotonic "has any second factor
-- ever been enrolled on this deployment" gate, and an active-only count
-- would let bearer-only revocation (of credentials or of their owning
-- tokens) reopen that gate. Rows are never deleted by any API path — revoke
-- sets revoked_at, and the ON DELETE CASCADE on reviewer_token_id can only
-- fire on a reviewer_tokens DELETE, which no API endpoint performs (tokens
-- are revoked, never deleted) — so this count only ever grows.
SELECT count(*) FROM webauthn_credentials;

-- name: ReviewerHasActiveWebAuthnCredential :one
SELECT EXISTS(
    SELECT 1 FROM webauthn_credentials WHERE reviewer_token_id = $1 AND revoked_at IS NULL
);

-- name: ReviewerHasTOTP :one
-- Per-reviewer, not the deployment-wide CountEverEnrolledReviewerTokens: this
-- answers "does *this* token have a factor to demand", not "has anything ever
-- been enrolled" — see requireExistingSecondFactor (internal/api).
SELECT totp_secret_enc IS NOT NULL AS has_totp FROM reviewer_tokens WHERE id = $1;

-- name: UpdateWebAuthnCredentialCounter :exec
UPDATE webauthn_credentials SET sign_count = $2, last_used_at = now() WHERE id = $1;

-- name: FlagWebAuthnCredentialCloneWarning :exec
-- A regressed sign counter is treated as a clone signal and fails closed by
-- revoking the credential in the same statement that flags it — a warning
-- left live would mean the same possibly-cloned key keeps passing this gate
-- on every subsequent call. See the webauthn_credentials migration's comment
-- on clone_warning_at.
UPDATE webauthn_credentials SET clone_warning_at = now(), revoked_at = now() WHERE id = $1;

-- name: RevokeWebAuthnCredential :execrows
UPDATE webauthn_credentials SET revoked_at = now() WHERE id = $1 AND reviewer_token_id = $2 AND revoked_at IS NULL;

-- name: UpsertWebAuthnChallenge :exec
-- One pending challenge per (reviewer, purpose): starting a new ceremony
-- overwrites whatever the previous, presumably-abandoned one was rather than
-- accumulating rows nothing will ever consume.
INSERT INTO webauthn_challenges (reviewer_token_id, purpose, session_data, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (reviewer_token_id, purpose)
DO UPDATE SET session_data = EXCLUDED.session_data, expires_at = EXCLUDED.expires_at, created_at = now();

-- name: ConsumeWebAuthnChallenge :one
-- DELETE ... RETURNING makes single-use atomic: two concurrent finish calls
-- for the same reviewer/purpose can never both see a row, since only one
-- DELETE can match it. expires_at > now() folds the short-expiry check into
-- the same statement rather than a separate read-then-check that would leave
-- a window between them.
DELETE FROM webauthn_challenges
WHERE reviewer_token_id = $1 AND purpose = $2 AND expires_at > now()
RETURNING session_data;
